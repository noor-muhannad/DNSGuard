"""
Prevention: turn an incident into a DNS block on the resolver the network uses.

Blocking happens on the registrable domain (e.g. attacker-lab.net), so every subdomain the tool generates is refused
and the channel stops. Backends:

  dnsmasq   writes address=/domain/ lines to a conf file (NXDOMAIN for the domain and all subdomains), then reloads
  pihole    runs `pihole --wild <domain>` (adjust --block-cmd for your Pi-hole version)
  unbound   `unbound-control local_zone <domain> always_nxdomain` (instant, no restart)
  rpz       writes a BIND Response Policy Zone file and runs `rndc reload <zone>`
  command   your own commands: --block-cmd "…{domain}…" --unblock-cmd "…{domain}…"

Safety: allowlisted domains and --never-block domains are never blocked; --dry-run logs the command without running it.
Note: a DNS block only works if devices cannot reach outside resolvers directly. In the lab, force all DNS through
the resolver with a firewall rule (see lab/README_AR.md).
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time


class Blocker:
    def __init__(self, backend: str = "none", dry_run: bool = False, conf: str | None = None, zone: str = "rpz.dnsguard",
                 reload_cmd: str | None = None, block_cmd: str | None = None, unblock_cmd: str | None = None,
                 never_block=(), log=print):
        self.backend, self.dry, self.zone, self.log = backend, dry_run, zone, log
        self.never = {d.lower().strip(".") for d in never_block}
        self.blocked: dict[str, dict] = {}
        defaults = {
            "dnsmasq": dict(conf="/etc/dnsmasq.d/dnsguard-block.conf", reload="systemctl restart dnsmasq"),
            "rpz": dict(conf="/etc/bind/db.rpz.dnsguard", reload=f"rndc reload {zone}"),
            "pihole": dict(block="pihole --wild {domain}", unblock="pihole --wild -d {domain}"),
            "unbound": dict(block="unbound-control local_zone {domain} always_nxdomain",
                            unblock="unbound-control local_zone_remove {domain}"),
        }.get(backend, {})
        self.conf = conf or defaults.get("conf")
        self.reload_cmd = reload_cmd or defaults.get("reload")
        self.block_cmd = block_cmd or defaults.get("block")
        self.unblock_cmd = unblock_cmd or defaults.get("unblock")
        if backend in ("dnsmasq", "rpz") and self.conf and os.path.exists(self.conf):
            self._load_file()

    # ---------- helpers ----------
    def _run(self, cmd: str) -> tuple[bool, str]:
        if self.dry:
            self.log(f"[dry-run] {cmd}"); return True, "dry-run"
        try:
            r = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            ok = r.returncode == 0
            return ok, (r.stdout + r.stderr).strip()[-300:]
        except Exception as e:  # missing binary, permission, timeout
            return False, str(e)

    def _load_file(self):
        try:
            for line in open(self.conf):
                line = line.strip()
                if self.backend == "dnsmasq" and line.startswith("address=/"):
                    d = line.split("/")[1]
                elif self.backend == "rpz" and line.endswith("CNAME .") and not line.startswith("*."):
                    d = line.split()[0].rstrip(".")
                else:
                    continue
                self.blocked[d] = {"domain": d, "at": os.path.getmtime(self.conf), "reason": "(from file)"}
        except OSError:
            pass

    def _write_file(self) -> tuple[bool, str]:
        doms = sorted(self.blocked)
        if self.backend == "dnsmasq":
            body = "# managed by DNSGuard — do not edit by hand\n" + "".join(f"address=/{d}/\n" for d in doms)
        else:
            serial = time.strftime("%y%m%d%H%M")
            body = (f"$TTL 60\n@ IN SOA localhost. admin.localhost. ({serial} 3600 600 86400 60)\n@ IN NS localhost.\n"
                    "; managed by DNSGuard\n" + "".join(f"{d} CNAME .\n*.{d} CNAME .\n" for d in doms))
        if self.dry:
            self.log(f"[dry-run] write {len(doms)} domain(s) to {self.conf}")
        else:
            try:
                tmp = self.conf + ".tmp"
                with open(tmp, "w") as fh:
                    fh.write(body)
                os.replace(tmp, self.conf)
            except OSError as e:
                return False, f"cannot write {self.conf}: {e}"
        return self._run(self.reload_cmd) if self.reload_cmd else (True, "written")

    # ---------- public ----------
    def can_block(self, domain: str, allow: set) -> str | None:
        """None if allowed to block, otherwise the reason it is refused."""
        d = domain.lower().strip(".")
        if self.backend == "none":
            return "no blocking backend configured (--block-backend)"
        if d in allow or d in self.never:
            return "domain is allowlisted / never-block"
        if "." not in d:
            return "not a registrable domain"
        return None

    def block(self, domain: str, reason: str = "", allow: set = frozenset()) -> tuple[bool, str]:
        d = domain.lower().strip(".")
        why_not = self.can_block(d, allow)
        if why_not:
            return False, why_not
        if d in self.blocked:
            return True, "already blocked"
        self.blocked[d] = {"domain": d, "at": time.time(), "reason": reason}
        ok, msg = self._write_file() if self.backend in ("dnsmasq", "rpz") else self._run(self.block_cmd.format(domain=d))
        if not ok:
            self.blocked.pop(d, None)
        self.log(f"[block] {d}: {'OK' if ok else 'FAILED'} {msg}")
        return ok, msg

    def unblock(self, domain: str) -> tuple[bool, str]:
        d = domain.lower().strip(".")
        if d not in self.blocked:
            return False, "not blocked"
        info = self.blocked.pop(d)
        ok, msg = self._write_file() if self.backend in ("dnsmasq", "rpz") else self._run(self.unblock_cmd.format(domain=d))
        if not ok:
            self.blocked[d] = info
        self.log(f"[unblock] {d}: {'OK' if ok else 'FAILED'} {msg}")
        return ok, msg
