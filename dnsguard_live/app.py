"""
DNSGuard Live: source -> detector -> (optional) blocker, with an Arabic web dashboard.

    python -m dnsguard_live --bundle dnsguard_bundle_v4.zip --source demo
    python -m dnsguard_live --bundle dnsguard_bundle_v4.zip --source pihole:/var/log/pihole/pihole.log \
                            --mode block --block-backend pihole
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sqlite3
import sys
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .blocker import Blocker
from .detector import DEFAULT_IGNORE, LiveDetector
from .sources import open_source

HERE = os.path.dirname(os.path.abspath(__file__))
BUCKET = 5          # seconds per chart bucket
BUCKETS = 120       # 10 minutes


class Engine:
    def __init__(self, a):
        self.a, self.lock = a, threading.RLock()
        self.logs = deque(maxlen=200)
        self.det = LiveDetector(a.bundle, ignore_suffixes=DEFAULT_IGNORE + tuple(a.ignore_suffix),
                                extra_allow=a.allow, threads=a.threads)
        self.blk = Blocker(a.block_backend, a.dry_run, a.block_conf, a.rpz_zone, a.reload_cmd, a.block_cmd,
                           a.unblock_cmd, a.never_block, log=self.log)
        self.mode = a.mode
        self.alerts = deque(maxlen=300)
        self.incidents: dict[int, object] = {}
        self.series = deque(maxlen=BUCKETS)             # [bucket_start, queries, alerts]
        self.clients = Counter(); self.client_alerts = Counter()
        self.running, self.source_done, self.error = True, False, None
        self.last_ts = None
        self.db = None
        if a.db:
            self.db = sqlite3.connect(a.db, check_same_thread=False)
            self.db.executescript("""
              CREATE TABLE IF NOT EXISTS incidents(id INTEGER, run TEXT, client TEXT, domain TEXT, first REAL, last REAL,
                alerts INTEGER, est_bytes REAL, why TEXT, blocked INTEGER, examples TEXT, PRIMARY KEY(run, id));
              CREATE TABLE IF NOT EXISTS alerts(run TEXT, ts REAL, client TEXT, query TEXT, domain TEXT, score REAL, why TEXT);
              CREATE TABLE IF NOT EXISTS actions(run TEXT, ts REAL, action TEXT, domain TEXT, ok INTEGER, msg TEXT);""")
        self.run_id = time.strftime("%Y%m%d-%H%M%S")
        self.log(f"DNSGuard ready · {self.det.info()['family']} · mode={self.mode} · blocking={a.block_backend}"
                 + (" (dry-run)" if a.dry_run else ""))

    def log(self, msg):
        line = f"{time.strftime('%I:%M:%S %p')}  {msg}"
        self.logs.append(line); print(line, flush=True)

    # ---------- detection loop ----------
    def run(self):
        try:
            src = open_source(self.a.source, self.a.replay, self.a.from_start, self.a.speed, self.a.slow_gap)
            n = 0
            for q, ts, c in src:
                if not self.running:
                    break
                with self.lock:
                    self._one(q, ts, c)
                n += 1
                if self.db and n % 500 == 0:
                    self.db.commit()
            self.source_done = True
            self.log("source finished" + (" — dashboard stays open (Ctrl+C to stop)" if self.a.port else ""))
        except Exception as e:  # keep the dashboard alive and show the error
            self.error = repr(e); self.log(f"ERROR: {e!r}")
        finally:
            if self.db:
                self.db.commit()

    def _one(self, q, ts, c):
        ev = self.det.update(q, ts, c)
        self.last_ts = ts
        b = int(ts // BUCKET) * BUCKET
        if not self.series or self.series[-1][0] != b:
            if self.series and b < self.series[-1][0]:     # out-of-order timestamp
                b = self.series[-1][0]
            else:
                self.series.append([b, 0, 0])
        self.series[-1][1] += 1
        self.clients[c] += 1
        if not ev["alert"]:
            return
        self.series[-1][2] += 1; self.client_alerts[c] += 1
        self.alerts.append({k: ev[k] for k in ("ts", "client", "query", "domain", "score", "why")})
        if self.db and self.a.db_alerts:
            self.db.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,?)",
                            (self.run_id, ts, c, q, ev["domain"], ev["score"], ev["why"]))
        inc = ev["incident"]
        if inc is None:
            return
        self.incidents[inc.id] = inc
        if len(self.incidents) > 1000:
            self.incidents.pop(min(self.incidents))
        if ev["new_incident"]:
            self.log(f"⚠ حادثة #{inc.id}: {c} → {inc.domain} · {ev['why']}")
            if self.mode == "block":
                self._block(inc.domain, f"incident #{inc.id} from {c}")
        if inc.domain in self.blk.blocked:
            inc.blocked = True
        if self.db:
            self.db.execute("INSERT OR REPLACE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                            (inc.id, self.run_id, inc.client, inc.domain, inc.first, inc.last, inc.alerts, inc.est_bytes,
                             inc.why, int(inc.blocked), json.dumps(inc.examples)))

    def _block(self, domain, reason):
        ok, msg = self.blk.block(domain, reason, self.det.allow)
        if ok:
            for inc in self.incidents.values():
                if inc.domain == domain:
                    inc.blocked = True
        if self.db:
            self.db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?)", (self.run_id, time.time(), "block", domain, int(ok), msg))
        return ok, msg

    def _unblock(self, domain):
        ok, msg = self.blk.unblock(domain)
        if ok:
            for inc in self.incidents.values():
                if inc.domain == domain:
                    inc.blocked = False
        if self.db:
            self.db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?)", (self.run_id, time.time(), "unblock", domain, int(ok), msg))
        return ok, msg

    # ---------- dashboard API ----------
    def state(self):
        with self.lock:
            st = dict(self.det.stats)
            now = self.last_ts or time.time()
            incs = sorted(self.incidents.values(), key=lambda i: i.last, reverse=True)[:100]
            return {
                "info": self.det.info(), "mode": self.mode, "backend": self.blk.backend, "dry_run": self.blk.dry,
                "source": self.a.source, "source_done": self.source_done, "error": self.error,
                "stats": st, "now": now,
                "open_incidents": sum(1 for i in incs if now - i.last <= self.det.gap),
                "series": list(self.series),
                "alerts": list(self.alerts)[-60:][::-1],
                "incidents": [dict(i.as_dict(), active=(now - i.last <= self.det.gap)) for i in incs],
                "blocked": sorted(self.blk.blocked.values(), key=lambda b: -b["at"]),
                "clients": [{"client": c, "queries": n, "alerts": self.client_alerts[c]}
                            for c, n in sorted(self.clients.items(), key=lambda kv: (-self.client_alerts[kv[0]], -kv[1]))[:12]],
                "logs": list(self.logs)[-40:][::-1],
            }

    def action(self, path, body):
        with self.lock:
            if path == "/api/mode":
                m = body.get("mode")
                if m not in ("monitor", "block"):
                    return False, "mode must be monitor or block"
                if m == "block" and self.blk.backend == "none":
                    return False, "شغّلي البرنامج مع --block-backend حتى يشتغل المنع"
                self.mode = m; self.log(f"mode → {m}"); return True, m
            d = (body.get("domain") or "").strip().lower()
            if not d:
                return False, "domain missing"
            if path == "/api/block":
                return self._block(d, "manual (dashboard)")
            if path == "/api/unblock":
                return self._unblock(d)
            if path == "/api/allow":
                self.det.allow.add(d); self.log(f"allowlisted {d} (this session)")
                return True, "allowlisted"
        return False, "unknown action"

    def incidents_csv(self):
        with self.lock:
            out = io.StringIO(); w = csv.writer(out)
            w.writerow(["id", "client", "domain", "first", "last", "alerts", "est_bytes", "blocked", "why", "examples"])
            for i in sorted(self.incidents.values(), key=lambda i: i.id):
                w.writerow([i.id, i.client, i.domain, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.first)),
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.last)), i.alerts, round(i.est_bytes),
                            int(i.blocked), i.why, " | ".join(i.examples)])
            return out.getvalue()


def make_handler(E: Engine, token: str | None):
    static = {"/": ("dashboard.html", "text/html; charset=utf-8"),
              "/logo_ink.png": ("logo_ink.png", "image/png"), "/logo_gold.png": ("logo_gold.png", "image/png")}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _auth(self):
            if not token:
                return True
            q = parse_qs(urlparse(self.path).query)
            if self.headers.get("X-Token") == token or q.get("token", [None])[0] == token:
                return True
            self._send(401, b'{"error":"token required"}', "application/json"); return False

        def _send(self, code, data: bytes, ctype):
            self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(data)

        def do_GET(self):
            p = urlparse(self.path).path
            if p in static:
                fn, ct = static[p]
                with open(os.path.join(HERE, "static", fn), "rb") as fh:
                    return self._send(200, fh.read(), ct)
            if not self._auth():
                return
            if p == "/api/state":
                return self._send(200, json.dumps(E.state(), ensure_ascii=False).encode(), "application/json; charset=utf-8")
            if p == "/api/incidents.csv":
                return self._send(200, ("﻿" + E.incidents_csv()).encode(), "text/csv; charset=utf-8")
            self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if not self._auth():
                return
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                body = {}
            ok, msg = E.action(urlparse(self.path).path, body)
            self._send(200 if ok else 400, json.dumps({"ok": ok, "msg": msg}, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8")
    return H


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="dnsguard_live", description="DNSGuard live DNS exfiltration detection & prevention")
    ap.add_argument("--bundle", required=True, help="dnsguard_bundle_v4.zip (or its unzipped folder)")
    ap.add_argument("--source", default="demo", help="demo | stdin | dnsmasq:PATH | pihole:PATH | bind:PATH | unbound:PATH | "
                                                    "zeek:PATH | sniff:IFACE | pcap:PATH | csv:PATH")
    ap.add_argument("--replay", action="store_true", help="read a log file once with its own timestamps (no follow)")
    ap.add_argument("--from-start", action="store_true", help="when following a log, start at the beginning of the file")
    ap.add_argument("--speed", type=float, default=0.0, help="replay speed for demo/csv/pcap/--replay (0 = as fast as possible, 1 = real time)")
    ap.add_argument("--slow-gap", type=float, default=30, help="demo: seconds between the slow leaker's queries")
    ap.add_argument("--mode", choices=("monitor", "block"), default="monitor")
    ap.add_argument("--block-backend", choices=("none", "dnsmasq", "pihole", "unbound", "rpz", "command"), default="none")
    ap.add_argument("--block-conf", help="dnsmasq conf file / RPZ zone file to write")
    ap.add_argument("--rpz-zone", default="rpz.dnsguard")
    ap.add_argument("--reload-cmd"); ap.add_argument("--block-cmd"); ap.add_argument("--unblock-cmd")
    ap.add_argument("--dry-run", action="store_true", help="log blocking commands without running them")
    ap.add_argument("--never-block", nargs="*", default=[], help="domains that must never be blocked (e.g. your university domain)")
    ap.add_argument("--allow", nargs="*", default=[], help="extra allowlisted registrable domains")
    ap.add_argument("--ignore-suffix", nargs="*", default=[], help="extra suffixes to skip (local zones)")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080, help="0 = no dashboard")
    ap.add_argument("--token", help="require this token for the dashboard API (use when --host 0.0.0.0)")
    ap.add_argument("--db", default="dnsguard_events.sqlite", help="SQLite log of incidents and actions ('' to disable)")
    ap.add_argument("--db-alerts", action="store_true", help="also store every single alert in the database")
    ap.add_argument("--threads", type=int, default=1)
    a = ap.parse_args(argv)
    if a.block_backend == "command" and not (a.block_cmd and a.unblock_cmd):
        ap.error("--block-backend command needs --block-cmd and --unblock-cmd")
    if a.mode == "block" and a.block_backend == "none":
        ap.error("--mode block needs --block-backend (dnsmasq, pihole, unbound, rpz or command)")
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.token and a.port:
        ap.error("the dashboard can block domains: when --host is not localhost, set --token")
    return a


def main(argv=None):
    a = parse_args(argv)
    E = Engine(a)
    t = threading.Thread(target=E.run, daemon=True); t.start()
    if not a.port:
        t.join(); return E
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(E, a.token))
    url = f"http://{'localhost' if a.host in ('0.0.0.0', '127.0.0.1') else a.host}:{a.port}/" + (f"?token={a.token}" if a.token else "")
    E.log(f"dashboard: {url}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        E.running = False; srv.server_close()
        if E.db:
            with E.lock:
                E.db.commit()
    return E


if __name__ == "__main__":
    sys.exit(main() and 0)
