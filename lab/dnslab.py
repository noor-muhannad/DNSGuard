#!/usr/bin/env python3
"""
DNSGuard lab measurement tools (standard library only). Use ONLY inside the isolated lab network.

These are MEASUREMENT and GROUND-TRUTH tools, not attack tools. The actual exfiltration in the lab is produced by the
established, well-documented tunnelling tools you install on the victim VM (iodine, dnscat2, dns2tcp, dnsexfiltrator) —
the same tools the Daumel dataset is built from. This script never generates or sends exfiltration payloads itself.

  sink      run on the ATTACKER VM: a tiny authoritative DNS server for the lab zones. It answers queries so the
            tunnelling tools work, and logs what actually reached it (received.csv). Comparing received.csv before and
            after DNSGuard's block mode is how we measure how much data got out.
  benign    run on a VICTIM VM: normal-looking background DNS traffic (popular sites + local services), so we can
            measure DNSGuard's false-alarm rate on realistic benign traffic.
  mark      record the start/end of each tunnelling-tool run in ground_truth.csv, so detection (recall) and false
            alarms (FPR) can be computed against a known timeline.

Examples
  sudo python3 dnslab.py sink --zones io-lab.net cat-lab.net d2t-lab.net
  python3 dnslab.py benign --resolver 10.10.0.2 --minutes 30 --rate 2
  python3 dnslab.py mark start --tool iodine --domain io-lab.net --client 10.10.0.5
      # …now run the real iodine client/server in the lab…
  python3 dnslab.py mark stop  --tool iodine
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import socket
import struct
import sys
import time

GT = "ground_truth.csv"
GT_COLS = ["run", "kind", "tool", "client", "domain", "rate_qps", "start", "end", "queries", "notes"]


# ---------------- minimal DNS wire format (server side only) ----------------
def build_query(name: str, qtype: int = 1, qid: int | None = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)          # RD=1
    q = b"".join(bytes([len(l)]) + l.encode("ascii") for l in name.strip(".").split(".")) + b"\0"
    return hdr + q + struct.pack(">HH", qtype, 1)


def parse_qname(msg: bytes, off: int = 12):
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            name, _ = parse_qname(msg, ptr)
            return ".".join(labels + [name]), off + 2
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace")); off += 1 + n


def answer(msg: bytes, ip: str = "10.66.66.66") -> bytes:
    """Answer any query so the real tunnelling tools keep working; we only care what reached us."""
    qid, flags = struct.unpack(">HH", msg[:4])
    name, end = parse_qname(msg)
    qtype, _ = struct.unpack(">HH", msg[end:end + 4])
    question = msg[12:end + 4]
    rflags = 0x8400 | (flags & 0x0100)                                  # QR + AA, copy RD
    if qtype == 16:
        txt = b"ok"; rtype, rdata = 16, bytes([len(txt)]) + txt
    elif qtype == 28:
        rtype, rdata = 28, socket.inet_pton(socket.AF_INET6, "fd00::66")
    else:
        rtype, rdata = 1, socket.inet_aton(ip)
    rr = b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 0, len(rdata)) + rdata
    return struct.pack(">HHHHHH", qid, rflags, 1, 1, 0, 0) + question + rr


def send(sock, resolver, name, qtype=1, timeout=1.0) -> bool:
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(name, qtype), (resolver, 53)); sock.recvfrom(4096); return True
    except (socket.timeout, OSError):
        return False


def my_ip(resolver: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((resolver, 53)); return s.getsockname()[0]
    finally:
        s.close()


def gt_write(row: dict):
    new = not os.path.exists(GT)
    with open(GT, "a", newline="") as fh:
        w = csv.DictWriter(fh, GT_COLS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in GT_COLS})


# ---------------- commands ----------------
def cmd_sink(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((a.bind, 53))
    zones = tuple(z.lower().strip(".") for z in a.zones)
    new = not os.path.exists(a.out)
    out = open(a.out, "a", newline=""); w = csv.writer(out)
    if new:
        w.writerow(["ts", "src", "name", "zone", "sub_chars"])
    print(f"sink listening on {a.bind}:53 for {', '.join(zones)} -> {a.out}  (Ctrl+C to stop)")
    n = 0
    try:
        while True:
            msg, addr = s.recvfrom(4096)
            try:
                name, _ = parse_qname(msg)
            except Exception:
                continue
            lname = name.lower()
            zone = next((z for z in zones if lname == z or lname.endswith("." + z)), "")
            sub = lname[: -len(zone) - 1] if zone and lname != zone else ""
            w.writerow([f"{time.time():.3f}", addr[0], name, zone, len(sub.replace(".", ""))]); n += 1
            if n % 50 == 0:
                out.flush()
            try:
                s.sendto(answer(msg), addr)
            except Exception:
                pass
    except KeyboardInterrupt:
        out.flush(); print(f"\nreceived {n} queries, logged to {a.out}")


BENIGN = ["www.google.com", "mail.google.com", "www.youtube.com", "i.ytimg.com", "www.facebook.com", "static.xx.fbcdn.net",
          "www.instagram.com", "web.whatsapp.com", "api.github.com", "github.com", "www.wikipedia.org", "upload.wikimedia.org",
          "outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com", "www.bing.com", "cdn.jsdelivr.net",
          "fonts.googleapis.com", "fonts.gstatic.com", "www.uobabylon.edu.iq", "www.amazon.com", "m.media-amazon.com",
          "time.windows.com", "connectivitycheck.gstatic.com", "clients4.google.com", "www.linkedin.com", "scholar.google.com",
          "ieeexplore.ieee.org", "www.kaggle.com", "pypi.org", "files.pythonhosted.org", "update.googleapis.com"]


def cmd_benign(a):
    rng = random.Random(a.seed); sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t0 = time.time(); end = t0 + a.minutes * 60; n = 0
    print(f"benign traffic -> {a.resolver} for {a.minutes} min at ~{a.rate} q/s  (Ctrl+C to stop)")
    try:
        while time.time() < end:
            name = rng.choice(BENIGN)
            if rng.random() < 0.15:                                      # CDN-style hashed hostnames (hard benign)
                name = f"r{rng.randint(1, 9)}---sn-{rng.getrandbits(32):08x}.googlevideo.com"
            send(sock, a.resolver, name, rng.choice([1, 1, 1, 28]), timeout=0.5); n += 1
            time.sleep(rng.expovariate(a.rate))
    except KeyboardInterrupt:
        pass
    gt_write({"run": a.run or f"benign-{int(t0)}", "kind": "benign", "tool": "dnslab-benign", "client": my_ip(a.resolver),
              "domain": "*", "rate_qps": a.rate, "start": f"{t0:.3f}", "end": f"{time.time():.3f}", "queries": n,
              "notes": "popular sites + CDN hostnames"})
    print(f"done: {n} benign queries")


def cmd_mark(a):
    state = ".dnslab_mark"
    if a.action == "start":
        if not a.tool or not a.domain:
            sys.exit("mark start needs --tool and --domain")
        open(state, "w").write(f"{time.time():.3f},{a.tool},{a.domain},{a.client or ''}")
        print(f"marked start of '{a.tool}' on {a.domain}. Run the tunnelling tool now, then: dnslab.py mark stop")
        return
    if not os.path.exists(state):
        sys.exit("no run in progress (start one with: dnslab.py mark start --tool … --domain …)")
    t0, tool, dom, cli = open(state).read().split(",")
    gt_write({"run": a.run or f"{tool}-{int(float(t0))}", "kind": "attack", "tool": tool, "client": cli or a.client or "",
              "domain": dom, "start": t0, "end": f"{time.time():.3f}", "notes": a.notes or ""})
    os.remove(state); print(f"recorded '{tool}' run ({dom}) in {GT}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("sink", help="authoritative sink + receive log (attacker VM)")
    s.add_argument("--zones", nargs="+", required=True); s.add_argument("--bind", default="0.0.0.0"); s.add_argument("--out", default="received.csv")
    b = sp.add_parser("benign", help="benign background traffic (victim VM)")
    b.add_argument("--resolver", required=True); b.add_argument("--minutes", type=float, default=30)
    b.add_argument("--rate", type=float, default=2.0); b.add_argument("--seed", type=int, default=0); b.add_argument("--run")
    m = sp.add_parser("mark", help="record a real tunnelling-tool run as ground truth")
    m.add_argument("action", choices=("start", "stop")); m.add_argument("--tool"); m.add_argument("--domain")
    m.add_argument("--client"); m.add_argument("--run"); m.add_argument("--notes")
    a = ap.parse_args()
    {"sink": cmd_sink, "benign": cmd_benign, "mark": cmd_mark}[a.cmd](a)


if __name__ == "__main__":
    main()
