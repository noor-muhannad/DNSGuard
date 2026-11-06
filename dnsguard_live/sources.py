"""
Where DNSGuard reads queries from. Every source yields (qname, ts, client).

  dnsmasq:/var/log/pihole/pihole.log   dnsmasq or Pi-hole query log (log-queries)
  bind:/var/log/named/queries.log      BIND query log
  unbound:/var/log/unbound.log         Unbound with log-queries: yes
  zeek:/opt/zeek/logs/current/dns.log  Zeek dns.log (TSV)
  sniff:eth0                           live capture of UDP/53 queries (needs root + scapy)
  pcap:capture.pcap                    replay a capture file (needs scapy)
  csv:benign.csv                       replay a Daumel-style CSV (timestamp, src_ip, dns_domain_name)
  stdin                                one "qname [client]" per line
  demo                                 built-in simulation: normal device + fast Base32 leak + slow Hex leak

Log sources follow the file live (like tail -F) unless --replay is given, in which case they read it once from the start
and use the timestamps written in the log.
"""
from __future__ import annotations

import base64
import csv
import os
import re
import sys
import time
from datetime import datetime

RE_DNSMASQ = re.compile(r"query\[(?P<t>[A-Za-z0-9]+)\]\s+(?P<q>\S+)\s+from\s+(?P<c>\S+)")
RE_BIND = re.compile(r"client (?:@\S+ )?(?P<c>[0-9A-Fa-f:.]+)#\d+ \((?P<n>[^)]*)\): (?:view \S+: )?query: (?P<q>\S+) IN (?P<t>\S+)")
RE_UNBOUND = re.compile(r"info: (?P<c>[0-9A-Fa-f:.]+) (?P<q>\S+)\. (?P<t>\S+) IN")
RE_SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)")
RE_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?)")
RE_BIND_TS = re.compile(r"^(?P<ts>\d\d-[A-Z][a-z]{2}-\d{4} \d\d:\d\d:\d\d(?:\.\d+)?)")
RE_UNBOUND_TS = re.compile(r"^\[(?P<ts>\d+(?:\.\d+)?)\]")

QTYPES = {"A", "AAAA", "TXT", "CNAME", "MX", "NULL", "ANY", "SRV", "NS", "PTR", "HTTPS", "SVCB", "SOA", "CAA"}


def _line_ts(line: str, now: float) -> float:
    """Best-effort timestamp from the start of a log line (falls back to now)."""
    m = RE_UNBOUND_TS.match(line)
    if m:
        return float(m["ts"])
    for rx, fmts in ((RE_ISO_TS, ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")),
                     (RE_BIND_TS, ("%d-%b-%Y %H:%M:%S.%f", "%d-%b-%Y %H:%M:%S")),
                     (RE_SYSLOG_TS, ("%Y %b %d %H:%M:%S",))):
        m = rx.match(line)
        if not m:
            continue
        s = m["ts"]
        if rx is RE_SYSLOG_TS:                       # syslog has no year
            s = f"{datetime.now().year} {' '.join(s.split())}"
        for fmt in fmts:
            try:
                return datetime.strptime(s, fmt).timestamp()
            except ValueError:
                pass
    return now


def parse_line(kind: str, line: str):
    """Return (qname, client, qtype) or None."""
    rx = {"dnsmasq": RE_DNSMASQ, "pihole": RE_DNSMASQ, "bind": RE_BIND, "unbound": RE_UNBOUND}[kind]
    m = rx.search(line)
    if not m:
        return None
    return m["q"].rstrip("."), m["c"], m["t"].upper()


def follow(path: str, from_start: bool = False, poll: float = 0.25):
    """tail -F: keeps reading through log rotation."""
    while not os.path.exists(path):
        print(f"[dnsguard] waiting for {path} …", file=sys.stderr); time.sleep(2)
    f = open(path, "r", errors="replace"); ino = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, os.SEEK_END)
    buf = ""
    while True:
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf.rstrip("\n"); buf = ""
            continue
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():          # rotated or truncated
                f.close(); f = open(path, "r", errors="replace"); ino = os.fstat(f.fileno()).st_ino
                continue
        except FileNotFoundError:
            pass
        time.sleep(poll)


def log_source(kind: str, path: str, replay: bool = False, from_start: bool = False):
    lines = open(path, "r", errors="replace") if replay else follow(path, from_start)
    for line in lines:
        r = parse_line(kind, line)
        if r is None:
            continue
        q, c, t = r
        if t not in QTYPES and not t.isdigit():
            continue
        now = time.time()
        yield q, (_line_ts(line, now) if replay else now), c


def zeek_source(path: str, replay: bool = False, from_start: bool = False):
    lines = open(path, "r", errors="replace") if replay else follow(path, from_start=True if from_start else False)
    cols = None
    for line in lines:
        if line.startswith("#fields"):
            cols = line.rstrip("\n").split("\t")[1:]; continue
        if line.startswith("#") or not line.strip():
            continue
        if cols is None:   # default dns.log layout
            cols = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "rtt", "query"]
        v = dict(zip(cols, line.rstrip("\n").split("\t")))
        q = v.get("query", "-")
        if q in ("-", "(empty)", ""):
            continue
        yield q.rstrip("."), (float(v.get("ts", time.time())) if replay else time.time()), v.get("id.orig_h", "?")


def _scapy():
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, PcapReader, sniff  # noqa: F401
        import scapy.all as S
        return S
    except ImportError:
        sys.exit("scapy is needed for sniff/pcap sources:  pip install scapy")


def _pkt_query(S, pkt):
    if not pkt.haslayer(S.DNS) or pkt[S.DNS].qr != 0 or not pkt.haslayer(S.DNSQR):
        return None
    q = pkt[S.DNSQR].qname
    q = q.decode("ascii", "replace") if isinstance(q, bytes) else str(q)
    ip = pkt[S.IP].src if pkt.haslayer(S.IP) else (pkt[S.IPv6].src if pkt.haslayer(S.IPv6) else "?")
    return q.rstrip("."), float(pkt.time), ip


def sniff_source(iface: str, bpf: str = "udp dst port 53"):
    import queue
    import threading
    S = _scapy(); qq = queue.Queue(maxsize=100_000)

    def cb(pkt):
        r = _pkt_query(S, pkt)
        if r:
            try:
                qq.put_nowait(r)
            except queue.Full:
                pass
    threading.Thread(target=lambda: S.sniff(iface=iface or None, filter=bpf, prn=cb, store=False), daemon=True).start()
    while True:
        yield qq.get()


def pcap_source(path: str):
    S = _scapy()
    with S.PcapReader(path) as rd:
        for pkt in rd:
            r = _pkt_query(S, pkt)
            if r:
                yield r


def csv_source(path: str):
    with open(path, newline="", errors="replace") as fh:
        rd = csv.DictReader(fh)
        cols = {c.lower(): c for c in rd.fieldnames or []}
        qc = next((cols[c] for c in ("dns_domain_name", "query", "qname", "domain", "name") if c in cols), None)
        tc = next((cols[c] for c in ("timestamp", "ts", "time", "frame.time_epoch") if c in cols), None)
        cc = next((cols[c] for c in ("src_ip", "client", "ip", "source", "ip.src") if c in cols), None)
        if qc is None:
            sys.exit(f"{path}: no query column (expected dns_domain_name / query / qname)")
        for row in rd:
            ts = time.time()
            if tc and row.get(tc):
                v = row[tc]
                try:
                    ts = float(v)
                except ValueError:
                    ts = _line_ts(v.replace("T", " "), ts)
            yield row[qc].strip().rstrip("."), ts, (row.get(cc) or "?") if cc else "?"


def stdin_source():
    for line in sys.stdin:
        p = line.split()
        if p:
            yield p[0].rstrip("."), time.time(), p[1] if len(p) > 1 else "stdin"


def demo_source(slow_gap: float = 30, seed: int = 1, minutes: float = 20):
    """Simulated network: 192.168.1.20 normal, .45 fast Base32 leak (min 1-2), .77 slow Hex leak (every slow_gap s)."""
    import random
    rng = random.Random(seed); t0 = time.time() - minutes * 60
    normal = ["www.google.com", "outlook.office365.com", "api.github.com", "www.uobabylon.edu.iq", "cdn.jsdelivr.net",
              "mail.google.com", "static.xx.fbcdn.net", "www.wikipedia.org", "clients4.google.com", "login.microsoftonline.com"]
    out = []
    n = int(minutes * 60 / 0.5)
    for i in range(n):
        out.append((rng.choice(normal), t0 + i * 0.5, "192.168.1.20"))
        if 120 <= i < 240:
            c = base64.b32encode(rng.randbytes(35)).decode().lower().strip("=")
            out.append((f"{c[:50]}.{c[50:]}.c2.attacker-lab.net", t0 + i * 0.5 + .1, "192.168.1.45"))
    for j in range(int(minutes * 60 / slow_gap)):
        out.append((rng.randbytes(24).hex() + ".s.slowleak-relay.org", t0 + j * slow_gap + .2, "192.168.1.77"))
    out.sort(key=lambda r: r[1])
    yield from out


def paced(src, speed: float):
    """Replay at `speed` x real time (0 = as fast as possible). Keeps the original timestamps."""
    if speed <= 0:
        yield from src; return
    first = start = None
    for q, ts, c in src:
        if first is None:
            first, start = ts, time.time()
        wait = (ts - first) / speed - (time.time() - start)
        if wait > 0:
            time.sleep(min(wait, 5))
        yield q, ts, c


def open_source(spec: str, replay: bool = False, from_start: bool = False, speed: float = 0.0, slow_gap: float = 30):
    kind, _, arg = spec.partition(":")
    kind = kind.lower()
    if kind in ("dnsmasq", "pihole", "bind", "unbound"):
        src = log_source(kind, arg, replay, from_start)
    elif kind == "zeek":
        src = zeek_source(arg, replay, from_start)
    elif kind == "sniff":
        return sniff_source(arg)
    elif kind == "pcap":
        src = pcap_source(arg)
    elif kind == "csv":
        src = csv_source(arg)
    elif kind == "stdin":
        return stdin_source()
    elif kind == "demo":
        src = demo_source(slow_gap)
    else:
        sys.exit(f"unknown source '{spec}'. Use dnsmasq:, pihole:, bind:, unbound:, zeek:, sniff:, pcap:, csv:, stdin or demo")
    return paced(src, speed) if (replay or kind in ("pcap", "csv", "demo")) else src
