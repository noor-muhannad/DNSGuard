"""
DNSGuard live detector: the v4 bundle (v2 full + v4 full XGBoost + character CNN) applied to one query at a time.

Same policy as notebook section 11.1:
  alert    = (any full model >= its threshold OR the CNN >= its threshold)
             AND domain not in the allowlist AND fewer than `pop_clients` devices asked for it in the last hour
  incident = >= incident_k alerts for the same (device, domain) within incident_gap_s seconds
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field

import numpy as np

CNN_REASON = "نموذج الحروف (CNN) يقرأ هذا الاسم كبيانات مرمّزة"
DEFAULT_IGNORE = ("in-addr.arpa", "ip6.arpa", "local", "lan", "home.arpa", "localdomain")


def load_bundle(path: str):
    """Load dnsguard_bundle_v4.zip (or the folder it was unzipped into). Returns (bundle, features_module, cnn_module)."""
    if os.path.isfile(path) and zipfile.is_zipfile(path):
        d = tempfile.mkdtemp(prefix="dnsguard_bundle_")
        with zipfile.ZipFile(path) as z:
            for n in ("dnsguard_model.pkl", "dnsguard_features.py", "dnsguard_cnn.py"):
                if n in z.namelist():
                    z.extract(n, d)
        path = d
    if not os.path.isfile(os.path.join(path, "dnsguard_model.pkl")):
        raise FileNotFoundError(f"dnsguard_model.pkl not found in {path}")
    sys.path.insert(0, path)
    for m in ("dnsguard_features", "dnsguard_cnn"):
        sys.modules.pop(m, None)
    F = importlib.import_module("dnsguard_features")
    try:
        C = importlib.import_module("dnsguard_cnn")
    except Exception:
        C = None
    import joblib
    B = joblib.load(os.path.join(path, "dnsguard_model.pkl"))
    return B, F, C


@dataclass
class Incident:
    id: int
    client: str
    domain: str
    first: float
    last: float
    alerts: int = 0
    chars: float = 0.0
    est_bytes: float = 0.0
    why: str = ""
    max_score: float = 0.0
    examples: list = field(default_factory=list)
    blocked: bool = False

    def as_dict(self):
        return {k: getattr(self, k) for k in ("id", "client", "domain", "first", "last", "alerts", "est_bytes",
                                              "why", "max_score", "examples", "blocked")}


class LiveDetector:
    def __init__(self, bundle_path: str, ignore_suffixes=DEFAULT_IGNORE, extra_allow=(), threads: int = 1):
        self.B, self.F, CNNM = load_bundle(bundle_path)
        meta = self.B["meta"]
        self.k, self.gap = int(meta["incident_k"]), float(meta["incident_gap_s"])
        self.pop = int(self.B.get("pop_clients", 10 ** 9))
        self.allow = set(self.B.get("allowlist", [])) | {d.lower().strip(".") for d in extra_allow}
        self.ignore = tuple(s.lower().strip(".") for s in ignore_suffixes)
        self.S = self.F.StreamFeaturizer()
        self.models = list(self.B["fulls"]) + [self.B["lexical"]]
        self.cnn = None
        L = self.B["lexical"]
        if L["kind"] == "cnn":
            if CNNM is None or getattr(CNNM, "torch", None) is None:
                print("[dnsguard] PyTorch is not installed: running without the CNN (install torch for the full system)")
                self.models = list(self.B["fulls"])
            else:
                CNNM.torch.set_num_threads(max(1, threads))
                self.cnn = CNNM.CharCNN.from_state(L["cnn_state"])
        for R in self.models:
            if R["kind"] == "xgb":
                R["_med"] = np.array([R["medians"][k] for k in R["features"]], np.float64)
                try:
                    R["model"].set_params(n_jobs=max(1, threads))
                except Exception:
                    pass
        self.recent: dict = {}     # (client, domain) -> [alert timestamps]
        self.open: dict = {}       # (client, domain) -> Incident (while active)
        self.n_inc = 0
        self.stats = {"queries": 0, "alerts": 0, "incidents": 0, "ignored": 0, "allowlisted": 0, "popular": 0, "started": time.time()}

    # ---------- scoring ----------
    def _x(self, R, f):
        x = np.array([f.get(k, np.nan) for k in R["features"]], np.float64)
        x = np.where(np.isnan(x), R["_med"], x)
        return x.astype(np.float32)[None, :]

    def _score(self, R, f):
        if R["kind"] == "cnn":
            return float(self.cnn.predict_proba([f["sub"]])[0, 1]), None
        x = self._x(R, f)
        return float(R["model"].predict_proba(x)[0, 1]), x

    def _why(self, R, x):
        if R["kind"] == "cnn":
            return CNN_REASON
        import xgboost as xgb
        c = R["model"].get_booster().predict(xgb.DMatrix(x), pred_contribs=True)[0, :-1]
        return "؛ ".join(self.F.explain(dict(zip(R["features"], c)))) or "نمط غير طبيعي بالطلبات"

    def ignored(self, domain: str) -> bool:
        return any(domain == s or domain.endswith("." + s) for s in self.ignore)

    # ---------- main entry ----------
    def update(self, qname: str, ts: float | None = None, client: str = "all") -> dict:
        """Feed one query. Returns an event dict; event['incident'] is set when an incident is open/updated."""
        ts = time.time() if ts is None else float(ts)
        qname = (qname or "").strip().rstrip(".")
        self.stats["queries"] += 1
        f = self.S.update(qname, ts, client)            # always update state, even for ignored names
        dom = f["domain"]
        ev = {"ts": ts, "client": client, "query": qname, "domain": dom, "score": 0.0, "alert": False,
              "why": "", "incident": None, "new_incident": False, "status": "ok"}
        if not qname or self.ignored(dom):
            self.stats["ignored"] += 1; ev["status"] = "ignored"; return ev
        scored = [(R, *self._score(R, f)) for R in self.models]
        ev["score"] = max(p for _, p, _ in scored)
        fired = [(R, p, x) for R, p, x in scored if p >= R["threshold"]]
        if not fired:
            return ev
        if dom in self.allow:
            self.stats["allowlisted"] += 1; ev["status"] = "allowlisted"; return ev
        if f.get("dom_clients_1h", 1) >= self.pop:
            self.stats["popular"] += 1; ev["status"] = "popular"; return ev
        trees = [r for r in fired if r[0]["kind"] == "xgb"]
        R, p, x = max(trees or fired, key=lambda r: r[1])      # tree models give feature-level reasons
        why = self._why(R, x)
        if trees and any(r[0]["kind"] == "cnn" for r in fired):
            why += "؛ " + CNN_REASON
        ev.update(alert=True, status="alert", why=why, model="+".join(r[0]["config"] for r in fired))
        self.stats["alerts"] += 1
        key = (client, dom)
        dq = [t for t in self.recent.get(key, []) if t > ts - self.gap] + [ts]
        self.recent[key] = dq
        inc = self.open.get(key)
        if inc is not None and ts - inc.last > self.gap:      # quiet for longer than the gap: close it
            del self.open[key]; inc = None
        if inc is None and len(dq) >= self.k:
            self.n_inc += 1; self.stats["incidents"] += 1
            inc = self.open[key] = Incident(self.n_inc, client, dom, first=dq[0], last=ts)
            ev["new_incident"] = True
        if inc is not None:
            inc.alerts += 1; inc.chars += f["sub_len"]; inc.last = ts; inc.why = ev["why"]
            inc.max_score = max(inc.max_score, ev["score"])
            inc.est_bytes = float(self.F.estimate_exfil_bytes(inc.chars))
            if len(inc.examples) < 5:
                inc.examples.append(qname)
            ev["incident"] = inc
        return ev

    def info(self) -> dict:
        m = self.B["meta"]
        return {"family": m.get("family"), "model": m.get("model"), "created": m.get("created"),
                "thresholds": {R["config"]: R["threshold"] for R in self.models},
                "incident_k": self.k, "incident_gap_s": self.gap, "pop_clients": self.pop,
                "allowlist_size": len(self.allow), "cnn": self.cnn is not None}
