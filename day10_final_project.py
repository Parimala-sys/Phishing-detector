import os
import re
import ssl
import sys
import csv
import json
import time
import atexit
import shutil
import socket
import hashlib
import logging
import argparse
import tempfile
import textwrap
import urllib.parse
from io    import StringIO
from enum  import Enum
from pathlib    import Path
from datetime   import datetime, timezone
from textwrap   import dedent
from urllib.parse import urlparse
from collections import namedtuple, defaultdict

# ── Optional third-party library (Day 8) ─────────────────────
try:
    import requests
    from requests.exceptions import (
        RequestException, ConnectionError as ReqConnError,
        Timeout, HTTPError, TooManyRedirects, SSLError as ReqSSLError,
    )
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ════════════════════════════════════════════════════════════════
# SECTION 1 — CONFIGURATION  (Day 6: config.py)
# All constants in one place. Change here → changes everywhere.
# ════════════════════════════════════════════════════════════════

VERSION     = "1.0.0"
APP_NAME    = "PhishGuard Pro"
REPORT_WIDTH = 62

# ── Score weights ────────────────────────────────────────────
# Each check name → risk points it adds (total capped at 100)
SCORE_WEIGHTS = {
    "no_https":           15,
    "bad_tld":            25,
    "fake_brand":         30,
    "suspicious_path":    10,
    "ip_address":         20,
    "long_subdomain":     10,
    "excessive_hyphens":  15,
    "query_sensitive":    30,
    "url_pattern":        15,
    "no_dns":             40,
    "ssl_error":          20,
    "new_cert":           10,
    "missing_headers":    15,
    "threat_database":    60,
    "redirect_chain":     15,
    "redirect_hijack":    20,
}

# ── Risk thresholds ──────────────────────────────────────────
# (max_score, label) — must be ascending, last must be 100
RISK_THRESHOLDS = (
    (0,   "SAFE"),
    (30,  "LOW RISK"),
    (60,  "SUSPICIOUS"),
    (100, "PHISHING"),
)

# ── Blocklists ───────────────────────────────────────────────
BAD_TLDS = (
    ".xyz",".tk",".ml",".win",".top",".click",
    ".gq",".cf",".pw",".buzz",".loan",".work",".party",
)

FAKE_BRANDS = (
    "paypa1","paypa1l","paypai",
    "amaz0n","amazom","arnazon",
    "g00gle","go0gle","micros0ft","microsoct",
    "app1e","netfl1x","netf1ix",
    "faceb00k","facebok","inst4gram",
    "tw1tter","linkedln","lnkedin",
    "hsb0","ba1rclays","we11sfargo","cit1bank",
)

SUSPICIOUS_PATHS = (
    "verify","login","update","confirm","secure",
    "validate","account","suspend","authenticate",
    "recover","billing","password","webscr","signin",
)

SENSITIVE_PARAMS = frozenset({
    "ssn","social_security","password","passwd","pwd",
    "pin","creditcard","cardnumber","cvv","cvc","expiry","dob",
})

TRACKING_PARAMS = frozenset({
    "utm_source","utm_medium","utm_campaign","utm_content","utm_term",
    "fbclid","gclid","mc_eid","ref","_ga","msclkid",
})

WHITELISTED_DOMAINS = frozenset({
    "google.com","google.co.uk","github.com","gitlab.com",
    "youtube.com","amazon.com","amazon.co.uk","microsoft.com",
    "apple.com","twitter.com","linkedin.com","stackoverflow.com",
    "python.org","pypi.org","mozilla.org","wikipedia.org",
})

URGENCY_PHRASES = (
    "act now","immediate action","verify your account",
    "your account will be suspended","click here immediately",
    "you have won","claim your prize","unusual activity detected",
    "wire transfer","gift card","bitcoin payment","confirm your identity",
)

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS",             10),
    "content-security-policy":   ("CSP",              15),
    "x-frame-options":           ("X-Frame-Options",  10),
    "x-content-type-options":    ("X-Content-Type",    5),
    "referrer-policy":           ("Referrer-Policy",   5),
}

DB_SCHEMA_VERSION = 2

# ── namedtuple for structured check definitions (Day 6) ──────
CheckDef = namedtuple("CheckDef", ["name","weight","description"])

CHECKS = tuple(
    CheckDef(name=name, weight=weight, description="")
    for name, weight in SCORE_WEIGHTS.items()
)

# ── Enum for risk levels (Day 6) ─────────────────────────────
class Risk(Enum):
    SAFE       = "SAFE"
    LOW_RISK   = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING   = "PHISHING"


# ════════════════════════════════════════════════════════════════
# SECTION 2 — UTILITIES  (Day 6: utils.py)
# Pure helper functions — no side effects, easy to test.
# ════════════════════════════════════════════════════════════════

def classify(score: int) -> str:
    """Converts a 0-100 score into a risk label."""
    for max_s, label in RISK_THRESHOLDS:
        if score <= max_s:
            return label
    return "PHISHING"

def confidence_score(triggered: int, total: int) -> int:
    """
    Returns confidence percentage based on
    how many independent checks fired.
    """
    if total <= 0:
        return 0
    return round((triggered / total) * 100)

def score_bar(score: int, width: int = 10) -> str:
    """Returns a text progress bar for a score."""
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)

def risk_icon(risk: str) -> str:
    return {"SAFE":"✓","LOW RISK":"◎","SUSPICIOUS":"⚠","PHISHING":"✕"}.get(risk,"?")

def truncate(text: str, max_len: int = 50) -> str:
    return text if len(text) <= max_len else text[:max_len-1] + "…"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def divider(char: str = "=", width: int = REPORT_WIDTH) -> str:
    return char * width

def url_hash(url: str) -> str:
    """SHA-256 hash of a normalised URL (first 16 hex chars)."""
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()[:16]

def is_ip_domain(domain: str) -> bool:
    parts = domain.split(":")[0].split(".")
    return sum(1 for p in parts if p.isdigit()) >= 3

def extract_params(query: str) -> set:
    if not query: return set()
    return {p.split("=")[0].lower() for p in query.split("&") if p}

def strip_tracking(url: str) -> str:
    """Removes known tracking parameters from a URL query string."""
    parsed = urlparse(url)
    if not parsed.query:
        return url
    clean = "&".join(
        p for p in parsed.query.split("&")
        if p.split("=")[0].lower() not in TRACKING_PARAMS
    )
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return f"{base}?{clean}" if clean else base

def compute_stats(results: list) -> dict:
    if not results:
        return {"total": 0}
    total  = len(results)
    scores = [r.get("score",0) for r in results]
    return {
        "total":      total,
        "safe":       sum(1 for r in results if r.get("risk")=="SAFE"),
        "low_risk":   sum(1 for r in results if r.get("risk")=="LOW RISK"),
        "suspicious": sum(1 for r in results if r.get("risk")=="SUSPICIOUS"),
        "phishing":   sum(1 for r in results if r.get("risk")=="PHISHING"),
        "avg_score":  round(sum(scores)/total, 1),
        "max_score":  max(scores),
        "min_score":  min(scores),
        "highest":    max(results, key=lambda r: r.get("score",0)),
    }

# ── Regex patterns (Day 8) ────────────────────────────────────
_RE_IP          = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_RE_PUNYCODE    = re.compile(r"xn--")
_RE_AT_TRICK    = re.compile(r"@")
_RE_SHORTENER   = re.compile(
    r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|rb\.gy|cutt\.ly|is\.gd)",
    re.I
)
_RE_ENCODED     = re.compile(r"%[0-9a-fA-F]{2}")
_RE_DOUBLE_SLASH= re.compile(r"/{2,}[^/]")

def find_url_patterns(url: str) -> list:
    """Returns list of (name, description) for triggered regex patterns."""
    domain   = urlparse(url).netloc.lower().split(":")[0]
    findings = []
    checks = [
        (_RE_PUNYCODE,      domain,     "Punycode domain (homograph attack risk)"),
        (_RE_SHORTENER,     domain,     "URL shortener (hides real destination)"),
        (_RE_AT_TRICK,      url.lower(),"@ sign in URL (real domain is after @)"),
        (_RE_ENCODED,       url.lower(),"Percent-encoded chars (obfuscation)"),
        (_RE_DOUBLE_SLASH,  url.lower(),"Double slash bypass trick"),
    ]
    for pattern, target, desc in checks:
        if pattern.search(target):
            findings.append(desc)
    return findings


# ════════════════════════════════════════════════════════════════
# SECTION 3 — ANSI COLORS  (Day 7)
# ════════════════════════════════════════════════════════════════

class C:
    """ANSI terminal color codes. Auto-disabled when piped."""
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    ON     = hasattr(sys.stdout,"fileno") and os.isatty(sys.stdout.fileno())

    @classmethod
    def _c(cls, *codes): return ("".join(codes) if cls.ON else ""), (cls.RESET if cls.ON else "")

    @classmethod
    def safe(cls,t):       s,e=cls._c(cls.GREEN);        return f"{s}{t}{e}"
    @classmethod
    def low(cls,t):        s,e=cls._c(cls.GREEN,cls.DIM); return f"{s}{t}{e}"
    @classmethod
    def warn(cls,t):       s,e=cls._c(cls.YELLOW);       return f"{s}{t}{e}"
    @classmethod
    def danger(cls,t):     s,e=cls._c(cls.RED,cls.BOLD); return f"{s}{t}{e}"
    @classmethod
    def header(cls,t):     s,e=cls._c(cls.BOLD,cls.CYAN);return f"{s}{t}{e}"
    @classmethod
    def dim(cls,t):        s,e=cls._c(cls.DIM);          return f"{s}{t}{e}"
    @classmethod
    def bold(cls,t):       s,e=cls._c(cls.BOLD);         return f"{s}{t}{e}"
    @classmethod
    def by_risk(cls,risk,t=None):
        target = t if t is not None else risk
        return {
            "SAFE":cls.safe,"LOW RISK":cls.low,
            "SUSPICIOUS":cls.warn,"PHISHING":cls.danger,
        }.get(risk, lambda x:x)(target)


# ════════════════════════════════════════════════════════════════
# SECTION 4 — NETWORK ENRICHMENT  (Day 8)
# Live checks: DNS, SSL, HTTP headers, threat API.
# All return dicts — partial failures never crash the pipeline.
# ════════════════════════════════════════════════════════════════

def dns_lookup(domain: str) -> dict:
    """Resolves a domain. Returns {resolves, ip, error}."""
    domain = domain.split(":")[0].split("/")[0].lower()
    result = {"resolves":False,"ip":"","all_ips":[],"is_private":False,"error":""}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips   = list({i[4][0] for i in infos})
        result.update({"resolves":True,"ip":ips[0] if ips else "","all_ips":ips})
        ip = result["ip"]
        result["is_private"] = (
            ip.startswith("10.") or ip.startswith("127.") or
            ip.startswith("192.168.") or
            any(ip.startswith(f"172.{i}.") for i in range(16,32))
        )
    except (socket.gaierror, socket.timeout) as e:
        result["error"] = str(e)
    return result


def ssl_check(domain: str, timeout: int = 6) -> dict:
    """Checks TLS certificate for domain. Returns cert metadata."""
    result = {"has_ssl":False,"issued_to":"","issued_by":"","valid_until":"",
              "days_remaining":0,"is_expired":False,"cert_age_days":0,
              "is_new":False,"is_self_signed":False,"error":""}
    try:
        ctx  = ssl.create_default_context()
        with socket.create_connection((domain,443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ts:
                cert = ts.getpeercert()
        def fields(raw): return {k:v for pair in raw for k,v in pair}
        subj   = fields(cert.get("subject",()))
        issuer = fields(cert.get("issuer",()))
        fmt    = "%b %d %H:%M:%S %Y %Z"
        nb     = datetime.strptime(cert["notBefore"],fmt).replace(tzinfo=timezone.utc)
        na     = datetime.strptime(cert["notAfter"],fmt).replace(tzinfo=timezone.utc)
        now    = datetime.now(timezone.utc)
        result.update({
            "has_ssl":True,
            "issued_to":    subj.get("commonName",""),
            "issued_by":    issuer.get("organizationName",issuer.get("commonName","")),
            "valid_until":  na.strftime("%Y-%m-%d"),
            "days_remaining":(na-now).days,
            "is_expired":   now > na,
            "cert_age_days":(now-nb).days,
            "is_new":       (now-nb).days < 30,
            "is_self_signed":subj.get("commonName")==issuer.get("commonName"),
        })
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def header_check(url: str, timeout: int = 6) -> dict:
    """Fetches HTTP HEAD and analyses security headers."""
    result = {"ok":False,"status":0,"server":"","missing":[],"risk_pts":0,"error":""}
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result
    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True,
                             headers={"User-Agent":"PhishGuard/1.0"})
        result["ok"]     = True
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("Server","")
        lowered = {k.lower():v for k,v in resp.headers.items()}
        for hdr,(name,pts) in SECURITY_HEADERS.items():
            if hdr not in lowered:
                result["missing"].append(name)
                result["risk_pts"] += pts
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def urlhaus_check(url: str, timeout: int = 8) -> dict:
    """Queries URLhaus threat database (no API key needed)."""
    result = {"found":False,"status":"unknown","threat":"","error":""}
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"; return result
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url":url}, timeout=timeout,
            headers={"Content-Type":"application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "is_listed":
            result.update({"found":True,"status":data.get("url_status",""),
                           "threat":data.get("threat","")})
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def http_fetch(url: str, timeout: int = 8) -> dict:
    """Makes a GET request. Returns status, redirect info, page title."""
    result = {"ok":False,"status":0,"final_url":url,"redirects":0,
              "time_s":0.0,"title":"","server":"","error":""}
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"; return result
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent":"Mozilla/5.0 PhishGuard/1.0"},
        )
        title_m = re.search(r"<title[^>]*>(.*?)</title>",
                             resp.text[:4000], re.I|re.S)
        result.update({
            "ok":True,"status":resp.status_code,"final_url":resp.url,
            "redirects":len(resp.history),"time_s":round(resp.elapsed.total_seconds(),2),
            "title":title_m.group(1).strip()[:80] if title_m else "",
            "server":resp.headers.get("Server",""),
        })
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


# ════════════════════════════════════════════════════════════════
# SECTION 5 — SCAN DATABASE  (Day 9)
# Persistent JSON store with atomic writes, CRUD, export.
# ════════════════════════════════════════════════════════════════

def _atomic_write(data, path: Path, **kw) -> None:
    """Writes JSON atomically: temp file → fsync → replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".pgpro_tmp_", suffix=".json")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data, f, **kw)
            f.flush(); os.fsync(f.fileno())
        Path(tmp).replace(path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def _load_safe(path: Path, default=None):
    """Loads JSON safely — returns default on any error."""
    try:
        with open(path,"r",encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return [] if default is None else default
    except (json.JSONDecodeError, PermissionError):
        return [] if default is None else default


class ScanDatabase:
    """
    Persistent JSON-backed database of scan results.

    Storage format:
    {
        "version": 2,
        "created": "<iso>",
        "updated": "<iso>",
        "count":   N,
        "results": [ {...}, ... ]
    }
    """

    def __init__(self, path: str = "phishguard.json"):
        self.path     = Path(path)
        self._records = {}
        self._meta    = {}
        self._load()

    def _load(self):
        raw = _load_safe(self.path)
        if isinstance(raw, list):
            results, self._meta = raw, {
                "version": DB_SCHEMA_VERSION,
                "created": now_iso(), "updated": now_iso(),
            }
        else:
            self._meta = {
                "version": raw.get("version", 1),
                "created": raw.get("created", now_iso()),
                "updated": raw.get("updated", now_iso()),
            }
            results = raw.get("results", []) if isinstance(raw, dict) else []
        self._records = {}
        for r in results:
            r.setdefault("tags", [])
            r.setdefault("notes", "")
            r.setdefault("enrichment", {})
            key = url_hash(r.get("url",""))
            self._records[key] = r

    def _save(self):
        self._meta["updated"] = now_iso()
        _atomic_write({
            "version": DB_SCHEMA_VERSION,
            "created": self._meta["created"],
            "updated": self._meta["updated"],
            "count":   len(self._records),
            "results": list(self._records.values()),
        }, self.path, indent=2, ensure_ascii=False)

    def add(self, result: dict) -> str:
        result.setdefault("scanned_at", now_iso())
        result.setdefault("tags",       [])
        result.setdefault("notes",      "")
        result.setdefault("enrichment", {})
        key = url_hash(result.get("url",""))
        self._records[key] = result
        self._save()
        return key

    def add_many(self, results: list) -> int:
        for r in results:
            r.setdefault("scanned_at", now_iso())
            r.setdefault("tags", [])
            r.setdefault("notes", "")
            r.setdefault("enrichment", {})
            self._records[url_hash(r.get("url",""))] = r
        self._save()
        return len(results)

    def get(self, url: str) -> dict | None:
        return self._records.get(url_hash(url))

    def all(self) -> list:
        return list(self._records.values())

    def search(self, risk=None, min_score=None, max_score=None,
               keyword=None, tag=None, since=None) -> list:
        rows = list(self._records.values())
        if risk:
            rows = [r for r in rows if r.get("risk")==risk.upper()]
        if min_score is not None:
            rows = [r for r in rows if r.get("score",0) >= min_score]
        if max_score is not None:
            rows = [r for r in rows if r.get("score",0) <= max_score]
        if keyword:
            kw = keyword.lower()
            rows = [r for r in rows if kw in r.get("url","").lower()]
        if tag:
            rows = [r for r in rows if tag in r.get("tags",[])]
        if since:
            rows = [r for r in rows if r.get("scanned_at","") >= since]
        return sorted(rows, key=lambda r: r.get("score",0), reverse=True)

    def update(self, url: str, fields: dict) -> bool:
        key = url_hash(url)
        if key not in self._records: return False
        self._records[key].update(fields)
        self._save(); return True

    def delete(self, url: str) -> bool:
        key = url_hash(url)
        if key not in self._records: return False
        del self._records[key]; self._save(); return True

    def clear(self) -> int:
        n = len(self._records); self._records = {}; self._save(); return n

    def stats(self) -> dict:
        rows = list(self._records.values())
        s = compute_stats(rows)
        s["db_file"]    = str(self.path)
        s["db_size_kb"] = round(self.path.stat().st_size/1024,1) if self.path.exists() else 0
        s["updated"]    = self._meta.get("updated","")
        return s

    def backup(self, bd: str = "backups") -> Path:
        Path(bd).mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = Path(bd)/f"phishguard_{ts}.json"
        shutil.copy2(self.path, dst)
        return dst

    # ── Exports ───────────────────────────────────────────────
    def export_csv(self, path: str = "phishguard_report.csv") -> Path:
        out = Path(path)
        rows = sorted(self._records.values(), key=lambda r: r.get("score",0), reverse=True)
        with open(out,"w",newline="",encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL)
            w.writerow(["url","score","risk","reasons","tags","notes","scanned_at"])
            for r in rows:
                w.writerow([
                    r.get("url",""), r.get("score",0), r.get("risk",""),
                    " | ".join(r.get("reasons",[])),
                    ",".join(r.get("tags",[])),
                    r.get("notes",""), r.get("scanned_at",""),
                ])
        return out

    def export_html(self, path: str = "phishguard_report.html") -> Path:
        out  = Path(path)
        rows = sorted(self._records.values(), key=lambda r: r.get("score",0), reverse=True)
        s    = self.stats()
        risk_colors = {
            "SAFE":"#22c55e","LOW RISK":"#84cc16",
            "SUSPICIOUS":"#f59e0b","PHISHING":"#ef4444",
        }
        tr_rows = []
        for r in rows:
            c    = risk_colors.get(r.get("risk",""),"#94a3b8")
            sc   = r.get("score",0)
            bar  = f'<div style="background:{c};width:{sc}%;height:6px;border-radius:3px;margin-top:4px"></div>'
            rsns = "<br>".join(f"• {x}" for x in r.get("reasons",[]))
            tags = " ".join(f'<span style="background:#1e3a5f;color:#7dd3fc;border-radius:4px;padding:1px 6px;font-size:10px">{t}</span>' for t in r.get("tags",[]))
            tr_rows.append(f"""<tr>
              <td style="font-family:monospace;font-size:12px;word-break:break-all">{r.get('url','')}</td>
              <td style="text-align:center;min-width:70px">{sc}/100{bar}</td>
              <td style="text-align:center;color:{c};font-weight:700;white-space:nowrap">{r.get('risk','')}</td>
              <td style="font-size:11px;color:#94a3b8">{rsns}</td>
              <td>{tags}</td>
              <td style="font-size:11px;color:#64748b;white-space:nowrap">{r.get('scanned_at','')[:19]}</td>
            </tr>""")

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{APP_NAME} — Scan Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;padding:32px}}
  h1{{color:#38bdf8;font-size:24px;margin-bottom:4px}}
  .sub{{color:#64748b;font-size:13px;margin-bottom:24px}}
  .stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
  .stat{{background:#1e293b;border-radius:10px;padding:16px 20px;min-width:110px}}
  .stat .n{{font-size:26px;font-weight:700}}
  .stat .l{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}}
  .actions{{margin-bottom:20px}}
  .btn{{display:inline-block;background:#1e40af;color:#fff;text-decoration:none;
         padding:8px 16px;border-radius:6px;font-size:13px;margin-right:8px}}
  table{{width:100%;border-collapse:collapse;background:#111827;border-radius:12px;overflow:hidden}}
  th{{background:#0f172a;padding:10px 14px;text-align:left;font-size:11px;
      text-transform:uppercase;color:#64748b;letter-spacing:.05em}}
  td{{padding:10px 14px;border-bottom:1px solid #0f172a;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#162032}}
</style></head><body>
  <h1>🛡 {APP_NAME} — Scan Report</h1>
  <div class="sub">Generated {now_str()} &nbsp;·&nbsp; {s['total']} URLs scanned</div>
  <div class="stats">
    <div class="stat"><div class="n">{s['total']}</div><div class="l">Total</div></div>
    <div class="stat"><div class="n" style="color:#22c55e">{s.get('safe',0)}</div><div class="l">Safe</div></div>
    <div class="stat"><div class="n" style="color:#84cc16">{s.get('low_risk',0)}</div><div class="l">Low Risk</div></div>
    <div class="stat"><div class="n" style="color:#f59e0b">{s.get('suspicious',0)}</div><div class="l">Suspicious</div></div>
    <div class="stat"><div class="n" style="color:#ef4444">{s.get('phishing',0)}</div><div class="l">Phishing</div></div>
    <div class="stat"><div class="n">{s.get('avg_score',0)}</div><div class="l">Avg Score</div></div>
  </div>
  <div class="actions">
    <a class="btn" href="phishguard_report.csv" download>⬇ Download CSV</a>
  </div>
  <table>
    <thead><tr>
      <th>URL</th><th>Score</th><th>Risk</th><th>Reasons</th><th>Tags</th><th>Scanned At</th>
    </tr></thead>
    <tbody>{''.join(tr_rows)}</tbody>
  </table>
</body></html>"""
        out.write_text(html, encoding="utf-8")
        return out

    def export_jsonl(self, path: str = "phishguard.jsonl") -> Path:
        out = Path(path)
        rows = sorted(self._records.values(), key=lambda r: r.get("score",0), reverse=True)
        with open(out,"w",encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False)+"\n")
        return out

    def __len__(self):  return len(self._records)
    def __contains__(self, url): return url_hash(url) in self._records
    def __iter__(self): return iter(self._records.values())
    def __repr__(self): return f"ScanDatabase('{self.path}', n={len(self)})"


class PhishGuard:
    """
    The core scanning engine.

    Combines:
      - Weighted scoring system (Day 4)
      - OOP design with properties and dunder methods (Day 5)
      - Persistent JSON database (Day 9)
      - Live network enrichment (Day 8)
      - Auto-save via atexit (Day 9)

    Usage:
        pg     = PhishGuard()
        result = pg.scan("http://paypa1.xyz/verify")
        pg.scan_file("urls.txt")
        pg.db.export_html("report.html")
    """

    version = VERSION

    def __init__(self, db_path: str = "phishguard.json", name: str = APP_NAME):
        self.name         = name
        self.db           = ScanDatabase(db_path)
        self.weights      = dict(SCORE_WEIGHTS)
        self.bad_tlds     = list(BAD_TLDS)
        self.fake_brands  = list(FAKE_BRANDS)
        self.sus_paths    = list(SUSPICIOUS_PATHS)
        self.sens_params  = set(SENSITIVE_PARAMS)
        self.whitelist    = set(WHITELISTED_DOMAINS)
        atexit.register(self._on_exit)

    # ── Local scan (no network) ───────────────────────────────
    def _local(self, url: str) -> dict:
        """Runs all local checks. Returns a result dict."""
        url    = strip_tracking(url.strip())
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        params = extract_params(query)
        base   = ".".join(domain.split(".")[-2:])

        # Whitelist fast-exit
        if base in self.whitelist:
            return self._result(url, 0, ["Trusted domain"], {})

        score = 0; reasons = []

        if parsed.scheme != "https":
            score += self.weights["no_https"]; reasons.append("Uses HTTP not HTTPS")
        for t in self.bad_tlds:
            if domain.endswith(t):
                score += self.weights["bad_tld"]; reasons.append(f"High-risk TLD: {t}"); break
        for b in self.fake_brands:
            if b in domain:
                score += self.weights["fake_brand"]; reasons.append(f"Impersonates: '{b}'"); break
        for w in self.sus_paths:
            if w in path:
                score += self.weights["suspicious_path"]; reasons.append(f"Suspicious path: /{w}"); break
        if is_ip_domain(domain):
            score += self.weights["ip_address"]; reasons.append("Raw IP as domain")
        if domain.count(".") >= 3:
            score += self.weights["long_subdomain"]; reasons.append("Long subdomain chain")
        if domain.count("-") >= 3:
            score += self.weights["excessive_hyphens"]; reasons.append("Excessive hyphens")
        if self.sens_params & params:
            score += self.weights["query_sensitive"]; reasons.append("Sensitive params in URL")
        for desc in find_url_patterns(url):
            score += self.weights["url_pattern"]; reasons.append(f"Pattern: {desc}")

        score = min(score, 100)

        total_checks = len(CHECKS)
        triggered_checks = len(reasons)

        result = self._result(url, score, reasons, {})
        result["confidence"] = confidence_score(
            triggered_checks,
            total_checks
    )

        return result
 
    # ── Network enrichment ────────────────────────────────────
    def _enrich(self, result: dict) -> None:
        """Adds live DNS, SSL, header, and threat API findings."""
        url    = result["url"]
        domain = urlparse(url).netloc.split(":")[0]
        enr    = result.setdefault("enrichment", {})

        # DNS
        dns = dns_lookup(domain)
        enr["dns"] = dns
        if not dns["resolves"]:
            result["score"] = min(result["score"]+self.weights["no_dns"],100)
            result["reasons"].append(f"DNS failure: {dns['error']}")

        # SSL (HTTPS only)
        if url.startswith("https://") and dns["resolves"]:
            sc = ssl_check(domain)
            enr["ssl"] = sc
            if sc["is_expired"] or (sc["error"] and "VERIFY" in sc["error"]):
                result["score"] = min(result["score"]+self.weights["ssl_error"],100)
                result["reasons"].append("SSL certificate error or expired")
            elif sc["is_new"]:
                result["score"] = min(result["score"]+self.weights["new_cert"],100)
                result["reasons"].append(f"SSL cert only {sc['cert_age_days']} days old")

        # HTTP headers
        if dns["resolves"]:
            hdr = header_check(url)
            enr["headers"] = hdr
            if hdr.get("risk_pts",0) >= 20:
                result["score"] = min(result["score"]+self.weights["missing_headers"],100)
                result["reasons"].append(f"Missing headers: {', '.join(hdr.get('missing',[]))}")

        # Threat intelligence (URLhaus)
        if dns["resolves"] and result["score"] < 100:
            th = urlhaus_check(url)
            enr["threat"] = th
            if th.get("found"):
                result["score"] = 100
                result["reasons"].append(f"IN THREAT DB: {th.get('threat','malware')}")

        # Recalculate risk after enrichment
        result["risk"] = classify(result["score"])
        result["confidence"] = confidence_score(
    len(result["reasons"]),
    len(CHECKS)
)

    # ── Public scan methods ───────────────────────────────────
    def scan(self, url: str, enrich: bool = False, force: bool = False) -> dict:
        """
        Scans a single URL.

        Args:
            url    : URL to scan.
            enrich : If True, run live DNS/SSL/header/API checks.
            force  : If True, ignore cached result and rescan.

        Returns:
            dict: Scan result stored in the database.
        """
        url = url.strip()

        # Cache lookup (Day 9)
        if not force:
            cached = self.db.get(url)
            if cached:
                return cached
            

        result = self._local(url)

        if enrich and REQUESTS_AVAILABLE:
            self._enrich(result)

        self.db.add(result)
        return result

    def scan_many(self, urls: list, enrich: bool = False,
                  force: bool = False, delay: float = 0.0) -> list:
        """
        Scans a list of URLs. Optionally rate-limits with delay.

        Args:
            urls   : List of URL strings.
            enrich : Run live checks for each URL.
            force  : Bypass cache for all URLs.
            delay  : Seconds to wait between enriched scans.
        """
        results = []
        for i, url in enumerate(urls):
            if url.strip():
                results.append(self.scan(url, enrich=enrich, force=force))
                if enrich and delay > 0 and i < len(urls)-1:
                    time.sleep(delay)
        return results

    def scan_file(self, filepath: str, enrich: bool = False,
                  force: bool = False) -> list:
        """Reads URLs from a text file (one per line, # = comment)."""
        try:
            lines = Path(filepath).read_text(encoding="utf-8").splitlines()
            urls  = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            return self.scan_many(urls, enrich=enrich, force=force)
        except FileNotFoundError:
            print(C.danger(f"  ERROR: File not found: '{filepath}'"))
            return []

    def scan_email(self, subject: str, body: str) -> dict:
        """
        Scans email text for phishing indicators.
        Returns a result dict (not stored in URL database).
        """
        text    = (subject+" "+body).lower()
        score   = 0; reasons = []

        for phrase in URGENCY_PHRASES:
            if phrase in text:
                score += 20; reasons.append(f"Urgency phrase: '{phrase}'")

        url_score = 0
        for word in body.split():
            word = word.strip(".,<>\"'()")
            if word.startswith("http"):
                r = self.scan(word)
                url_score = max(url_score, r["score"])
                if r["score"] > 30:
                    reasons.append(f"Suspicious URL: {truncate(word,40)}")

        score = min(score + url_score//2, 100)
        return {"subject":subject,"score":score,"risk":classify(score),
                "reasons":reasons,"scanned_at":now_iso()}

    # ── Tagging / notes ───────────────────────────────────────
    def tag(self, url: str, *tags: str) -> bool:
        r = self.db.get(url)
        if not r: return False
        existing = set(r.get("tags",[]))
        existing.update(tags)
        return self.db.update(url, {"tags": sorted(existing)})

    def note(self, url: str, text: str) -> bool:
        return self.db.update(url, {"notes":text, "reviewed":True})

    # ── Helpers ───────────────────────────────────────────────
    @staticmethod
    def _result(url, score, reasons, enrichment) -> dict:
     return {"url": url,
             "score": score,
             "confidence": 0,
             "risk": classify(score),
             "reasons": reasons,
             "enrichment": enrichment,
             "scanned_at": now_iso(),
             "tags": [],
             "notes": "",
    }

    def _on_exit(self):
        self.db._save()

    # ── Properties / dunders ──────────────────────────────────
    @property
    def scan_count(self):    return len(self.db)
    @property
    def phishing_count(self):return len(self.db.search(risk="PHISHING"))
    def __len__(self):       return len(self.db)
    def __contains__(self,u):return u in self.db
    def __str__(self):       return f"{self.name} v{self.version} | {self.scan_count} scans"
    def __repr__(self):      return f"PhishGuard(db='{self.db.path}', n={len(self)})"


# ════════════════════════════════════════════════════════════════
# SECTION 7 — OUTPUT FORMATTERS  (Day 7)
# table / json / csv output — same data, different shapes.
# ════════════════════════════════════════════════════════════════

def fmt_table(results: list, verbose: bool = False) -> str:
    if not results:
        return C.dim("  No results.\n")
    lines = [
    C.header(
        f"  {'RISK':<12} {'SCORE':>5} {'CONF':>6}  {'BAR':<12}  URL"
    )
]
    for r in results:
     risk = r.get("risk", "?")
     sc = r.get("score", 0)
     conf = r.get("confidence", 0)

     line = (
         f"  {C.by_risk(risk,f'{risk:<12}')} "
         f"{C.by_risk(risk,f'{sc:>3}/100')} "
         f"{conf:>3}%  "
         f"[{score_bar(sc)}]  "
         f"{C.dim(truncate(r.get('url',''),42))}"
    )
     lines.append(line)
     if verbose:
        for rs in r.get("reasons",[]):
            lines.append(C.dim(f"             • {rs}"))
        if r.get("tags"):
                lines.append(C.dim(f"             ◈ tags: {', '.join(r['tags'])}"))
    return "\n".join(lines)+"\n"

def fmt_summary(stats: dict) -> str:
    if not stats.get("total"):
        return C.dim("  No scans yet.\n")
    lines = [
        C.header(divider()),
        C.header(f"  {APP_NAME.upper()} — SUMMARY"),
        C.header(divider()),
        f"  Total    : {C.bold(str(stats['total']))}",
        f"  Avg score: {C.bold(str(stats['avg_score'])+'/100')}",
        f"  Highest  : {C.by_risk(stats['highest']['risk'], str(stats['max_score'])+'/100')}",
        divider("-"),
        f"  {C.safe(risk_icon('SAFE')+' SAFE        : '+str(stats.get('safe',0)))}",
        f"  {C.low(risk_icon('LOW RISK')+' LOW RISK    : '+str(stats.get('low_risk',0)))}",
        f"  {C.warn(risk_icon('SUSPICIOUS')+' SUSPICIOUS  : '+str(stats.get('suspicious',0)))}",
        f"  {C.danger(risk_icon('PHISHING')+' PHISHING    : '+str(stats.get('phishing',0)))}",
        C.header(divider()),
    ]
    return "\n".join(lines)+"\n"

def fmt_json(results: list, pretty: bool = True) -> str:
    return json.dumps(results, indent=2 if pretty else None, ensure_ascii=False)

def fmt_csv(results: list) -> str:
    buf = StringIO()
    w   = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["url","score","risk","reasons","scanned_at"])
    for r in results:
        w.writerow([r.get("url",""),r.get("score",0),r.get("risk",""),
                    " | ".join(r.get("reasons",[])),r.get("scanned_at","")])
    return buf.getvalue()

def write_summary_email(results, filename="summary_email.txt"):
    """
    Generates a plain-text security summary email.
    """

    phishing = [r for r in results if r["risk"] == "PHISHING"]

    lines = [
        "To: security@example.com",
        f"Subject: PhishGuard — {len(phishing)} phishing URLs detected",
        "",
        "Hello Security Team,",
        "",
        "The latest PhishGuard scan detected the following phishing URLs:",
        "",
    ]

    if phishing:
        for i, r in enumerate(phishing, 1):
            lines.append(f"{i}. {r['url']}")
            lines.append(f"   Score   : {r['score']}/100")
            lines.append(f"   Risk    : {r['risk']}")
            lines.append(f"   Reasons :")
            for reason in r["reasons"]:
                lines.append(f"      - {reason}")
            lines.append("")
    else:
        lines.append("No phishing URLs were detected.")
        lines.append("")

    lines.append("Regards,")
    lines.append("PhishGuard Pro")

    Path(filename).write_text("\n".join(lines), encoding="utf-8")

    print(C.safe(f"  Summary email saved to '{filename}'"))

# ════════════════════════════════════════════════════════════════
# SECTION 8 — CLI  (Day 7: argparse + subcommands)
# ════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "phishguard",
        description = C.header(f"{APP_NAME} v{VERSION} — Phishing Detection Tool"),
        epilog      = dedent("""\
            Examples:
              python day10_final_project.py scan --url http://paypa1.xyz
              python day10_final_project.py scan --file urls.txt --verbose
              python day10_final_project.py scan --url http://evil.xyz --enrich
              python day10_final_project.py history --risk PHISHING
              python day10_final_project.py report --format html
              python day10_final_project.py interactive
              python day10_final_project.py stats
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version","-V",action="version",version=f"%(prog)s {VERSION}")
    parser.add_argument("--db",default="phishguard.json",metavar="FILE",
                        help="Database file path. (default: phishguard.json)")
    parser.add_argument("--no-color",action="store_true",help="Disable colored output.")

    sub = parser.add_subparsers(dest="command",metavar="{scan,email,history,report,stats,config,interactive}")
    # ── scan ──────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Scan URLs for phishing.")
    ig = sp.add_mutually_exclusive_group()
    ig.add_argument("--url","-u",metavar="URL",help="Single URL to scan.")
    ig.add_argument("--file","-f",metavar="FILE",help="File of URLs (one per line).")
    ig.add_argument("--stdin",action="store_true",help="Read URLs from stdin.")
    sp.add_argument("--enrich","-e",action="store_true",help="Run live DNS/SSL/API checks.")
    sp.add_argument("--format",choices=["table","json","csv"],default="table")
    sp.add_argument("--output","-o",metavar="FILE",help="Write output to file.")
    sp.add_argument("--verbose","-v",action="store_true",help="Show reasons per URL.")
    sp.add_argument("--quiet","-q",action="store_true",help="Summary only.")
    sp.add_argument("--top","-t",type=int,metavar="N",help="Show N most dangerous.")
    sp.add_argument("--min-score",type=int,default=0,metavar="N")
    sp.add_argument("--whitelist",nargs="+",default=[],metavar="DOMAIN")
    sp.add_argument("--add-tld",nargs="+",default=[],metavar="TLD")
    sp.add_argument("--force",action="store_true",help="Bypass cache, rescan all.")
    sp.add_argument("--delay",type=float,default=0.5,metavar="SEC",
                    help="Seconds between enriched scans. (default: 0.5)")
    sp.add_argument(
    "--watch",
    type=int,
    metavar="SECONDS",
    help="Re-scan the file every N seconds."
)
    
    # ── email ─────────────────────────────────────────────
    ep = sub.add_parser("email", help="Scan an email for phishing.")
    ep.add_argument("--subject",required=True,help="Email subject.")
    ep.add_argument("--body",required=True,help="Email body.")

    # ── history ───────────────────────────────────────────────
    hp = sub.add_parser("history", help="Search scan history.")
    hp.add_argument("--risk",choices=["SAFE","LOW RISK","SUSPICIOUS","PHISHING"])
    hp.add_argument("--min-score",type=int,default=0,metavar="N")
    hp.add_argument("--keyword","-k",metavar="TEXT")
    hp.add_argument("--tag",metavar="TAG")
    hp.add_argument("--since",metavar="DATE",help="ISO date e.g. 2024-01-01")
    hp.add_argument("--verbose","-v",action="store_true")
    hp.add_argument("--format",choices=["table","json","csv"],default="table")

    # ── report ────────────────────────────────────────────────
    rp = sub.add_parser("report", help="Export scan report.")
    rp.add_argument("--format",choices=["html","csv","json","jsonl"],default="html")
    rp.add_argument("--output","-o",metavar="FILE")

    # ── stats ─────────────────────────────────────────────────
    sub.add_parser("stats", help="Show database statistics.")

    # ── config ────────────────────────────────────────────────
    cp = sub.add_parser("config", help="Show configuration.")
    cp.add_argument("--show-weights",action="store_true")
    cp.add_argument("--show-tlds",action="store_true")
    cp.add_argument("--show-all",action="store_true")

    # ── interactive ───────────────────────────────────────────
    ip = sub.add_parser("interactive",help="Interactive scan session (REPL).")
    ip.add_argument("--enrich","-e",action="store_true")
    ip.add_argument("--format",choices=["table","json"],default="table")

    return parser


# ════════════════════════════════════════════════════════════════
# SECTION 9 — SUBCOMMAND HANDLERS  (Day 7: command pattern)
# ════════════════════════════════════════════════════════════════

def _write_output(content: str, filepath: str | None) -> None:
    if filepath:
        Path(filepath).write_text(content, encoding="utf-8")
        print(C.safe(f"  Saved to '{filepath}'"))
    else:
        print(content, end="")


def handle_scan(args, pg: PhishGuard) -> int:
    for d in (args.whitelist or []): pg.whitelist.add(d.lower())
    for t in (args.add_tld or []):   pg.add_bad_tld(t) if hasattr(pg,"add_bad_tld") else pg.bad_tlds.append(t if t.startswith(".") else "."+t)
    
    if getattr(args, "watch", None):
     if not args.file:
         print(C.danger("  ERROR: --watch requires --file"))
         return 2
     return watch_file(args, pg) 
    if args.url:
        if not args.url.startswith(("http://","https://")):
            print(C.danger("  ERROR: URL must start with http:// or https://"))
            return 2
        results = [pg.scan(args.url, enrich=args.enrich, force=args.force)]
    elif args.file:
        if not Path(args.file).exists():
            print(C.danger(f"  ERROR: File not found: '{args.file}'")); return 2
        results = pg.scan_file(args.file, enrich=args.enrich, force=args.force)
    elif args.stdin:
        print(C.dim("  Reading from stdin (Ctrl+D when done)..."))
        urls    = [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
        results = pg.scan_many(urls, enrich=args.enrich, force=args.force, delay=args.delay)
    else:
        # Demo mode
        print(C.dim("  No input given — running built-in demo.\n"))
        results = pg.scan_many(DEMO_URLS, force=args.force)

    if args.min_score > 0:
        results = [r for r in results if r.get("score",0) >= args.min_score]
    if args.top:
        results = sorted(results, key=lambda r: r.get("score",0), reverse=True)[:args.top]

    if not args.quiet:
        if args.format == "json":
            content = fmt_json(results)
        elif args.format == "csv":
            content = fmt_csv(results)
        else:
            content = fmt_table(results, verbose=args.verbose)
        _write_output(content, args.output)
        write_summary_email(results)

    s = pg.db.stats()
    if s.get("total",0) > 0:
        print(fmt_summary(s))

    return 1 if pg.phishing_count > 0 else 0


def handle_history(args, pg: PhishGuard) -> int:
    results = pg.db.search(
        risk      = args.risk,
        min_score = args.min_score,
        keyword   = getattr(args,"keyword",None),
        tag       = getattr(args,"tag",None),
        since     = getattr(args,"since",None),
    )
    if not results:
        print(C.dim("  No matching results in history."))
        return 0

    fmt = getattr(args,"format","table")
    if fmt == "json":
        print(fmt_json(results))
    elif fmt == "csv":
        print(fmt_csv(results))
    else:
        verbose = getattr(args,"verbose",False)
        print(fmt_table(results, verbose=verbose))
    print(C.dim(f"  {len(results)} result(s) found."))
    return 0

def handle_email(args, pg: PhishGuard) -> int:
    result = pg.scan_email(
        subject=args.subject,
        body=args.body,
    )

    print(C.header(divider()))
    print(C.header("  EMAIL PHISHING SCAN"))
    print(C.header(divider()))

    print(f"Subject : {result['subject']}")
    print(f"Score   : {result['score']}/100")
    print(f"Risk    : {C.by_risk(result['risk'], result['risk'])}")

    if result["reasons"]:
        print("\nReasons:")
        for reason in result["reasons"]:
            print(f"  • {reason}")
    else:
        print("\nNo phishing indicators detected.")

    return 1 if result["risk"] == "PHISHING" else 0

def handle_report(args, pg: PhishGuard) -> int:
    fmt  = getattr(args,"format","html")
    path = getattr(args,"output",None)

    if fmt == "html":
        out = pg.db.export_html(path or "phishguard_report.html")
        print(C.safe(f"  HTML report → {out}  ({out.stat().st_size:,} bytes)"))
        print(C.dim("  Open in any browser — no server needed."))
    elif fmt == "csv":
        out = pg.db.export_csv(path or "phishguard_report.csv")
        print(C.safe(f"  CSV report  → {out}  ({out.stat().st_size:,} bytes)"))
    elif fmt == "json":
        content = fmt_json(pg.db.all())
        _write_output(content, path or "phishguard_report.json")
    elif fmt == "jsonl":
        out = pg.db.export_jsonl(path or "phishguard.jsonl")
        print(C.safe(f"  JSONL       → {out}  ({out.stat().st_size:,} bytes)"))
    return 0


def handle_stats(args, pg: PhishGuard) -> int:
    s = pg.db.stats()
    print(fmt_summary(s))
    if s.get("total",0) > 0:
        print(C.dim(f"  DB file  : {s['db_file']}"))
        print(C.dim(f"  DB size  : {s['db_size_kb']} KB"))
        print(C.dim(f"  Updated  : {s.get('updated','')[:19]}"))
        print()
    return 0


def handle_config(args, pg: PhishGuard) -> int:
    show_all = getattr(args,"show_all",False)
    print(C.header(divider()))
    print(C.header(f"  {APP_NAME} v{VERSION} — Configuration"))
    print(C.header(divider()))
    print(f"  DB path    : {pg.db.path}")
    print(f"  DB records : {len(pg.db)}")
    print(f"  Whitelist  : {len(pg.whitelist)} domains")
    print(f"  Bad TLDs   : {len(pg.bad_tlds)}")
    print(f"  Brands     : {len(pg.fake_brands)}")
    print()
    if getattr(args,"show_weights",False) or show_all:
        print(C.bold("  SCORE WEIGHTS:"))
        for n,w in sorted(SCORE_WEIGHTS.items(),key=lambda x:x[1],reverse=True):
            bar = C.danger("█"*(w//5)) + C.dim("░"*(20-w//5))
            print(f"    {n:<22} {w:>3} pts  {bar}")
        print()
    if getattr(args,"show_tlds",False) or show_all:
        print(C.bold("  BLOCKED TLDs:"))
        print("    " + "  ".join(pg.bad_tlds))
        print()
    return 0

def watch_file(args, pg: PhishGuard) -> int:
    """
    Continuously scans a URL file.
    Prints only URLs whose risk level changes.
    """

    previous = {}

    print(C.header(divider()))
    print(C.header("  WATCH MODE"))
    print(C.header(divider()))
    print(C.dim(f"  Watching '{args.file}' every {args.watch} seconds"))
    print(C.dim("  Press Ctrl+C to stop.\n"))

    try:
        while True:

            results = pg.scan_file(
                args.file,
                enrich=args.enrich,
                force=True
            )

            changes = []

            for r in results:
                url = r["url"]
                risk = r["risk"]

                old = previous.get(url)

                if old is None:
                    previous[url] = risk
                    continue

                if old != risk:
                    changes.append(r)
                    previous[url] = risk

            if changes:
                print(C.header(divider()))
                print(C.header(f"  {len(changes)} NEW THREAT(S) DETECTED"))
                print(C.header(divider()))
                print(fmt_table(changes, verbose=True))

            time.sleep(args.watch)

    except KeyboardInterrupt:
        print("\n" + C.dim("  Watch stopped."))

    return 0


REPL_HELP = dedent("""\
  Commands:
    <url>              Scan a URL  (must start with http:// or https://)
    history            Show all scans this session
    top [N]            Show N most dangerous (default 3)
    stats              Database statistics
    tag <url> <tag>    Add a tag to a scanned URL
    note <url> <text>  Add a note to a scanned URL
    export html        Export HTML report
    export csv         Export CSV report
    clear              Clear in-memory session (DB keeps its data)
    help               Show this message
    quit / exit        Exit the session
""")

def handle_interactive(args, pg: PhishGuard) -> int:
    enrich = getattr(args,"enrich",False)
    fmt    = getattr(args,"format","table")
    session_results = []

    print(C.header(divider()))
    print(C.header(f"  {APP_NAME} v{VERSION} — Interactive Mode"))
    print(C.header(divider()))
    print(C.dim("  Type a URL to scan. 'help' for commands. 'quit' to exit.\n"))

    while True:
        try:
            raw = input(C.bold("  phish> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.dim('  Session ended.')}")
            break

        if not raw: continue
        parts = raw.split()
        cmd   = raw.lower()

        if cmd in ("quit","exit","q"):
            print(C.dim(f"\n  Scanned {len(session_results)} URLs this session."))
            break
        elif cmd == "help":
            print(C.dim(REPL_HELP))
        elif cmd == "stats":
            print(fmt_summary(pg.db.stats()))
        elif cmd == "history":
            data = pg.db.all()
            print(fmt_table(data) if data else C.dim("  No history yet."))
        elif parts[0] == "top":
            n   = int(parts[1]) if len(parts)>1 and parts[1].isdigit() else 3
            top = pg.db.search()[:n]
            print(fmt_table(top, verbose=True) if top else C.dim("  No results."))
        elif parts[0] == "tag" and len(parts) >= 3:
            pg.tag(parts[1], *parts[2:])
            print(C.safe(f"  Tagged '{parts[1]}' with {parts[2:]}"))
        elif parts[0] == "note" and len(parts) >= 3:
            pg.note(parts[1], " ".join(parts[2:]))
            print(C.safe(f"  Note saved."))
        elif parts[0] == "export" and len(parts) > 1:
            if parts[1] == "html":
                out = pg.db.export_html(); print(C.safe(f"  Exported → {out}"))
            elif parts[1] == "csv":
                out = pg.db.export_csv();  print(C.safe(f"  Exported → {out}"))
        elif cmd == "clear":
            session_results = []
            print(C.dim("  Session cleared (database unchanged)."))
        elif raw.startswith(("http://","https://")):
            r = pg.scan(raw, enrich=enrich)
            session_results.append(r)
            if fmt == "json":
                print(fmt_json([r]))
            else:
                print(fmt_table([r], verbose=True))
        else:
            print(C.dim(f"  Unknown: '{truncate(raw,30)}'. Type 'help' for commands."))
    return 0


# ════════════════════════════════════════════════════════════════
# SECTION 10 — DEMO DATA
# ════════════════════════════════════════════════════════════════

DEMO_URLS = [
    "https://www.google.com/search?q=python+tutorial",
    "https://github.com/user/phishing-detector",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://python.org/downloads",
    "https://stackoverflow.com/questions/tagged/python",
    "http://paypa1.secure-login.xyz/verify",
    "http://192.168.1.1/admin/login",
    "http://free-prize.win/claim?ssn=123-45-6789",
    "http://micros0ft-update.tk/download",
    "http://my-secure-bank-login-update.com/confirm?password=abc",
    "http://bit.ly/3xEvil",
    "http://tw1tter-login.xyz/verify?pwd=abc",
    "http://amaz0n-prime-deals.tk/offer?creditcard=1234",
    "http://login.secure.paypal.com.evil.xyz/webscr",
]


# ════════════════════════════════════════════════════════════════
# SECTION 11 — MAIN ENTRY POINT  (Day 7: if __name__ guard)
# ════════════════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Disable color if requested
    if getattr(args,"no_color",False):
        C.ON = False

    # No subcommand -> print banner + help
    if not args.command:
        print(C.header(divider()))
        print(C.header(f"  {APP_NAME} v{VERSION}"))
        print(C.header(f"  Complete Phishing Detection Tool"))
        print(C.header(divider()))
        print()
        print("  Days covered in this project:")
        days = [
            ("Day 1","Variables, input(), if/else, loops"),
            ("Day 2","Functions — def, parameters, return"),
            ("Day 3","File I/O — open(), read, write, with"),
            ("Day 4","Dicts, scoring system, filter, sort"),
            ("Day 5","Classes — __init__, methods, inheritance, dunders"),
            ("Day 6","Modules — config, utils, constants, Enum, namedtuple"),
            ("Day 7","CLI — argparse, subcommands, colors, REPL"),
            ("Day 8","External libs — requests, socket, ssl, regex, hashlib"),
            ("Day 9","JSON persistence — ScanDatabase, atomic write, export"),
            ("Day 10","Final project — everything wired together"),
        ]
        for d, desc in days:
            print(f"  {C.bold(d):<25}  {C.dim(desc)}")
        print()
        parser.print_help()
        print()
        print(C.dim("  Running built-in demo scan...\n"))
        args.command = "scan"
        args.url     = None
        args.file    = None
        args.stdin   = False
        args.enrich  = False
        args.format  = "table"
        args.output  = None
        args.verbose = False
        args.quiet   = False
        args.top     = None
        args.min_score = 0
        args.whitelist = []
        args.add_tld   = []
        args.force     = False
        args.delay     = 0.0

    pg = PhishGuard(db_path=getattr(args,"db","phishguard.json"))

    handlers = {
        "scan":        handle_scan,
        "email":       handle_email,
        "history":     handle_history,
        "report":      handle_report,
        "stats":       handle_stats,
        "config":      handle_config,
        "interactive": handle_interactive,
    }

    handler = handlers.get(args.command)
    if not handler:
        print(C.danger(f"  Unknown command: '{args.command}'")); return 2

    try:
        return handler(args, pg)
    except KeyboardInterrupt:
        print(f"\n{C.dim('  Interrupted.')}"); return 0
    except Exception as e:
        print(C.danger(f"  ERROR: {e}")); return 1


if __name__ == "__main__":

    code = main()

    # ── Post-run: write all export files ─────────────────────
    if "--help" not in sys.argv and "-h" not in sys.argv:
        pg = PhishGuard.__new__(PhishGuard)
        pg.db = ScanDatabase("phishguard.json")

        if len(pg.db) > 0:
            print()
            print(C.header(divider()))
            print(C.header("  FILES GENERATED"))
            print(C.header(divider())) 

            exports = [
                ("phishguard.json",         "Persistent scan database  (JSON)"),
                (pg.db.export_csv(),        "Spreadsheet-ready export (CSV)"),
                (pg.db.export_html(),       "Browser report — open directly (HTML)"),
                (pg.db.export_jsonl(),      "Streaming format          (JSONL)"),
            ]
            for path, desc in exports:
                p   = Path(path) if isinstance(path, str) else path
                sz  = f"{p.stat().st_size:,}" if p.exists() else "0"
                print(f"  {str(p):<36} {sz:>8} bytes   {C.dim(desc)}")

            # Backup
            try:
                bk = pg.db.backup()
                print(f"  {str(bk):<36}           {C.dim('Timestamped backup')}")
            except Exception:
                pass

            print()
            print(C.dim("  Tip: open phishguard_report.html in your browser!"))

    sys.exit(code)