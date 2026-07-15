import os
import csv
import json
import time
import atexit
import shutil
import hashlib
import tempfile
import urllib.parse
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

print("=== LESSON 1: Why Persistence Matters ===\n")
print("  Without persistence: results vanish on exit.")
print("  With JSON:           history survives, searchable, shareable.\n")

print("=== LESSON 2: json.dumps() and json.loads() ===\n")

# Basic serialisation
scan_result = {
    "url":        "http://paypa1.xyz/verify",
    "score":      85,
    "risk":       "PHISHING",
    "reasons":    ["Fake brand: 'paypa1'", "High-risk TLD: .xyz", "Suspicious path: /verify"],
    "scanned_at": "2024-01-15 10:30:00",
    "tags":       ["phishing", "brand-impersonation"],
    "flagged":    True,
    "metadata":   None,
}

# dumps: Python dict -> JSON string
json_string = json.dumps(scan_result)
print("  json.dumps() — compact (one line):")
print(f"  {json_string[:80]}...")
print()

# dumps with indent: human-readable
pretty = json.dumps(scan_result, indent=2)
print("  json.dumps(indent=2) — pretty printed:")
for line in pretty.splitlines()[:8]:
    print(f"  {line}")
print("  ...")
print()

# loads: JSON string -> Python dict
restored = json.loads(json_string)
print("  json.loads() — restored from string:")
print(f"    type:  {type(restored)}")
print(f"    score: {restored['score']}")
print(f"    risk:  {restored['risk']}")
print(f"    equal: {restored == scan_result}")
print()

# dumps options
print("  json.dumps() options:")
print(f"    indent=2          : {json.dumps({'a':1,'b':2}, indent=2)}")
print(f"    sort_keys=True    : {json.dumps({'b':2,'a':1}, sort_keys=True)}")
print(f"    ensure_ascii=False: handles unicode — café -> {'café'!r}")
print(f"    separators        : {json.dumps({'a':1,'b':2}, separators=(',',':'))}")
print()

print("=== LESSON 3: Custom Serialisers for datetime ===\n")

# Problem
print("  Problem: datetime crashes json.dumps()")
try:
    json.dumps({"time": datetime.now()})
except TypeError as e:
    print(f"    TypeError: {e}")
print()

# Solution 1: convert to ISO string manually (simplest)
now_str = datetime.now(timezone.utc).isoformat()
safe    = {"time": now_str}
print(f"  Solution 1 — store as ISO string: {now_str}")
print(f"    json.dumps: {json.dumps(safe)}")
print()

# Solution 2: custom JSONEncoder
class PhishEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that handles types json can't normally serialise.

    Subclass json.JSONEncoder and override default(obj).
    Called only when the base encoder can't handle the type.
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            # Store datetime as ISO 8601 string with timezone
            return obj.isoformat()
        if isinstance(obj, set):
            # Store set as sorted list (sorted for reproducibility)
            return sorted(list(obj))
        if isinstance(obj, Path):
            # Store Path as string
            return str(obj)
        # For anything else, let the base class raise TypeError
        return super().default(obj)

tricky = {
    "scanned_at": datetime.now(timezone.utc),
    "tags":       {"phishing", "malware", "brand-abuse"},
    "report":     Path("reports/scan.json"),
}

encoded = json.dumps(tricky, cls=PhishEncoder, indent=2)
print("  Solution 2 — PhishEncoder:")
for line in encoded.splitlines():
    print(f"    {line}")
print()

# Solution 3: to_dict() helper on result objects
def result_to_dict(result: dict) -> dict:
    """
    Converts a scan result to a JSON-safe dict.
    Converts datetime -> ISO string, set -> sorted list.
    """
    safe = {}
    for key, value in result.items():
        if isinstance(value, datetime):
            safe[key] = value.isoformat()
        elif isinstance(value, set):
            safe[key] = sorted(list(value))
        elif isinstance(value, dict):
            safe[key] = result_to_dict(value)   # recurse for nested dicts
        else:
            safe[key] = value
    return safe

# Restore datetime from ISO string
def parse_datetime(iso_str: str) -> datetime:
    """Parses an ISO 8601 datetime string back to a datetime object."""
    try:
        return datetime.fromisoformat(iso_str)
    except (ValueError, TypeError):
        return None


print("=== LESSON 4: json.dump() and json.load() ===\n")

DEMO_FILE = Path("demo_scan.json")

# Write
sample_results = [
    {"url":"https://google.com",       "score":0,  "risk":"SAFE",      "reasons":[],"scanned_at":"2024-01-15T10:00:00"},
    {"url":"http://paypa1.xyz/verify", "score":85, "risk":"PHISHING",   "reasons":["Fake brand"],"scanned_at":"2024-01-15T10:01:00"},
    {"url":"http://free-prize.tk",     "score":40, "risk":"SUSPICIOUS", "reasons":["Bad TLD","HTTP"],"scanned_at":"2024-01-15T10:02:00"},
]

with open(DEMO_FILE, "w", encoding="utf-8") as f:
    json.dump(sample_results, f, indent=2, ensure_ascii=False)

print(f"  Written: {DEMO_FILE}  ({DEMO_FILE.stat().st_size} bytes)")

# Read back
with open(DEMO_FILE, "r", encoding="utf-8") as f:
    loaded = json.load(f)

print(f"  Loaded:  {len(loaded)} results")
for r in loaded:
    print(f"    {r['risk']:<12} {r['score']:>3}/100  {r['url']}")
print()

# Handle errors gracefully
def load_json_safe(filepath: Path, default=None):
    """
    Loads JSON from a file, returning default if anything goes wrong.
    Never crashes — safe to call on first run when file doesn't exist.

    Args:
        filepath : Path to the JSON file.
        default  : Value to return on any error. Default None.

    Returns:
        Parsed JSON object, or default.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        # Normal on first run — file doesn't exist yet
        return default if default is not None else []
    except json.JSONDecodeError as e:
        # File is corrupted or empty
        print(f"  WARNING: {filepath} is corrupted ({e}). Starting fresh.")
        return default if default is not None else []
    except PermissionError as e:
        print(f"  ERROR: Cannot read {filepath}: {e}")
        return default if default is not None else []

print("  load_json_safe() on missing file:")
result = load_json_safe(Path("nonexistent.json"), default=[])
print(f"    Returns: {result!r}  (empty list, no crash)")
print()


print("=== LESSON 5: Atomic Writes ===\n")

def atomic_write_json(data, filepath: Path, **kwargs) -> None:
    """
    Writes JSON to filepath atomically.
    The file is never left in a partially-written corrupt state.

    Args:
        data     : JSON-serialisable Python object.
        filepath : Destination path.
        **kwargs : Passed to json.dump() (e.g. indent=2).
    """
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the SAME directory as the target.
    # SAME directory is critical: rename() is only atomic when source
    # and destination are on the same filesystem/device.
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir    = filepath.parent,
        prefix = f".{filepath.stem}_tmp_",
        suffix = ".json",
    )

    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, **kwargs)
            f.flush()               # push from Python buffer to OS buffer
            os.fsync(f.fileno())    # push from OS buffer to physical disk

        # Atomic rename: replaces filepath in one OS operation
        Path(tmp_path).replace(filepath)

    except Exception:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise   # re-raise the original exception


# Demo
ATOMIC_FILE = Path("atomic_test.json")
atomic_write_json(sample_results, ATOMIC_FILE, indent=2)
print(f"  Atomic write complete: {ATOMIC_FILE}  ({ATOMIC_FILE.stat().st_size} bytes)")
print("  If program had crashed mid-write, old file would be untouched.")
print()

print("=== LESSON 6: ScanDatabase Class ===\n")

DB_SCHEMA_VERSION = 2   # increment when the format changes

class ScanDatabase:
    """
    A persistent JSON-backed database of URL scan results.

    The database file contains a single JSON object:
    {
        "version": 2,
        "created": "2024-01-15T10:00:00",
        "updated": "2024-01-15T10:30:00",
        "count":   42,
        "results": [ {...}, {...}, ... ]
    }

    Usage:
        db = ScanDatabase("scans.json")
        db.add(result)
        db.search(risk="PHISHING")
        db.export_csv("report.csv")
    """

    def __init__(self, filepath: str = "scan_database.json"):
        self.filepath = Path(filepath)
        self._records = {}    # url_hash -> result dict  (in-memory index)
        self._meta    = {}    # database metadata
        self._load()
        print(f"  [{self.__class__.__name__}] Opened '{self.filepath}' "
              f"({len(self._records)} records)")

    # ── Private: load from disk ───────────────────────────────────────
    def _load(self) -> None:
        """
        Loads the database from disk into self._records.
        Handles missing file (first run) and schema migration.
        """
        raw = load_json_safe(self.filepath, default=None)
        # Automatically back up the existing database before loading it
        if raw is not None:
            if isinstance(raw, dict):
                if raw.get("count", 0) > 0:
                   self.backup()
            elif isinstance(raw, list):
               if len(raw) > 0:
                  self.backup()

        if raw is None:
            # First run — initialise empty database
            self._meta    = {
                "version": DB_SCHEMA_VERSION,
                "created": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat(),
            }
            self._records = {}
            return

        # Schema migration: handle old list-only format (version 1)
        if isinstance(raw, list):
            print(f"  Migrating old format (list) to schema v{DB_SCHEMA_VERSION}...")
            results = raw
            self._meta = {
                "version": DB_SCHEMA_VERSION,
                "created": datetime.now(timezone.utc).isoformat(),
                "updated": datetime.now(timezone.utc).isoformat(),
            }
        else:
            # Current format: dict with metadata + results list
            self._meta = {
                "version": raw.get("version", 1),
                "created": raw.get("created", ""),
                "updated": raw.get("updated", ""),
            }
            results = raw.get("results", [])

        # Index by URL hash for O(1) lookup
        self._records = {}
        for r in results:
            key = self._key(r.get("url", ""))
            self._records[key] = r

    # ── Private: save to disk ─────────────────────────────────────────
    def _save(self) -> None:
        """Persists current in-memory state to disk atomically."""
        self._meta["updated"] = datetime.now(timezone.utc).isoformat()
        data = {
            "version": DB_SCHEMA_VERSION,
            "created": self._meta.get("created", ""),
            "updated": self._meta["updated"],
            "count":   len(self._records),
            "results": list(self._records.values()),
        }
        atomic_write_json(data, self.filepath, indent=2, ensure_ascii=False)

    # ── Private: url -> hash key ──────────────────────────────────────
    @staticmethod
    def _key(url: str) -> str:
        """
        Returns a SHA-256 key for the base URL
        (scheme + host + path), ignoring query parameters.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url.strip().lower())
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        return hashlib.sha256(base_url.encode()).hexdigest()[:16]

    # ── CREATE ────────────────────────────────────────────────────────
    def add(self, result: dict) -> str:
        """
        Adds or updates a scan result in the database.
        If the URL was scanned before, the old result is replaced.

        Args:
            result: Scan result dict with at least a 'url' key.

        Returns:
            str: The URL hash key used to store this result.
        """
        if "url" not in result:
            raise ValueError("Result must have a 'url' key.")

        # Ensure scanned_at is always a string
        if "scanned_at" not in result:
            result["scanned_at"] = datetime.now(timezone.utc).isoformat()

        key = self._key(result["url"])
        self._records[key] = result
        self._save()
        return key

    def add_many(self, results: list) -> int:
        """
        Bulk-adds a list of results. Saves once at the end (efficient).

        Args:
            results: List of scan result dicts.

        Returns:
            int: Number of results added.
        """
        for result in results:
            if "url" in result:
                if "scanned_at" not in result:
                    result["scanned_at"] = datetime.now(timezone.utc).isoformat()
                key = self._key(result["url"])
                self._records[key] = result
        self._save()
        return len(results)

    # ── READ ──────────────────────────────────────────────────────────
    def get(self, url: str) -> dict | None:
        """
        Retrieves a scan result by URL.

        Args:
            url: The URL to look up.

        Returns:
            dict or None if not found.
        """
        return self._records.get(self._key(url))

    def all(self) -> list:
        """Returns all scan results as a list."""
        return list(self._records.values())

    def search(self,
           risk:      str = None,
           min_score: int = None,
           max_score: int = None,
           keyword:   str = None,
           since:     str = None,
           tag:       str = None) -> list:
        """
        Searches scan results with optional filters.

        Args:
            risk      : Filter by risk level ("SAFE","LOW RISK","SUSPICIOUS","PHISHING").
            min_score : Only return results with score >= min_score.
            max_score : Only return results with score <= max_score.
            keyword   : Only return results whose URL contains keyword.
            since     : Only return results scanned after this ISO date string.

        Returns:
            list: Matching scan result dicts, sorted by score descending.

        Example:
            db.search(risk="PHISHING", since="2024-01-01")
        """
        results = list(self._records.values())

        if risk:
            results = [r for r in results if r.get("risk") == risk.upper()]

        if min_score is not None:
            results = [r for r in results if r.get("score", 0) >= min_score]

        if max_score is not None:
            results = [r for r in results if r.get("score", 0) <= max_score]

        if keyword:
            kw = keyword.lower()
            results = [r for r in results if kw in r.get("url", "").lower()]
        
        if tag:
            tag = tag.lower()
            results = [ r for r in results if tag in {t.lower() for t in r.get("tags", [])}
    ]
        if since:
            results = [r for r in results
                       if r.get("scanned_at", "") >= since]

        return sorted(results, key=lambda r: r.get("score", 0), reverse=True)

    def contains(self, url: str) -> bool:
        """Returns True if this URL has been scanned before."""
        return self._key(url) in self._records

    # ── UPDATE ────────────────────────────────────────────────────────
    def update(self, url: str, fields: dict) -> bool:
        """
        Updates specific fields of an existing scan result.

        Args:
            url    : The URL to update.
            fields : Dict of field names and new values to merge in.

        Returns:
            bool: True if found and updated, False if URL not in DB.
        """
        key = self._key(url)
        if key not in self._records:
            return False
        self._records[key].update(fields)
        self._save()
        return True

    # ── DELETE ────────────────────────────────────────────────────────
    def delete(self, url: str) -> bool:
        """
        Removes a scan result from the database.

        Args:
            url: The URL to delete.

        Returns:
            bool: True if found and deleted, False if not found.
        """
        key = self._key(url)
        if key not in self._records:
            return False
        del self._records[key]
        self._save()
        return True

    def clear(self) -> int:
        """Removes ALL records. Returns count of deleted records."""
        count = len(self._records)
        self._records = {}
        self._save()
        return count
    
    def deduplicate(self) -> int:
        """
        Removes duplicate scan results based on the base URL
        (scheme + host + path), ignoring query parameters.

        If multiple results have the same base URL, keeps the one
        with the highest score.

        Returns:
             int: Number of duplicate records removed.
        """
        from urllib.parse import urlparse

        unique = {}

        for result in self._records.values():
            parsed = urlparse(result.get("url", ""))

        # Ignore query string and fragment
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Keep the highest-score result
            if (
               base_url not in unique
               or result.get("score", 0) > unique[base_url].get("score", 0)
        ):
              unique[base_url] = result

        removed = len(self._records) - len(unique)

        # Rebuild the database index
        self._records.clear()

        for record in unique.values():
         self._records[self._key(record["url"])] = record


        if removed:
         self._save()

        return removed

    # ── STATS ─────────────────────────────────────────────────────────
    def stats(self) -> dict:
        """
        Returns a summary statistics dict.

        Returns:
            dict: total, safe, low_risk, suspicious, phishing, avg_score, etc.
        """
        records = list(self._records.values())
        if not records:
            return {"total": 0}

        total = len(records)
        scores = [r.get("score", 0) for r in records]

        return {
            "total":      total,
            "safe":       sum(1 for r in records if r.get("risk") == "SAFE"),
            "low_risk":   sum(1 for r in records if r.get("risk") == "LOW RISK"),
            "suspicious": sum(1 for r in records if r.get("risk") == "SUSPICIOUS"),
            "phishing":   sum(1 for r in records if r.get("risk") == "PHISHING"),
            "avg_score":  round(sum(scores) / total, 1),
            "max_score":  max(scores),
            "min_score":  min(scores),
            "db_file":    str(self.filepath),
            "db_size_kb": round(self.filepath.stat().st_size / 1024, 1)
                          if self.filepath.exists() else 0,
            "last_updated": self._meta.get("updated", ""),
        }

    # ── EXPORT ────────────────────────────────────────────────────────
    def export_csv(self, filepath: str = "scan_report.csv") -> Path:
        """
        Exports all results to a CSV file.
        Readable in Excel, Google Sheets, any spreadsheet tool.

        Args:
            filepath: Output CSV file path.

        Returns:
            Path: The written file path.
        """
        out = Path(filepath)
        records = sorted(
            self._records.values(),
            key=lambda r: r.get("score", 0),
            reverse=True
        )

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            # Header
            writer.writerow(["url", "score", "risk", "reasons", "scanned_at"])
            for r in records:
                writer.writerow([
                    r.get("url", ""),
                    r.get("score", 0),
                    r.get("risk", ""),
                    " | ".join(r.get("reasons", [])),
                    r.get("scanned_at", ""),
                ])

        print(f"  Exported CSV: {out}  ({out.stat().st_size} bytes, {len(records)} rows)")
        return out

    def export_html(self, filepath: str = "scan_report.html") -> Path:
        """
        Exports all results to a self-contained HTML report.
        Open in any browser — no server needed.

        Args:
            filepath: Output HTML file path.

        Returns:
            Path: The written file path.
        """
        out = Path(filepath)
        records = sorted(
            self._records.values(),
            key=lambda r: r.get("score", 0),
            reverse=True
        )
        s = self.stats()

        # Risk level colors
        colors = {
            "SAFE":       "#22c55e",
            "LOW RISK":   "#84cc16",
            "SUSPICIOUS": "#f59e0b",
            "PHISHING":   "#ef4444",
        }

        # Build rows
        rows = []
        for r in records:
            risk  = r.get("risk", "UNKNOWN")
            color = colors.get(risk, "#94a3b8")
            score = r.get("score", 0)
            bar   = f'<div style="background:{color};width:{score}%;height:8px;border-radius:4px"></div>'
            reasons = "<br>".join(r.get("reasons", []))
            rows.append(f"""
        <tr>
          <td style="font-family:monospace;font-size:12px">{r.get('url','')}</td>
          <td style="text-align:center">{score}<br>{bar}</td>
          <td style="text-align:center;color:{color};font-weight:700">{risk}</td>
          <td style="font-size:12px;color:#94a3b8">{reasons}</td>
          <td style="font-size:11px;color:#64748b">{r.get('scanned_at','')}</td>
        </tr>""")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PhishingDetector Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
    h1   {{ color: #38bdf8; }} h2 {{ color: #94a3b8; font-weight: 400; }}
    .stats {{ display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }}
    .stat  {{ background: #1e293b; border-radius: 8px; padding: 16px 24px; min-width: 120px; }}
    .stat .n {{ font-size: 28px; font-weight: 700; }}
    .stat .l {{ font-size: 12px; color: #64748b; text-transform: uppercase; }}
    table  {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }}
    th     {{ background: #0f172a; padding: 12px 16px; text-align: left; font-size: 12px;
              text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; }}
    td     {{ padding: 12px 16px; border-bottom: 1px solid #0f172a; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #162032; }}
  </style>
</head>
<body>
  <h1>PhishingDetector — Scan Report</h1>
  <h2>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
  <div style="margin:20px 0;">
  <a href="day9_report.csv"
     download
     style="
        display:inline-block;
        padding:10px 16px;
        background:#38bdf8;
        color:white;
        text-decoration:none;
        border-radius:6px;
        font-weight:bold;">
     Download CSV
  </a>
</div>
  <div class="stats">
    <div class="stat"><div class="n">{s['total']}</div><div class="l">Total</div></div>
    <div class="stat"><div class="n" style="color:#22c55e">{s['safe']}</div><div class="l">Safe</div></div>
    <div class="stat"><div class="n" style="color:#f59e0b">{s['suspicious']}</div><div class="l">Suspicious</div></div>
    <div class="stat"><div class="n" style="color:#ef4444">{s['phishing']}</div><div class="l">Phishing</div></div>
    <div class="stat"><div class="n">{s['avg_score']}</div><div class="l">Avg Score</div></div>
  </div>
  <table>
    <thead>
      <tr><th>URL</th><th>Score</th><th>Risk</th><th>Reasons</th><th>Scanned At</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""

        out.write_text(html, encoding="utf-8")
        print(f"  Exported HTML: {out}  ({out.stat().st_size} bytes, {len(records)} rows)")
        return out
    
    def export_jsonl(self, filepath: str = "scan_report.jsonl") -> Path:
     """
    Exports all scan results in JSON Lines (JSONL) format.
    One JSON object is written per line.

    Args:
        filepath: Output JSONL file path.

    Returns:
        Path: The written file path.
    """
     out = Path(filepath)

    # Start with a fresh file
     if out.exists():
        out.unlink()

     records = sorted(
        self._records.values(),
        key=lambda r: r.get("score", 0),
        reverse=True
    )

     for record in records:
         append_jsonl(record, out)

     print(f"  Exported JSONL: {out} ({out.stat().st_size} bytes, {len(records)} rows)")
     return out

    def backup(self, backup_dir: str = "backups") -> Path:
        """
        Creates a timestamped backup of the database file.

        Args:
            backup_dir: Directory to store backups.

        Returns:
            Path: The backup file path.
        """
        if not self.filepath.exists():
            raise FileNotFoundError(f"Database file '{self.filepath}' not found.")

        bd  = Path(backup_dir)
        bd.mkdir(parents=True, exist_ok=True)
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = bd / f"{self.filepath.stem}_{ts}.json"
        shutil.copy2(self.filepath, dst)
        print(f"  Backup created: {dst}")
        return dst

    # ── Dunder methods ────────────────────────────────────────────────
    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, url: str) -> bool:
        return self.contains(url)

    def __repr__(self) -> str:
        return f"ScanDatabase('{self.filepath}', records={len(self)})"

    def __iter__(self):
        return iter(self._records.values())

print("=== LESSON 7: Schema Versioning & Migration ===\n")

def migrate_result(result: dict) -> dict:
    """
    Ensures a result dict has all current fields.
    Safe to run on both old and new results.

    Missing fields get safe defaults rather than crashing.
    """
    # Fields added in v2
    result.setdefault("tags",       [])
    result.setdefault("enrichment", {})
    result.setdefault("reviewed",   False)
    result.setdefault("notes",      "")

    # Normalise scanned_at to ISO format
    ts = result.get("scanned_at", "")
    if ts and "T" not in ts:
        # Old format: "2024-01-15 10:30:00" -> "2024-01-15T10:30:00"
        result["scanned_at"] = ts.replace(" ", "T", 1)

    return result


def migrate_database(raw: dict | list) -> dict:
    """
    Migrates any database format to the current schema version.

    Args:
        raw: Raw data loaded from file (dict or list for old format).

    Returns:
        dict: Data in current schema format.
    """
    # Handle old list-only format (version 1)
    if isinstance(raw, list):
        print("  Migrating v1 format (bare list) -> v2...")
        results = [migrate_result(r) for r in raw]
        return {
            "version": DB_SCHEMA_VERSION,
            "created": datetime.now(timezone.utc).isoformat(),
            "updated": datetime.now(timezone.utc).isoformat(),
            "count":   len(results),
            "results": results,
        }

    # Already in dict format — migrate individual results
    version = raw.get("version", 1)
    if version < DB_SCHEMA_VERSION:
        print(f"  Migrating from schema v{version} -> v{DB_SCHEMA_VERSION}...")
        raw["results"] = [migrate_result(r) for r in raw.get("results", [])]
        raw["version"] = DB_SCHEMA_VERSION

    return raw


# Demo migration
old_format_v1 = [
    {"url": "https://google.com", "score": 0, "risk": "SAFE",
     "reasons": [], "scanned_at": "2024-01-10 09:00:00"},
    {"url": "http://paypa1.xyz",  "score": 85, "risk": "PHISHING",
     "reasons": ["Fake brand"], "scanned_at": "2024-01-10 09:01:00"},
]

migrated = migrate_database(old_format_v1)
print(f"  Migrated: version={migrated['version']}, {migrated['count']} results")
print(f"  First result keys: {list(migrated['results'][0].keys())}")
print(f"  scanned_at migrated: '{migrated['results'][0]['scanned_at']}'")
print()

print("=== LESSON 8: atexit — Auto-Save ===\n")

_AUTO_SAVE_REGISTRY = []   # list of (db_instance, filepath) pairs

def register_auto_save(db: ScanDatabase) -> None:
    """
    Registers a ScanDatabase instance for auto-save on exit.
    The database will be saved automatically when the program ends.
    """
    def _save_on_exit():
        print(f"\n  [atexit] Auto-saving '{db.filepath}'...")
        db._save()
        print(f"  [atexit] Saved {len(db)} records.")

    atexit.register(_save_on_exit)
    _AUTO_SAVE_REGISTRY.append(db)
    print(f"  Registered auto-save for '{db.filepath}'")


print("=== LESSON 9: PersistentDetector ===\n")

# Condensed scoring constants
SCORE_WEIGHTS = {
    "no_https":15,"bad_tld":25,"fake_brand":30,"suspicious_path":10,
    "ip_address":20,"long_subdomain":10,"excessive_hyphens":15,"query_sensitive":30,
}
BAD_TLDS        = (".xyz",".tk",".ml",".win",".top",".click",".gq",".cf",".pw",".buzz")
FAKE_BRANDS     = ("paypa1","amaz0n","g00gle","micros0ft","app1e","faceb00k","netfl1x","tw1tter")
SUSPICIOUS_PATHS= ("verify","login","update","confirm","secure","validate","suspend","billing")
SENSITIVE_PARAMS= frozenset({"ssn","password","passwd","pwd","creditcard","cvv","pin"})
WHITELISTED     = frozenset({"google.com","github.com","youtube.com","amazon.com","microsoft.com","python.org"})


class PersistentDetector:
    """
    A PhishingDetector that persists all results to a JSON database.

    - Results survive program restarts
    - Known URLs are never rescanned (uses cache)
    - Full CRUD via the embedded ScanDatabase
    - Auto-saves on exit via atexit

    Usage:
        detector = PersistentDetector("my_scans.json")
        result   = detector.scan("http://paypa1.xyz")
        detector.db.export_csv("report.csv")
        detector.db.export_html("report.html")
    """

    def __init__(self, db_path: str = "phish_history.json"):
        self.db   = ScanDatabase(db_path)
        self.name = "PersistentDetector"
        register_auto_save(self.db)

    def _classify(self, score: int) -> str:
        if score == 0:   return "SAFE"
        if score <= 30:  return "LOW RISK"
        if score <= 60:  return "SUSPICIOUS"
        return "PHISHING"

    def _local_scan(self, url: str) -> dict:
        """Runs all local phishing checks. No network needed."""
        url    = url.strip()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        params = {p.split("=")[0].lower() for p in query.split("&") if p}
        base   = ".".join(domain.split(".")[-2:])

        score = 0; reasons = []

        if base in WHITELISTED:
            return {"url":url,"score":0,"risk":"SAFE",
                    "reasons":["Trusted domain"],
                    "scanned_at":datetime.now(timezone.utc).isoformat(),
                    "tags":[],"enrichment":{}}

        if parsed.scheme != "https":
            score += SCORE_WEIGHTS["no_https"]; reasons.append("HTTP not HTTPS")
        for t in BAD_TLDS:
            if domain.endswith(t):
                score += SCORE_WEIGHTS["bad_tld"]; reasons.append(f"Bad TLD: {t}"); break
        for b in FAKE_BRANDS:
            if b in domain:
                score += SCORE_WEIGHTS["fake_brand"]; reasons.append(f"Fake brand: '{b}'"); break
        for w in SUSPICIOUS_PATHS:
            if w in path:
                score += SCORE_WEIGHTS["suspicious_path"]; reasons.append(f"Suspicious path: /{w}"); break
        parts = domain.split(":")[0].split(".")
        if sum(1 for p in parts if p.isdigit()) >= 3:
            score += SCORE_WEIGHTS["ip_address"]; reasons.append("Raw IP domain")
        if domain.count(".") >= 3:
            score += SCORE_WEIGHTS["long_subdomain"]; reasons.append("Long subdomain chain")
        if domain.count("-") >= 3:
            score += SCORE_WEIGHTS["excessive_hyphens"]; reasons.append("Excessive hyphens")
        if SENSITIVE_PARAMS & params:
            score += SCORE_WEIGHTS["query_sensitive"]; reasons.append("Sensitive params in URL")

        score = min(score, 100)
        return {
            "url":        url,
            "score":      score,
            "risk":       self._classify(score),
            "reasons":    reasons,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "tags":       [],
            "enrichment": {},
        }

    def scan(self, url: str, force: bool = False) -> dict:
        """
        Scans a URL. Returns cached result if already scanned.

        Args:
            url   : The URL to scan.
            force : If True, rescan even if already in the database.

        Returns:
            dict: Scan result (from DB cache or fresh scan).
        """
        url = url.strip()

        # Check database first — avoids redundant network calls
        if not force:
            cached = self.db.get(url)
            if cached:
                print(f"  [cache] {url[:50]}  ({cached['risk']})")
                return cached

        # Fresh scan
        result = self._local_scan(url)

        # Persist immediately
        self.db.add(result)
        return result

    def scan_many(self, urls: list, force: bool = False) -> list:
        """Scans a list of URLs, skipping already-known ones by default."""
        return [self.scan(url, force=force) for url in urls if url.strip()]

    def scan_file(self, filepath: str, force: bool = False) -> list:
        """Reads URLs from a text file and scans each one."""
        results = []
        try:
            lines = Path(filepath).read_text(encoding="utf-8").splitlines()
            urls  = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            results = self.scan_many(urls, force=force)
            print(f"  Scanned {len(results)} URLs from '{filepath}'")
        except FileNotFoundError:
            print(f"  ERROR: File not found: '{filepath}'")
        return results

    def tag(self, url: str, *tags: str) -> bool:
        """
        Adds tags to an existing scan result.
        Tags are useful for grouping: "confirmed", "false-positive", etc.

        Args:
            url  : The URL to tag.
            *tags: One or more tag strings.

        Returns:
            bool: True if found and updated.
        """
        result = self.db.get(url)
        if not result:
            return False
        existing = set(result.get("tags", []))
        existing.update(tags)
        return self.db.update(url, {"tags": sorted(existing)})

    def note(self, url: str, text: str) -> bool:
        """Adds a text note to a scan result."""
        return self.db.update(url, {"notes": text, "reviewed": True})

    def report(self) -> None:
        """Prints a formatted summary to the terminal."""
        s = self.db.stats()
        if s["total"] == 0:
            print("  No scans yet.")
            return

        w = 58
        print("=" * w)
        print(f"  PERSISTENT DETECTOR — DATABASE REPORT")
        print("=" * w)
        print(f"  File         : {s['db_file']}")
        print(f"  Size         : {s['db_size_kb']} KB")
        print(f"  Last updated : {s['last_updated'][:19]}")
        print(f"  Total scans  : {s['total']}")
        print(f"  Avg score    : {s['avg_score']}/100")
        print("-" * w)
        icons = {"SAFE":"v","LOW RISK":"o","SUSPICIOUS":"!","PHISHING":"X"}
        for label in ("SAFE","LOW RISK","SUSPICIOUS","PHISHING"):
            key = label.lower().replace(" ","_")
            print(f"  {icons[label]}  {label:<12}: {s.get(key,0)}")
        print("=" * w)
        phishing = self.db.search(risk="PHISHING")
        if phishing:
            print(f"\n  PHISHING URLS ({len(phishing)}):")
            for r in phishing[:5]:
                print(f"    {r['score']:>3}/100  {r['url']}")
                for reason in r.get("reasons",[]):
                    print(f"            - {reason}")
        print()

    def __len__(self) -> int:
        return len(self.db)

    def __str__(self) -> str:
        return f"PersistentDetector | db='{self.db.filepath}' | {len(self)} scans"

print("=== LESSON 10: JSON Lines (JSONL) for Large Datasets ===\n")

JSONL_FILE = Path("scan_stream.jsonl")

def append_jsonl(result: dict, filepath: Path) -> None:
    """
    Appends a single result as one line to a JSONL file.
    O(1) write — does not read or rewrite the file.

    Args:
        result  : Scan result dict.
        filepath: Path to the .jsonl file.
    """
    line = json.dumps(result, ensure_ascii=False)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read_jsonl(filepath: Path) -> list:
    """
    Reads all lines from a JSONL file into a list.
    Use iter_jsonl() instead for large files.

    Args:
        filepath: Path to the .jsonl file.

    Returns:
        list: All parsed result dicts.
    """
    results = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass   # skip corrupt lines
    except FileNotFoundError:
        pass
    return results


def iter_jsonl(filepath: Path):
    """
    Generator: yields one result at a time from a JSONL file.
    Memory-efficient for very large files — never loads all at once.

    Usage:
        for result in iter_jsonl("huge.jsonl"):
            if result["risk"] == "PHISHING":
                print(result["url"])
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        return


def jsonl_stats(filepath: Path) -> dict:
    """
    Computes stats by streaming a JSONL file line by line.
    Memory usage = O(1) regardless of file size.
    """
    total = safe = low = sus = phi = score_sum = 0
    for result in iter_jsonl(filepath):
        total += 1
        risk   = result.get("risk", "")
        score  = result.get("score", 0)
        score_sum += score
        if risk == "SAFE":       safe += 1
        elif risk == "LOW RISK": low  += 1
        elif risk == "SUSPICIOUS": sus += 1
        elif risk == "PHISHING": phi  += 1

    return {
        "total": total, "safe": safe, "low_risk": low,
        "suspicious": sus, "phishing": phi,
        "avg_score": round(score_sum / total, 1) if total else 0,
    }


# Demo JSONL
jsonl_results = [
    {"url":"https://google.com",        "score":0,  "risk":"SAFE",       "reasons":[]},
    {"url":"http://paypa1.xyz/verify",  "score":85, "risk":"PHISHING",   "reasons":["Fake brand"]},
    {"url":"http://free-prize.tk",      "score":40, "risk":"SUSPICIOUS",  "reasons":["Bad TLD"]},
    {"url":"https://github.com",        "score":0,  "risk":"SAFE",       "reasons":[]},
    {"url":"http://micros0ft-update.tk","score":80, "risk":"PHISHING",   "reasons":["Fake brand","Bad TLD"]},
]

# Append line by line (simulates streaming scan results)
if JSONL_FILE.exists():
    JSONL_FILE.unlink()

for r in jsonl_results:
    append_jsonl(r, JSONL_FILE)

print(f"  Appended {len(jsonl_results)} results to {JSONL_FILE}  ({JSONL_FILE.stat().st_size} bytes)")
print(f"  File contents (first 3 lines):")
with open(JSONL_FILE) as f:
    for i, line in enumerate(f):
        if i >= 3: break
        print(f"    {line.rstrip()[:80]}")

print()
stats = jsonl_stats(JSONL_FILE)
print("  jsonl_stats() — streamed, O(1) memory:")
for k, v in stats.items():
    print(f"    {k:<12}: {v}")
print()
print("  iter_jsonl() — only PHISHING:")
for r in iter_jsonl(JSONL_FILE):
    if r["risk"] == "PHISHING":
        print(f"    {r['score']}/100  {r['url']}")
print()


# ================================================================
# DEMO — Full run
# ================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("  DAY 9 — JSON & Data Persistence — Full Demo")
    print("=" * 60)
    print()

    # Create the persistent detector
    detector = PersistentDetector("phish_history.json")
    print(f"  {detector}\n")

    # Scan a batch of URLs
    urls_to_scan = [
        "https://www.google.com/search?q=python",
        "https://github.com/user/phishing-detector",
        "http://paypa1.secure-login.xyz/verify",
        "http://192.168.1.1/admin/login",
        "http://free-prize.win/claim?ssn=123",
        "http://micros0ft-update.tk/download",
        "https://youtube.com/watch?v=abc123",
        "http://my-secure-bank-login.com/confirm?password=abc",
        "https://amazon.com/products?id=999",
        "http://tw1tter-login.xyz?pwd=abc",
    ]

    print(f"  Scanning {len(urls_to_scan)} URLs...\n")
    results = detector.scan_many(urls_to_scan)

    # Print results table
    print(f"  {'RISK':<12} {'SCORE':>5}  URL")
    print(f"  {'-'*56}")
    icons = {"SAFE":"v","LOW RISK":"o","SUSPICIOUS":"!","PHISHING":"X"}
    for r in sorted(results, key=lambda x: x["score"], reverse=True):
        icon = icons.get(r["risk"], "?")
        bar  = "X" * (r["score"]//10) + "." * (10 - r["score"]//10)
        print(f"  {icon} [{bar}] {r['score']:>3}/100  {r['url'][:42]}")

    print()

    # Full report
    detector.report()

    # Tag some results
    detector.tag("http://paypa1.secure-login.xyz/verify", "confirmed", "high-priority")
    print("\ndb.search(tag='confirmed'):")
    for r in detector.db.search(tag="confirmed"):
     print(f"  {r['score']:>3}/100  {r['url']}  tags={r['tags']}")
    detector.note("http://free-prize.win/claim?ssn=123", "Reported to abuse@example.com")

    # Search the database
    print("  db.search(risk='PHISHING'):")
    phishing = detector.db.search(risk="PHISHING")
    for r in phishing:
        tags = f"  tags={r.get('tags')}" if r.get("tags") else ""
        print(f"    {r['score']:>3}/100  {r['url'][:45]}{tags}")

    print()
    print("  db.search(min_score=30, keyword='xyz'):")
    filtered = detector.db.search(min_score=30, keyword="xyz")
    for r in filtered:
        print(f"    {r['score']:>3}/100  {r['url'][:50]}")

    print()

    print("\nDeduplicating database...")
    removed = detector.db.deduplicate()
    print(f"Removed {removed} duplicate records.")

    # Export
    detector.db.export_csv("day9_report.csv")
    detector.db.export_html("day9_report.html")
    detector.db.export_jsonl("day9_report.jsonl")

    # Backup
    detector.db.backup("backups")

    # Demonstrate rescanning is avoided
    print("\n  Rescanning same URLs (should use cache):")
    detector.scan("http://paypa1.secure-login.xyz/verify")
    detector.scan("https://google.com/search?q=python")
    detector.scan("http://example.com/login?ref=1")
    detector.scan("http://example.com/login?ref=2")

    # Demonstrate rescanning is avoided
    print("\n  Rescanning same URLs (should use cache):")
    detector.scan("http://paypa1.secure-login.xyz/verify")
    detector.scan("https://google.com/search?q=python")
    detector.scan("http://example.com/login?ref=1")
    detector.scan("http://example.com/login?ref=2")


   # Force rescan (bypasses cache)
    print("\n  Force rescan (bypasses cache):")
    fresh = detector.scan(
    "http://paypa1.secure-login.xyz/verify",
    force=True
)
    print(f"    Fresh result: {fresh['score']}/100  {fresh['risk']}")


# Test deduplication
    print("\nDeduplicating database...")
    removed = detector.db.deduplicate()
    print(f"Removed {removed} duplicate records.")