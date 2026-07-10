import os
import sys
import json
import csv
import logging
import argparse
import io
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from textwrap import dedent

VERSION = "2.0.0"

SCORE_WEIGHTS = {
    "no_https": 15, "bad_tld": 25, "fake_brand": 30,
    "suspicious_path": 10, "ip_address": 20,
    "long_subdomain": 10, "excessive_hyphens": 15, "query_sensitive": 30,
}
BAD_TLDS = (".xyz",".tk",".ml",".win",".top",".click",".gq",".cf",".pw",".buzz",".loan",".work")
FAKE_BRANDS = ("paypa1","amaz0n","g00gle","micros0ft","app1e","faceb00k","netfl1x","tw1tter","linkedln")
SUSPICIOUS_PATHS = ("verify","login","update","confirm","secure","validate","account","suspend","signin","billing")
SENSITIVE_PARAMS = frozenset({"ssn","password","passwd","pwd","social_security","creditcard","cvv","pin","dob"})
WHITELISTED_DOMAINS = frozenset({"google.com","github.com","youtube.com","amazon.com","microsoft.com",
                                   "apple.com","twitter.com","linkedin.com","stackoverflow.com","python.org"})
URGENCY_PHRASES = ("act now","immediate action","verify your account","your account will be suspended",
                   "click here immediately","you have won","claim your prize","unusual activity detected",
                   "wire transfer","gift card","bitcoin payment","confirm your identity")

REPORT_WIDTH = 60

print("=== LESSON 1: ANSI Color Codes ===\n")

class Color:
    """
    ANSI color code constants for terminal output.
    Usage: print(Color.RED + "text" + Color.RESET)
    Or:    print(Color.red("text"))
    """
    # Reset
    RESET     = "\033[0m"
    # Styles
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"
    # Foreground colors
    BLACK     = "\033[30m"
    RED       = "\033[31m"
    GREEN     = "\033[32m"
    YELLOW    = "\033[33m"
    BLUE      = "\033[34m"
    MAGENTA   = "\033[35m"
    CYAN      = "\033[36m"
    WHITE     = "\033[37m"
    # Bright foreground
    BRIGHT_RED    = "\033[91m"
    BRIGHT_GREEN  = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_CYAN   = "\033[96m"
    BRIGHT_WHITE  = "\033[97m"

    # Detect if the terminal supports color
    # os.isatty(1) checks if stdout is a real terminal (not piped to a file)
    SUPPORTED = os.isatty(sys.stdout.fileno()) if hasattr(sys.stdout, 'fileno') else False

    @classmethod
    def colorize(cls, text: str, *codes: str) -> str:
        """
        Wraps text in ANSI codes if color is supported.
        If stdout is piped (to a file or another program), strips color.

        Args:
            text  : The string to colorize.
            *codes: One or more ANSI code strings to apply.

        Example:
            Color.colorize("hello", Color.BOLD, Color.RED)
        """
        if not cls.SUPPORTED:
            return text    # no color if piped or unsupported terminal
        return "".join(codes) + text + cls.RESET

    # Convenience methods -- one per risk level + common uses
    @classmethod
    def safe(cls, text):       return cls.colorize(text, cls.BRIGHT_GREEN)
    @classmethod
    def low(cls, text):        return cls.colorize(text, cls.GREEN)
    @classmethod
    def suspicious(cls, text): return cls.colorize(text, cls.BRIGHT_YELLOW)
    @classmethod
    def phishing(cls, text):   return cls.colorize(text, cls.BRIGHT_RED, cls.BOLD)
    @classmethod
    def header(cls, text):     return cls.colorize(text, cls.BOLD, cls.BRIGHT_CYAN)
    @classmethod
    def dim(cls, text):        return cls.colorize(text, cls.DIM)
    @classmethod
    def bold(cls, text):       return cls.colorize(text, cls.BOLD)


def colorize_risk(risk: str, text: str = None) -> str:
    """Returns the risk label (or custom text) colored by risk level."""
    target = text if text is not None else risk
    return {
        "SAFE":       Color.safe(target),
        "LOW RISK":   Color.low(target),
        "SUSPICIOUS": Color.suspicious(target),
        "PHISHING":   Color.phishing(target),
    }.get(risk, target)


# Show color examples
print("  Risk level colors:")
for risk in ("SAFE", "LOW RISK", "SUSPICIOUS", "PHISHING"):
    print(f"    {colorize_risk(risk, f'  {risk:<12}  ')}")
print()
print("  Other styles:")
print(f"    {Color.bold('Bold text')}")
print(f"    {Color.dim('Dim text')}")
print(f"    {Color.header('Header text')}")
print(f"    {Color.colorize('Bold + underline', Color.BOLD, Color.UNDERLINE)}")
print()

def _classify(score):
    if score == 0:   return "SAFE"
    if score <= 30:  return "LOW RISK"
    if score <= 60:  return "SUSPICIOUS"
    return "PHISHING"

def _score_bar(score, width=10):
    filled = round(score / 100 * width)
    if score == 0:   char = Color.colorize("█", Color.BRIGHT_GREEN)
    elif score <= 30: char = Color.colorize("█", Color.GREEN)
    elif score <= 60: char = Color.colorize("█", Color.BRIGHT_YELLOW)
    else:             char = Color.colorize("█", Color.BRIGHT_RED)
    empty = Color.dim("░")
    return char * filled + empty * (width - filled)

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _truncate(text, max_len=50):
    return text if len(text) <= max_len else text[:max_len-1] + "~"

def _is_ip(domain):
    parts = domain.split(":")[0].split(".")
    return sum(1 for p in parts if p.isdigit()) >= 3

def _extract_params(query):
    if not query: return set()
    return {p.split("=")[0].lower() for p in query.split("&") if p}

class PhishingDetector:
    version = VERSION
    _instance_count = 0

    def __init__(self, name="PhishingDetector"):
        self.name = name
        self.history = []
        self.created = _now()
        self.weights = dict(SCORE_WEIGHTS)
        self.bad_tlds = list(BAD_TLDS)
        self.fake_brands = list(FAKE_BRANDS)
        self.suspicious_paths = list(SUSPICIOUS_PATHS)
        self.sensitive_params = set(SENSITIVE_PARAMS)
        self.whitelist = set(WHITELISTED_DOMAINS)
        PhishingDetector._instance_count += 1

    def scan(self, url):
        url = url.strip()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        params = _extract_params(query)
        base   = ".".join(domain.split(".")[-2:])
        if base in self.whitelist:
            r = {"url":url,"score":0,"risk":"SAFE","reasons":["Trusted whitelist domain"],"scanned_at":_now()}
            self.history.append(r); return r
        score = 0; reasons = []
        if parsed.scheme != "https":
            score += self.weights["no_https"]; reasons.append("Uses HTTP instead of HTTPS")
        for t in self.bad_tlds:
            if domain.endswith(t):
                score += self.weights["bad_tld"]; reasons.append(f"High-risk TLD: {t}"); break
        for b in self.fake_brands:
            if b in domain:
                score += self.weights["fake_brand"]; reasons.append(f"Impersonates brand: '{b}'"); break
        for w in self.suspicious_paths:
            if w in path:
                score += self.weights["suspicious_path"]; reasons.append(f"Suspicious path: /{w}"); break
        if _is_ip(domain):
            score += self.weights["ip_address"]; reasons.append("Raw IP address as domain")
        if domain.count(".") >= 3:
            score += self.weights["long_subdomain"]; reasons.append(f"Long subdomain chain ({domain.count('.')} dots)")
        if domain.count("-") >= 3:
            score += self.weights["excessive_hyphens"]; reasons.append(f"Excessive hyphens ({domain.count('-')})")
        if self.sensitive_params & params:
            score += self.weights["query_sensitive"]; reasons.append("Sensitive parameters in URL")
        score = min(score, 100)
        r = {"url":url,"score":score,"risk":_classify(score),"reasons":reasons,"scanned_at":_now()}
        self.history.append(r); return r

    def scan_many(self, urls):
        return [self.scan(u) for u in urls if u.strip()]

    def scan_file(self, filepath):
     batch = []

     try:
        with open(filepath) as f:
            urls = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

        total = len(urls)

        for i, url in enumerate(urls, start=1):
            print(f"Scanning URL {i}/{total}...", end="\r")
            batch.append(self.scan(url))

        print(" " * 40, end="\r")
        print(f"Scanned {total} URLs successfully.")

     except FileNotFoundError:
        print(Color.phishing(f"ERROR: File not found: '{filepath}'"))

     return batch

    def stats(self):
        if not self.history: return {"total": 0}
        total = len(self.history)
        return {
            "total": total,
            "safe": sum(1 for r in self.history if r["risk"]=="SAFE"),
            "low_risk": sum(1 for r in self.history if r["risk"]=="LOW RISK"),
            "suspicious": sum(1 for r in self.history if r["risk"]=="SUSPICIOUS"),
            "phishing": sum(1 for r in self.history if r["risk"]=="PHISHING"),
            "avg_score": round(sum(r["score"] for r in self.history)/total, 1),
            "highest": max(self.history, key=lambda r: r["score"]),
            "lowest":  min(self.history, key=lambda r: r["score"]),
        }

    def top(self, n=3):
        return sorted(self.history, key=lambda r: r["score"], reverse=True)[:n]

    def search(self, keyword):
        return [r for r in self.history if keyword.lower() in r["url"].lower()]

    def add_bad_tld(self, tld):
        tld = tld if tld.startswith(".") else "."+tld
        self.bad_tlds.append(tld)

    def trust_domain(self, domain):
        self.whitelist.add(domain.lower())

    @property
    def scan_count(self): return len(self.history)

    @property
    def phishing_count(self): return sum(1 for r in self.history if r["risk"]=="PHISHING")

    def __len__(self): return len(self.history)
    def __str__(self): return f"PhishingDetector '{self.name}' | {self.scan_count} scans"
    def __contains__(self, url): return any(r["url"]==url for r in self.history)

class EmailDetector(PhishingDetector):
    """
    Extends PhishingDetector to scan email subjects and bodies.
    """

    def scan_email(self, subject: str, body: str):
        text = f"{subject} {body}"

        score = 0
        reasons = []

        suspicious_words = [
            "urgent",
            "click",
            "verify",
            "password",
            "account",
            "login",
            "bank",
            "free",
            "winner",
        ]

        for word in suspicious_words:
            if word.lower() in text.lower():
                score += 10
                reasons.append(f"Suspicious word: {word}")

        score = min(score, 100)

        if score >= 70:
            risk = "PHISHING"
        elif score >= 40:
            risk = "SUSPICIOUS"
        elif score >= 20:
            risk = "LOW RISK"
        else:
            risk = "SAFE"

        return {
            "url": "(email)",
            "score": score,
            "risk": risk,
            "reasons": reasons,
            "subject": subject,
        }
    
print("=== LESSON 2: Output Formatters ===\n")

def format_table(results: list, verbose: bool = False) -> str:
    """
    Formats scan results as a human-readable table with color.

    Args:
        results  : List of scan result dicts.
        verbose  : If True, include reason lines under each URL.

    Returns:
        str: Formatted table string ready to print.
    """
    if not results:
        return Color.dim("  No results.\n")

    lines = []
    lines.append(Color.header(f"  {'RISK':<12} {'SCORE':>5}  {'BAR':<12}  URL"))
    lines.append(Color.dim("  " + "-" * (REPORT_WIDTH - 2)))

    for r in results:
        risk_col  = colorize_risk(r["risk"], f"{r['risk']:<12}")
        score_col = colorize_risk(r["risk"], f"{r['score']:>3}/100")
        bar_col   = _score_bar(r["score"])
        url_col   = Color.dim(_truncate(r["url"], 42))
        lines.append(f"  {risk_col} {score_col}  [{bar_col}]  {url_col}")

        if verbose and r.get("reasons"):
            for reason in r["reasons"]:
                lines.append(Color.dim(f"             • {reason}"))

    return "\n".join(lines) + "\n"


def format_json(results: list, pretty: bool = True) -> str:
    """
    Formats scan results as JSON.

    Args:
        results : List of scan result dicts.
        pretty  : If True, indent with 2 spaces. False = compact one-liner.

    Returns:
        str: JSON string.

    WHY JSON OUTPUT?
        Other programs can consume it:
            python day7_cli.py scan --url http://evil.xyz --format json | jq .
        It's the standard for API responses and inter-process communication.
    """
    indent = 2 if pretty else None
    return json.dumps(results, indent=indent, ensure_ascii=False)


def format_csv(results: list) -> str:
    """
    Formats scan results as CSV (comma-separated values).

    Args:
        results : List of scan result dicts.

    Returns:
        str: CSV string with header row.

    WHY CSV OUTPUT?
        Anyone can open it in Excel or Google Sheets.
        Easy to import into databases or BI tools.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    # Header row
    writer.writerow(["url", "score", "risk", "reasons", "scanned_at"])
    for r in results:
        writer.writerow([
            r["url"],
            r["score"],
            r["risk"],
            " | ".join(r.get("reasons", [])),
            r.get("scanned_at", ""),
        ])
    return output.getvalue()


def format_summary(stats: dict) -> str:
    """
    Formats the stats dict as a colored summary block.

    Args:
        stats: Dictionary from detector.stats().

    Returns:
        str: Formatted summary string.
    """
    if stats.get("total", 0) == 0:
        return Color.dim("  No scans yet.\n")

    lines = []
    lines.append(Color.header("=" * REPORT_WIDTH))
    lines.append(Color.header(f"  SCAN SUMMARY"))
    lines.append(Color.header("=" * REPORT_WIDTH))
    lines.append(f"  Total scanned  : {Color.bold(str(stats['total']))}")
    lines.append(f"  Average score  : {Color.bold(str(stats['avg_score']) + '/100')}")
    lines.append(f"  Highest score  : {colorize_risk(stats['highest']['risk'], str(stats['highest']['score']) + '/100')}")
    lines.append("-" * REPORT_WIDTH)
    lines.append(f"  {Color.safe('✓  SAFE        : ' + str(stats['safe']))}")
    lines.append(f"  {Color.low('◎  LOW RISK    : ' + str(stats['low_risk']))}")
    lines.append(f"  {Color.suspicious('⚠  SUSPICIOUS  : ' + str(stats['suspicious']))}")
    lines.append(f"  {Color.phishing('✕  PHISHING    : ' + str(stats['phishing']))}")
    lines.append(Color.header("=" * REPORT_WIDTH))
    return "\n".join(lines) + "\n"


# Quick demo of formatters
_demo_results = [
    {"url":"https://google.com",        "score":0,  "risk":"SAFE",       "reasons":["Trusted domain"],                 "scanned_at":_now()},
    {"url":"http://free-offers.tk",     "score":40, "risk":"SUSPICIOUS",  "reasons":["HTTP","High-risk TLD: .tk"],     "scanned_at":_now()},
    {"url":"http://paypa1.secure.xyz",  "score":85, "risk":"PHISHING",    "reasons":["Fake brand","Bad TLD","HTTP"],   "scanned_at":_now()},
]

print("format_table() output:")
print(format_table(_demo_results))

print("format_json() output (first result only):")
print(json.dumps(_demo_results[0], indent=2))
print()

print("format_csv() output:")
print(format_csv(_demo_results))

print("=== LESSON 3: Subcommands with add_subparsers() ===\n")

def build_parser() -> argparse.ArgumentParser:
    """
    Builds the full argument parser with subcommands.

    Subcommands:
        scan        scan a URL, file, or stdin
        interactive launch an interactive REPL session
        config      show current configuration
        report      print/export the last scan results

    Returns:
        argparse.ArgumentParser: Fully configured parser.
    """
    # ── Root parser ───────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog        = "phish",
        description = Color.header("PhishingDetector v" + VERSION + " — URL & Email Phishing Scanner"),
        epilog      = dedent("""\
            Examples:
              python day7_cli.py scan --url http://paypa1.xyz
              python day7_cli.py scan --file urls.txt --format json
              python day7_cli.py scan --url http://evil.xyz --verbose
              echo "http://evil.xyz" | python day7_cli.py scan --stdin
              python day7_cli.py interactive
              python day7_cli.py config --show-weights
        """),
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    # Global flags (available to ALL subcommands)
    parser.add_argument(
        "--version", "-V",
        action  = "version",
        version = f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--no-color",
        action  = "store_true",
        default = False,
        help    = "Disable colored output (useful when piping).",
    )
    parser.add_argument(
        "--log-level",
        choices = ["DEBUG", "INFO", "WARNING", "ERROR"],
        default = "INFO",
        help    = "Set logging verbosity. (default: INFO)",
        metavar = "LEVEL",
    )

    # ── Subparsers ────────────────────────────────────────────────────
    # dest="command" means args.command will hold the chosen subcommand name
    subparsers = parser.add_subparsers(
        dest        = "command",
        title       = "subcommands",
        description = "Choose a subcommand to run:",
        metavar     = "{scan, interactive, config, report}",
    )

    # ── Subcommand: scan ──────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help        = "Scan URLs for phishing indicators.",
        description = "Scan one URL, a file of URLs, or URLs from stdin.",
        epilog      = "Example: python day7_cli.py scan --url http://paypa1.xyz --verbose",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    # Input source -- mutually exclusive (can only use one at a time)
    # argparse enforces this automatically and shows a clear error
    input_group = scan_parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        "--url", "-u",
        type    = str,
        help    = "A single URL to scan.",
        metavar = "URL",
    )
    input_group.add_argument(
        "--file", "-f",
        type    = str,
        help    = "Path to a text file of URLs (one per line).",
        metavar = "FILE",
    )
    input_group.add_argument(
        "--stdin",
        action  = "store_true",
        default = False,
        help    = "Read URLs from stdin (one per line). Enables piping.",
    )

    # Output options
    scan_parser.add_argument(
        "--format",
        choices = ["table", "json", "csv"],
        default = "table",
        help    = "Output format: table (default), json, or csv.",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type    = str,
        default = None,
        help    = "Write results to this file instead of stdout.",
        metavar = "FILE",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action  = "store_true",
        default = False,
        help    = "Show reasons for each flagged URL.",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action  = "store_true",
        default = False,
        help    = "Only show the summary, no per-URL output.",
    )
    scan_parser.add_argument(
        "--top", "-t",
        type    = int,
        default = None,
        help    = "Show only the N most dangerous results.",
        metavar = "N",
    )
    scan_parser.add_argument(
        "--min-score",
        type    = int,
        default = 0,
        help    = "Only show results with score >= N. (default: 0)",
        metavar = "N",
    )
    scan_parser.add_argument(
    "--search",
    type=str,
    default=None,
    help="Only show URLs containing the given keyword.",
    metavar="KEYWORD",
    )
    # Customisation
    scan_parser.add_argument(
        "--whitelist",
        nargs   = "+",          # one or more values: --whitelist a.com b.com
        default = [],
        help    = "Trust these domains (skip all checks for them).",
        metavar = "DOMAIN",
    )
    scan_parser.add_argument(
        "--add-tld",
        nargs   = "+",
        default = [],
        help    = "Add extra bad TLDs to check. e.g. --add-tld .scam .phish",
        metavar = "TLD",
    )

    # ── Subcommand: interactive ───────────────────────────────────────
    interactive_parser = subparsers.add_parser(
        "interactive",
        help        = "Launch an interactive scan session (REPL).",
        description = "Enter URLs one at a time and see results instantly.",
    )
    interactive_parser.add_argument(
        "--format",
        choices = ["table", "json"],
        default = "table",
        help    = "Output format per scan. (default: table)",
    )
    interactive_parser.add_argument(
        "--history",
        action  = "store_true",
        default = False,
        help    = "Show full scan history when you quit.",
    )

    # ── Subcommand: config ────────────────────────────────────────────
    config_parser = subparsers.add_parser(
        "config",
        help        = "Show the current detector configuration.",
        description = "Print all weights, blocklists, and settings.",
    )
    config_parser.add_argument(
    "--save-config",
    metavar="FILE",
    help="Save configuration to a JSON file."
    )
    config_parser.add_argument(
        "--show-weights",
        action  = "store_true",
        default = False,
        help    = "Show score weights for each check.",
    )
    config_parser.add_argument(
        "--show-tlds",
        action  = "store_true",
        default = False,
        help    = "List all blocked TLDs.",
    )
    config_parser.add_argument(
        "--show-brands",
        action  = "store_true",
        default = False,
        help    = "List all fake brand patterns.",
    )
    config_parser.add_argument(
        "--show-all",
        action  = "store_true",
        default = False,
        help    = "Show everything.",
    )
    email_parser = subparsers.add_parser(
    "email",
    help="Scan an email for phishing indicators.",
    description="Analyze an email subject and body."
    )
    email_parser.add_argument(
    "--subject",
    required=True,
    help="Email subject."
    )
    email_parser.add_argument(
    "--body",
    required=True,
    help="Email body."
    )
    # ── Subcommand: report ────────────────────────────────────────────
    report_parser = subparsers.add_parser(
        "report",
        help        = "Print a summary report from a saved JSON results file.",
        description = "Load a JSON results file and print a formatted report.",
    )
    report_parser.add_argument(
        "input_file",
        type    = str,
        help    = "Path to a JSON results file (saved with --format json --output file.json).",
        metavar = "FILE",
    )
    report_parser.add_argument(
        "--format",
        choices = ["table", "csv"],
        default = "table",
        help    = "Output format for the report. (default: table)",
    )
    return parser


# Show that the parser was built correctly
_parser = build_parser()
print("Parser built. Subcommands registered:")
for name, sub in _parser._subparsers._group_actions[0].choices.items():
    print(f"  {Color.bold(name):<25} {sub.description or ''}")
print()
print("  Run:  python day7_cli.py --help  to see the full help text.")
print()

print("=== LESSON 4: stdin Piping ===\n")

def read_stdin_urls() -> list:
    """
    Reads URLs from stdin, one per line.
    Skips empty lines and comment lines starting with #.

    Used when: python day7_cli.py scan --stdin
    Or piped:  cat urls.txt | python day7_cli.py scan --stdin

    Returns:
        list: List of URL strings.
    """
    urls = []
    print(Color.dim("  Reading from stdin (Ctrl+D when done)..."))
    try:
        for line in sys.stdin:
            url = line.strip()
            if url and not url.startswith("#"):
                urls.append(url)
    except KeyboardInterrupt:
        print()   # newline after ^C
    print(Color.dim(f"  Read {len(urls)} URLs from stdin."))
    return urls


print("  sys.stdin.isatty() =", sys.stdin.isatty())
if sys.stdin.isatty():
    print("  -> Running interactively (keyboard input)")
    print("  -> To pipe: echo 'http://evil.xyz' | python day7_cli.py scan --stdin")
else:
    print("  -> stdin is piped (data coming from another program)")
print()

print("=== LESSON 5: nargs — Multiple Values ===\n")

# Demonstrate with a mini parser
_nargs_demo = argparse.ArgumentParser(prog="nargs-demo", add_help=False)
_nargs_demo.add_argument("--whitelist", nargs="+", default=[])
_nargs_demo.add_argument("--add-tld",   nargs="+", default=[])
_nargs_demo.add_argument("--top",       type=int,  default=3)

# Simulate different command-line inputs
test_inputs = [
    ["--whitelist", "google.com"],
    ["--whitelist", "google.com", "github.com", "amazon.com"],
    ["--add-tld", ".scam", ".phish", "--top", "5"],
    [],
]
print("  nargs='+' examples:")
for inp in test_inputs:
    parsed = _nargs_demo.parse_args(inp)
    print(f"    Input: {inp or ['(nothing)']}")
    print(f"    Result: whitelist={parsed.whitelist}  add_tld={parsed.add_tld}  top={parsed.top}")
    print()

print("=== LESSON 6: choices ===\n")

_choices_demo = argparse.ArgumentParser(prog="choices-demo", add_help=False)
_choices_demo.add_argument(
    "--format",
    choices = ["table", "json", "csv"],
    default = "table",
)

print("  choices=['table','json','csv'] examples:")
for val in ["table", "json", "csv", "excel"]:
    try:
        parsed = _choices_demo.parse_args(["--format", val])
        print(f"    --format {val:<8} -> OK (args.format = '{parsed.format}')")
    except SystemExit:
        print(f"    --format {val:<8} -> REJECTED (not in choices)")
print()

print("=== LESSON 7: Interactive REPL ===\n")

REPL_HELP = dedent("""\
  Available commands:
    <url>           Scan a URL  (e.g. http://paypa1.xyz/verify)
    history         Show all scans from this session
    top [N]         Show N most dangerous (default: 3)
    stats           Show summary statistics
    clear           Reset scan history
    whitelist <dom> Trust a domain (skip all checks)
    export json     Print all results as JSON
    export csv      Print all results as CSV
    help            Show this help message
    quit / exit     Exit the REPL
""")

def run_repl(detector: PhishingDetector, fmt: str = "table", show_history: bool = False):
    """
    Runs an interactive REPL session.
    Keeps scanning until the user types 'quit' or presses Ctrl+C/D.

    Args:
        detector     : PhishingDetector instance to use.
        fmt          : Output format ('table' or 'json').
        show_history : If True, print history on quit.
    """
    print(Color.header("=" * REPORT_WIDTH))
    print(Color.header(f"  PhishingDetector v{VERSION} -- Interactive Mode"))
    print(Color.header("=" * REPORT_WIDTH))
    print(Color.dim("  Type a URL to scan, or 'help' for commands. 'quit' to exit.\n"))

    session_count = 0
    session_results = []

    while True:
        # ── Read ──────────────────────────────────────────────────────
        try:
            raw = input(Color.bold("  phish> ")).strip()
        except (EOFError, KeyboardInterrupt):
            # EOFError: user pressed Ctrl+D (end of stdin)
            # KeyboardInterrupt: user pressed Ctrl+C
            print(f"\n{Color.dim('  Session ended.')}")
            break

        if not raw:
            continue   # empty input -- just show prompt again

        cmd   = raw.lower()
        parts = raw.split()

        # ── Eval ──────────────────────────────────────────────────────

        if cmd in ("quit", "exit"):
            filename = f"session_{datetime.now():%Y%m%d_%H%M%S}.json"

            with open(filename, "w", encoding="utf-8") as f:
              json.dump(session_results, f, indent=4)

            print(Color.safe(f"Session saved to '{filename}'"))
            break
        # Help
        elif cmd == "help":
            print(Color.dim(REPL_HELP))

        # Stats
        elif cmd == "stats":
            s = detector.stats()
            print(format_summary(s))

        # History
        elif cmd == "history":
            if not detector.history:
                print(Color.dim("  No scans yet.\n"))
            else:
                print(format_table(detector.history, verbose=False))

        # Top N
        elif parts[0] == "top":
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
            top = detector.top(n)
            if not top:
                print(Color.dim("  No results yet.\n"))
            else:
                print(Color.bold(f"\n  Top {n} most dangerous:\n"))
                print(format_table(top, verbose=True))

        # Clear history
        elif cmd == "clear":
            count = len(detector.history)
            detector.history = []
            session_count = 0
            print(Color.dim(f"  Cleared {count} results.\n"))

        # Trust a domain
        elif parts[0] == "whitelist" and len(parts) > 1:
            domain = parts[1].lower()
            detector.trust_domain(domain)
            print(Color.safe(f"  Trusted: {domain}\n"))

        # Export
        elif parts[0] == "export" and len(parts) > 1:
            fmt_exp = parts[1].lower()
            if fmt_exp == "json":
                print(format_json(detector.history))
            elif fmt_exp == "csv":
                print(format_csv(detector.history))
            else:
                print(Color.suspicious(f"  Unknown format '{fmt_exp}'. Use: json, csv\n"))

        # Scan a URL
        elif raw.startswith("http://") or raw.startswith("https://"):
         result = detector.scan(raw)
         session_results.append(result)
         session_count += 1

        # Print result
         if fmt == "json":
          print(format_json([result], pretty=True))
         else:
          print(format_table([result], verbose=True))

        else:
         # Unknown input -- give a helpful message
         print(Color.dim(
           f"  Unknown command: '{raw[:30]}'. "
           f"URLs must start with http:// or https://. "
           f"Type 'help' for commands.\n"
    ))

    # After REPL exits
    if show_history and detector.history:
        print(Color.header("\n  Session history:"))
        print(format_table(detector.history))
        print(format_summary(detector.stats()))


print("  REPL defined. To launch interactively, run:")
print("  python day7_cli.py interactive")
print()

print("=== LESSON 8: Writing Output to Files ===\n")

def write_output(content: str, filepath: str | None) -> None:
    """
    Writes content to a file or stdout.

    If filepath is None, prints to stdout.
    If filepath is given, writes to that file (creates or overwrites).

    Args:
        content  : String content to output.
        filepath : Destination file path, or None for stdout.
    """
    if filepath is None:
        print(content, end="")
        return

    path = Path(filepath)
    # Create parent directories if they don't exist
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(Color.safe(f"  Output saved to '{filepath}' ({path.stat().st_size} bytes)"))


def auto_format(results: list, filepath: str | None, fmt: str, verbose: bool = False) -> str:
    """
    Chooses the right formatter based on --format flag OR file extension.
    File extension takes priority over --format if --output is given.

    Args:
        results  : List of scan result dicts.
        filepath : Output file path (or None for stdout).
        fmt      : Format flag value ('table', 'json', 'csv').
        verbose  : Show reasons in table format.

    Returns:
        str: Formatted content string.
    """
    # Auto-detect format from file extension
    if filepath:
        ext = Path(filepath).suffix.lower()
        if ext == ".json": fmt = "json"
        elif ext == ".csv": fmt = "csv"
        elif ext in (".txt", ".md"): fmt = "table"
        # (fmt stays as-is if extension is unrecognised)

    if fmt == "json":
        return format_json(results)
    elif fmt == "csv":
        return format_csv(results)
    else:
        return format_table(results, verbose=verbose)


# Demo
_test_results = [
    {"url":"http://paypa1.xyz","score":85,"risk":"PHISHING","reasons":["Fake brand","Bad TLD"],"scanned_at":_now()},
    {"url":"https://google.com","score":0,"risk":"SAFE","reasons":["Trusted domain"],"scanned_at":_now()},
]

print("  auto_format() with different formats:")
for fmt_name, fp in [("table", None), ("json", None), ("csv", None)]:
    content = auto_format(_test_results, None, fmt_name)
    lines = content.strip().split("\n")
    print(f"\n  format='{fmt_name}' -> {len(lines)} lines, {len(content)} chars")
    print(f"  First line: {lines[0][:70]}")
print()

print("=== LESSON 9: Subcommand Handlers ===\n")

def handle_scan(args, detector: PhishingDetector) -> int:
    """
    Handler for:  python day7_cli.py scan [options]

    Determines input source, runs scans, formats and outputs results.

    Returns:
        int: Exit code (0=ok, 1=phishing found, 2=usage error).
    """
    # ── Apply customisation from flags ────────────────────────────────
    for domain in (args.whitelist or []):
        detector.trust_domain(domain)
        print(Color.dim(f"  Whitelisted: {domain}"))

    for tld in (args.add_tld or []):
        detector.add_bad_tld(tld)
        print(Color.dim(f"  Added bad TLD: {tld}"))

    # ── Determine input source ────────────────────────────────────────
    results = []

    if args.url:
        # Single URL
        if not args.url.startswith(("http://", "https://")):
            print(Color.phishing(f"  ERROR: URL must start with http:// or https://"))
            return 2
        results = [detector.scan(args.url)]

    elif args.file:
        # File of URLs
        if not Path(args.file).exists():
            print(Color.phishing(f"  ERROR: File not found: '{args.file}'"))
            return 2
        results = detector.scan_file(args.file)

    elif args.stdin:
        # Piped stdin
        urls = read_stdin_urls()
        results = detector.scan_many(urls)

    else:
        # Demo mode
        print(Color.dim("  No input given. Running demo scan...\n"))
        demo_urls = [
            "https://www.google.com/search?q=python",
            "https://github.com/user/repo",
            "http://paypa1.secure-login.xyz/verify",
            "http://192.168.1.1/admin/login",
            "http://free-prize.win/claim?ssn=123",
            "http://micros0ft-update.tk/download",
            "https://youtube.com/watch?v=abc",
            "http://my-secure-bank-login.com/confirm?password=abc",
        ]
        results = detector.scan_many(demo_urls)

    # ── Apply filters ─────────────────────────────────────────────────
    if args.min_score > 0:
        results = [r for r in results if r["score"] >= args.min_score]

    if args.search:
        results = [r for r in results if args.search.lower() in r["url"].lower()]

    if args.top:
        results = sorted(results, key=lambda r: r["score"], reverse=True)[:args.top]

    # ── Format and output ─────────────────────────────────────────────
    if not args.quiet:
        content = auto_format(results, args.output, args.format, verbose=args.verbose)
        write_output(content, args.output)

    # ── Summary ───────────────────────────────────────────────────────
    if not args.quiet or not args.output:
        s = detector.stats()
        if s["total"] > 0:
            print(format_summary(s))

    return 1 if detector.phishing_count > 0 else 0

def handle_email(args, detector):
    """
    Handler for:
        python day7_cli.py email --subject "..." --body "..."
    """
    result = detector.scan_email(
        args.subject,
        args.body
    )

    if args.format == "json":
        print(format_json([result]))
    elif args.format == "csv":
        print(format_csv([result]))
    else:
        print(format_table([result]))

    return 0

def handle_interactive(args, detector: PhishingDetector) -> int:
    """
    Handler for:  python day7_cli.py interactive
    Launches the interactive REPL session.
    """
    run_repl(
        detector     = detector,
        fmt          = args.format,
        show_history = args.history,
    )
    return 0


def handle_config(args, detector: PhishingDetector) -> int:
    """
    Handler for:  python day7_cli.py config [options]
    Prints the current detector configuration.
    """
    show_all = args.show_all

    print(Color.header("=" * REPORT_WIDTH))
    print(Color.header(f"  PhishingDetector v{VERSION} -- Configuration"))
    print(Color.header("=" * REPORT_WIDTH))
    print(f"  Detector name  : {detector.name}")
    print(f"  Created at     : {detector.created}")
    print(f"  Whitelisted    : {len(detector.whitelist)} trusted domains")
    print(f"  Bad TLDs       : {len(detector.bad_tlds)}")
    print(f"  Fake brands    : {len(detector.fake_brands)}")
    print(f"  Sensitive params: {len(detector.sensitive_params)}")
    print()

    if args.show_weights or show_all:
        print(Color.bold("  SCORE WEIGHTS:"))
        for name, weight in sorted(detector.weights.items(), key=lambda x: x[1], reverse=True):
            bar = colorize_risk("PHISHING", "█") * (weight // 5)
            print(f"    {name:<22} {weight:>3} pts  {bar}")
        print()

    if args.show_tlds or show_all:
        print(Color.bold("  BLOCKED TLDs:"))
        print("    " + "  ".join(detector.bad_tlds))
        print()

    if args.show_brands or show_all:
        print(Color.bold("  FAKE BRAND PATTERNS:"))
        for i, brand in enumerate(detector.fake_brands):
            end = "\n" if (i + 1) % 5 == 0 else "  "
            print(f"    {brand}", end=end)
        print()
    if args.save_config:
     config = {
        "weights": detector.weights,
        "bad_tlds": detector.bad_tlds,
        "whitelist": detector.whitelist,
        "fake_brands": detector.fake_brands,
        "sensitive_params": detector.sensitive_params,
    }

    with open(args.save_config, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    print(Color.safe(f"Configuration saved to '{args.save_config}'"))

    return 0


def handle_report(args, detector: PhishingDetector) -> int:
    """
    Handler for:  python day7_cli.py report results.json
    Loads a JSON results file and prints a formatted report.
    """
    if not Path(args.input_file).exists():
        print(Color.phishing(f"  ERROR: File not found: '{args.input_file}'"))
        return 2

    try:
        with open(args.input_file) as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        print(Color.phishing(f"  ERROR: Invalid JSON in '{args.input_file}': {e}"))
        return 1

    if not isinstance(results, list):
        print(Color.phishing("  ERROR: JSON file must contain a list of scan results."))
        return 1

    # Load results into detector so stats() works
    detector.history = results

    content = auto_format(results, None, args.format, verbose=True)
    print(content)
    print(format_summary(detector.stats()))
    return 0


print("  Handlers defined:")
for fn in (handle_scan, handle_interactive, handle_config, handle_report):
    print(f"    {Color.bold(fn.__name__):<30} {fn.__doc__.strip().splitlines()[0]}")
print()

print("=== LESSON 10: Logging for CLI Tools ===\n")

def setup_logging(level_name: str = "INFO") -> logging.Logger:
    """
    Configures logging for a CLI tool.

    Logs go to STDERR so they don't pollute stdout (especially
    important when output is JSON or CSV being piped to another tool).

    Args:
        level_name: One of DEBUG / INFO / WARNING / ERROR.

    Returns:
        logging.Logger: Named logger for this module.
    """
    level = getattr(logging, level_name.upper(), logging.INFO)

    # Minimal format for terminal: just level + message
    handler = logging.StreamHandler(sys.stderr)   # <- stderr, not stdout!
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    return logging.getLogger("phish")


print("  Logging goes to STDERR (not STDOUT) so it doesn't mix with JSON/CSV output.")
print("  Demo: logging to stderr while main output goes to stdout")
print()

def main() -> int:
    """
    Entry point. Parses args, dispatches to the right handler.

    Flow:
        1. Build parser
        2. Parse args
        3. Setup logging
        4. Handle --no-color
        5. Create detector
        6. Dispatch to subcommand handler
        7. Return exit code

    Returns:
        int: Exit code (0=success, 1=phishing found, 2=usage error).
    """
    parser = build_parser()
    args   = parser.parse_args()

    # ── Global setup ──────────────────────────────────────────────────
    logger = setup_logging(args.log_level)

    # Disable color if --no-color flag is set
    if args.no_color:
        Color.SUPPORTED = False

    logger.debug(f"PhishingDetector v{VERSION} starting")
    logger.debug(f"Command: {args.command}")

    # ── No subcommand given -> show help ──────────────────────────────
    if not args.command:
        parser.print_help()
        print()
        print(Color.dim("  Tip: run 'python day7_cli.py scan' for a demo."))
        return 0

    # ── Create detector ───────────────────────────────────────────────
    detector = EmailDetector(name="Day7CLI")

    # ── Dispatch to the right handler ─────────────────────────────────
    handlers = {
        "scan":        handle_scan,
        "interactive": handle_interactive,
        "email":       handle_email,
        "config":      handle_config,
        "report":      handle_report,
    }

    handler = handlers.get(args.command)
    if not handler:
        print(Color.phishing(f"  Unknown command: '{args.command}'"))
        return 2

    # ── Run handler with top-level error protection ───────────────────
    try:
        exit_code = handler(args, detector)
        logger.debug(f"Handler returned exit code: {exit_code}")
        return exit_code

    except KeyboardInterrupt:
        print(f"\n{Color.dim('  Interrupted.')}")
        return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.debug("Full traceback:", exc_info=True)
        return 1

if __name__ == "__main__":

    print("=" * REPORT_WIDTH)
    print(Color.header(f"  DAY 7 -- CLI Tool Deep Dive"))
    print("=" * REPORT_WIDTH)
    print()

    print("  All lessons covered:")
    lessons = [
        ("Lesson 1",  "ANSI color codes -- colored terminal output"),
        ("Lesson 2",  "Output formatters -- table / json / csv"),
        ("Lesson 3",  "Subcommands with add_subparsers()"),
        ("Lesson 4",  "stdin piping -- echo url | python day7_cli.py scan"),
        ("Lesson 5",  "nargs -- multiple values for one argument"),
        ("Lesson 6",  "choices -- restricting allowed values"),
        ("Lesson 7",  "Interactive REPL -- read-eval-print loop"),
        ("Lesson 8",  "Writing output to files -- auto format by extension"),
        ("Lesson 9",  "Subcommand handler functions -- command pattern"),
        ("Lesson 10", "Logging for CLI tools -- stderr vs stdout"),
        ("Lesson 11", "main() -- wiring all subcommands together"),
    ]
    for name, desc in lessons:
        print(f"  {Color.bold(name):<22}  {Color.dim(desc)}")

    print()
    print(Color.header("  Running Demo Scan..."))
    print()

    # Run the full program with demo mode (no --url or --file)
    # We simulate args since we can't call argparse.parse_args() with custom
    # values easily in demo mode -- use Namespace directly
    demo_args = argparse.Namespace(
        command      = "scan",
        url          = None,
        file         = None,
        stdin        = False,
        subject      = None, 
        body         = None,
        format       = "table",
        output       = None,
        verbose      = True,
        quiet        = False,
        top          = None,
        min_score    = 0,
        search       = None,
        whitelist    = [],
        add_tld      = [],
        no_color     = False,
        log_level    = "WARNING",   # suppress INFO logs in demo
    )

    demo_detector = PhishingDetector(name="Day7Demo")
    exit_code     = handle_scan(demo_args, demo_detector)

    print()
    print(Color.header("  Try these commands:"))
    print()
    cmds = [
        ("python day7_cli.py --help",                               "show full help"),
        ("python day7_cli.py scan --help",                          "show scan subcommand help"),
        ("python day7_cli.py scan --url http://paypa1.xyz -v",      "scan one URL, verbose"),
        ("python day7_cli.py scan --file urls.txt --format json",   "scan file, JSON output"),
        ("python day7_cli.py scan --file urls.txt --search paypal", "scan only URLs containing 'paypal'"),
        ("python day7_cli.py scan --url http://evil.xyz -o out.json","save JSON to file"),
        ("python day7_cli.py config --show-all",                    "show all config"),
        ("python day7_cli.py config --save-config my_config.json", "save detector configuration to JSON"),
        ("python day7_cli.py interactive",                          "interactive REPL mode"),
        ("echo http://evil.xyz | python day7_cli.py scan --stdin",  "pipe a URL"),
    ]
    for cmd, desc in cmds:
        print(f"  {Color.bold('$')} {cmd}")
        print(f"    {Color.dim(desc)}")
        print()

    sys.exit(main())