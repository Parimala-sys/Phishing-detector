
import os
import sys
import logging
import argparse
from datetime import datetime

from pathlib import Path
from textwrap import dedent

from datetime import datetime as dt

print("=== LESSON 2: Import Styles ===\n")
print(f"  Style 1: import os          -> os.getcwd() = {os.getcwd()[:40]}...")
print(f"  Style 2: from pathlib import Path -> Path('.').exists() = {Path('.').exists()}")
print(f"  Style 3: from datetime import datetime as dt -> dt.now().year = {dt.now().year}")
print()

print("=== LESSON 3: Importing From the Package ===\n")

SCORE_WEIGHTS = {
    "no_https": 15, "bad_tld": 25, "fake_brand": 30,
    "suspicious_path": 10, "ip_address": 20,
    "long_subdomain": 10, "excessive_hyphens": 15, "query_sensitive": 30,
}
BAD_TLDS = (".xyz",".tk",".ml",".win",".top",".click",".gq",".cf",".pw",".buzz")
FAKE_BRANDS = ("paypa1","amaz0n","g00gle","micros0ft","app1e","faceb00k","netfl1x","tw1tter")
SUSPICIOUS_PATHS = ("verify","login","update","confirm","secure","validate","account","suspend")
SENSITIVE_PARAMS = frozenset({"ssn","password","passwd","pwd","social_security","creditcard","cvv"})
WHITELISTED_DOMAINS = frozenset({"google.com","github.com","youtube.com","amazon.com","facebook.com","microsoft.com"})
URGENCY_PHRASES = ("act now","immediate action","verify your account","your account will be suspended",
                   "click here immediately","you have won","claim your prize","wire transfer","gift card")
VERSION = "1.0.0"
REPORT_WIDTH = 58

from urllib.parse import urlparse

def _classify(score):
    if score == 0:   return "SAFE"
    if score <= 30:  return "LOW RISK"
    if score <= 60:  return "SUSPICIOUS"
    return "PHISHING"

def _score_bar(score, width=10):
    filled = round(score / 100 * width)
    return "X" * filled + "." * (width - filled)

def _risk_icon(risk):
    return {"SAFE":"v","LOW RISK":"o","SUSPICIOUS":"!","PHISHING":"X"}.get(risk,"?")

def _truncate(text, max_len=50):
    return text if len(text) <= max_len else text[:max_len-1] + "~"

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _divider(char="=", width=REPORT_WIDTH):
    return char * width

def _is_ip(domain):
    parts = domain.split(":")[0].split(".")
    return sum(1 for p in parts if p.isdigit()) >= 3

def _extract_params(query):
    if not query: return set()
    return {p.split("=")[0].lower() for p in query.split("&") if p}

class PhishingDetector:
    version = VERSION
    def __init__(self, name="PhishingDetector"):
        self.name = name; self.history = []; self.created = _now()
        self.weights = dict(SCORE_WEIGHTS); self.bad_tlds = list(BAD_TLDS)
        self.fake_brands = list(FAKE_BRANDS); self.suspicious_paths = list(SUSPICIOUS_PATHS)
        self.sensitive_params = set(SENSITIVE_PARAMS); self.whitelist = set(WHITELISTED_DOMAINS)
    def scan(self, url):
        url = url.strip(); parsed = urlparse(url)
        domain = parsed.netloc.lower(); path = parsed.path.lower()
        query = parsed.query.lower(); params = _extract_params(query)
        base = ".".join(domain.split(".")[-2:])
        if base in self.whitelist:
            r = {"url":url,"score":0,"risk":"SAFE","reasons":["Trusted domain"],"scanned_at":_now()}
            self.history.append(r); return r
        score = 0; reasons = []
        if parsed.scheme != "https": score += self.weights["no_https"]; reasons.append("Uses HTTP not HTTPS")
        for t in self.bad_tlds:
            if domain.endswith(t): score += self.weights["bad_tld"]; reasons.append(f"High-risk TLD: {t}"); break
        for b in self.fake_brands:
            if b in domain: score += self.weights["fake_brand"]; reasons.append(f"Fake brand: '{b}'"); break
        for w in self.suspicious_paths:
            if w in path: score += self.weights["suspicious_path"]; reasons.append(f"Suspicious path: /{w}"); break
        if _is_ip(domain): score += self.weights["ip_address"]; reasons.append("Raw IP domain")
        if domain.count(".") >= 3: score += self.weights["long_subdomain"]; reasons.append("Long subdomain")
        if domain.count("-") >= 3: score += self.weights["excessive_hyphens"]; reasons.append("Excessive hyphens")
        if self.sensitive_params & params: score += self.weights["query_sensitive"]; reasons.append("Sensitive params in URL")
        score = min(score, 100)
        r = {"url":url,"score":score,"risk":_classify(score),"reasons":reasons,"scanned_at":_now()}
        self.history.append(r); return r
    def scan_many(self, urls): return [self.scan(u) for u in urls if u.strip()]
    def scan_file(self, filepath):
        batch = []
        try:
            with open(filepath) as f:
                for line in f:
                    u = line.strip()
                    if u and not u.startswith("#"): batch.append(self.scan(u))
        except FileNotFoundError:
            print(f"[{self.name}] File not found: '{filepath}'")
        return batch
    def stats(self):
        if not self.history: return {"total":0}
        total = len(self.history)
        return {"total":total,"safe":sum(1 for r in self.history if r["risk"]=="SAFE"),
                "low_risk":sum(1 for r in self.history if r["risk"]=="LOW RISK"),
                "suspicious":sum(1 for r in self.history if r["risk"]=="SUSPICIOUS"),
                "phishing":sum(1 for r in self.history if r["risk"]=="PHISHING"),
                "avg_score":round(sum(r["score"] for r in self.history)/total,1),
                "highest":max(self.history,key=lambda r:r["score"]),
                "lowest":min(self.history,key=lambda r:r["score"])}
    def report(self):
        s = self.stats()
        if s["total"] == 0: print("No scans yet."); return
        print(_divider()); print(f"  {self.name.upper()} -- SCAN REPORT"); print(_divider())
        print(f"  Total : {s['total']}  |  Avg : {s['avg_score']}/100")
        print(f"  Worst : {_truncate(s['highest']['url'],38)}  ({s['highest']['score']}/100)")
        print(_divider("-"))
        for label in ("SAFE","LOW RISK","SUSPICIOUS","PHISHING"):
            key = label.lower().replace(" ","_")
            print(f"  {_risk_icon(label)}  {label:<12}: {s.get(key,0)}")
        print(_divider())
        flagged = [r for r in self.history if r["risk"] in ("SUSPICIOUS","PHISHING")]
        if flagged:
            print("\n  FLAGGED:")
            for r in sorted(flagged,key=lambda x:x["score"],reverse=True):
                print(f"\n  {_risk_icon(r['risk'])} {r['score']:>3}/100  {r['url']}")
                for reason in r["reasons"]: print(f"            - {reason}")
        print()
    def save(self, filename="report.txt"):
        if not self.history: print("Nothing to save."); return
        s = self.stats()
        with open(filename,"w") as f:
            f.write(f"PHISHING DETECTOR REPORT\nGenerated: {_now()}\n")
            f.write(f"Total: {s['total']}  Avg: {s['avg_score']}/100\n")
            f.write(_divider()+"\n\n")
            for r in sorted(self.history,key=lambda x:x["score"],reverse=True):
                f.write(f"URL  : {r['url']}\nScore: {r['score']}/100 ({r['risk']})\n")
                for reason in r["reasons"]: f.write(f"     - {reason}\n")
                f.write(_divider("-")+"\n")
        print(f"[{self.name}] Saved -> '{filename}'")
    def top(self, n=3): return sorted(self.history,key=lambda r:r["score"],reverse=True)[:n]
    def search(self, keyword): return [r for r in self.history if keyword.lower() in r["url"].lower()]
    def add_bad_tld(self, tld):
        tld = tld if tld.startswith(".") else "."+tld; self.bad_tlds.append(tld)
    def trust_domain(self, domain): self.whitelist.add(domain.lower())
    @property
    def scan_count(self): return len(self.history)
    @property
    def phishing_count(self): return sum(1 for r in self.history if r["risk"]=="PHISHING")
    def __len__(self): return len(self.history)
    def __str__(self): return f"PhishingDetector '{self.name}' | {self.scan_count} scans | {self.phishing_count} phishing"
    def __contains__(self, url): return any(r["url"]==url for r in self.history)
    def __enter__(self): return self
    def __exit__(self, *args): self.save("auto_report.txt"); return False

class EmailDetector(PhishingDetector):
    def __init__(self):
        super().__init__(name="EmailDetector")
        self.email_history = []; self.urgency_phrases = list(URGENCY_PHRASES)
        super().__init__(name="EmailDetector")
        self.email_history = []
        self.urgency_phrases = list(URGENCY_PHRASES)

    def scan_email(self, subject, body):
        text = (subject + " " + body).lower()

        reasons = []
        score = 0

        # Check urgency phrases
        for phrase in self.urgency_phrases:
            if phrase.lower() in text:
                score += 20
                reasons.append(f"Urgency phrase: '{phrase}'")

        # Common phishing keywords
        phishing_words = [
            "verify",
            "account",
            "paypal",
            "password",
            "login",
            "click here",
            "confirm",
            "bank",
            "security",
            "suspended",
            "immediately",
        ]

        for word in phishing_words:
            if word in text:
                score += 10
                reasons.append(f"Suspicious keyword: '{word}'")

        # Scan URLs in the email body
        url_score = 0

        for word in body.split():
            word = word.strip(".,<>\"'()")

            if word.startswith(("http://", "https://")):
                r = self.scan(word)

                url_score = max(url_score, r["score"])

                if r["score"] > 30:
                    reasons.append(f"Suspicious URL: {_truncate(word, 40)}")

        # Combine scores
        score = min(score + (url_score // 2), 100)

        result = {
            "subject": subject,
            "score": score,
            "risk": _classify(score),
            "reasons": reasons,
            "scanned_at": _now(),
        }

        self.email_history.append(result)

        return result
    
    
print(f"  Package version : {VERSION}")
print(f"  PhishingDetector: ready")
print(f"  EmailDetector   : ready")
print()

print("=== LESSON 4: __name__ == '__main__' ===\n")

def demonstrate_name_guard():
    """Shows the current __name__ value and what it means."""
    print(f"  __name__ = '{__name__}'")
    if __name__ == "__main__":
        print("  -> Running DIRECTLY (python day6_main.py)")
        print("  -> The if __name__ == '__main__' block WILL execute")
    else:
        print("  -> Running as an IMPORT (import day6_main)")
        print("  -> The if __name__ == '__main__' block will be SKIPPED")

demonstrate_name_guard()
print()

# What would happen WITHOUT the guard:
print("  Without the guard -- any top-level code runs on import too:")
print("  detector = PhishingDetector()  <- runs even on import!")
print("  detector.scan_many(urls)       <- scans fire when imported!")
print("  detector.report()              <- output appears in wrong context!")
print()
print("  With the guard -- safe to import this file from anywhere.")
print()


print("=== LESSON 5: sys.argv ===\n")

print(f"  sys.argv = {sys.argv}")
print(f"  Script name (sys.argv[0]) = '{sys.argv[0]}'")
print(f"  Extra arguments passed    = {sys.argv[1:] if len(sys.argv) > 1 else 'none'}")
print()

# Manual parsing (fragile -- just for understanding):
def parse_args_manually(argv):
    """Manually parse --key value pairs from sys.argv. Fragile example only."""
    args = {}
    i = 1  # skip argv[0] (script name)
    while i < len(argv):
        key = argv[i]
        if key.startswith("--") and i + 1 < len(argv):
            args[key[2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return args

manual = parse_args_manually(sys.argv)
if manual:
    print(f"  Manually parsed args: {manual}")
else:
    print("  No extra args passed -- try:  python day6_main.py --url http://test.com")
print()

print("=== LESSON 6: argparse ===\n")

def build_arg_parser():
    """
    Builds and returns the argument parser for this program.
    Separated into its own function so it can be tested independently.
    """
    parser = argparse.ArgumentParser(
        prog        = "phishing-detector",
        description = "Scan URLs and emails for phishing indicators.",
        epilog      = "Example: python day6_main.py --url http://paypa1.xyz",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )

    # Single URL to scan
    parser.add_argument(
        "--url", "-u",
        type    = str,
        default = None,
        help    = "A single URL to scan.",
        metavar = "URL",
    )

    # File of URLs to scan
    parser.add_argument(
        "--file", "-f",
        type    = str,
        default = None,
        help    = "Path to a text file containing URLs (one per line).",
        metavar = "FILE",
    )

    # Output report file
    parser.add_argument(
        "--output", "-o",
        type    = str,
        default = "report.txt",
        help    = "Output file for the scan report. (default: report.txt)",
        metavar = "FILE",
    )

    # Number of top results to show
    parser.add_argument(
        "--top", "-t",
        type    = int,
        default = 3,
        help    = "Show the N most dangerous URLs. (default: 3)",
        metavar = "N",
    )
    parser.add_argument(
    "--min-score",
    type=int,
    default=0,
    help="Only show URLs with a score greater than or equal to this value.",
    metavar="SCORE",
    )
    parser.add_argument(
    "--whitelist",
    nargs="+",
    help="Trusted domains to ignore during scanning"
    )
    # Flags (store_true: --verbose sets verbose=True, omitting it sets False)
    parser.add_argument(
        "--verbose", "-v",
        action  = "store_true",
        default = False,
        help    = "Print detailed scan output for every URL.",
    )

    parser.add_argument(
        "--quiet", "-q",
        action  = "store_true",
        default = False,
        help    = "Suppress all output except the final report.",
    )

    parser.add_argument(
        "--version", "-V",
        action  = "version",
        version = f"%(prog)s {VERSION}",
    )
    parser.add_argument(
    "--email-subject",
    type=str,
    help="Email subject to scan for phishing."
    )
    parser.add_argument(
    "--email-body",
    type=str,
    help="Email body to scan for phishing."
    )
    return parser


# Parse the actual command-line arguments
parser = build_arg_parser()
args   = parser.parse_args()

print("  Parsed arguments:")
print(f"    --url     = {args.url}")
print(f"    --file    = {args.file}")
print(f"    --output  = {args.output}")
print(f"    --top     = {args.top}")
print(f"    --min-score = {args.min_score}")
print(f"    --whitelist = {args.whitelist}")
print(f"    --verbose = {args.verbose}")
print(f"    --quiet   = {args.quiet}")
print()
print("  Try running:  python day6_main.py --help")
print("  Or:           python day6_main.py --url http://paypa1.xyz --verbose")
print()

print("=== LESSON 7: logging ===\n")

def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """
    Configures the root logger and returns a named logger for main.py.

    Args:
        verbose : If True, show DEBUG messages.
        quiet   : If True, show only WARNING and above.

    Returns:
        logging.Logger: Named logger for this module.
    """
    # Determine log level based on flags
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Format: timestamp  LEVEL  message
    log_format = "%(asctime)s  %(levelname)-8s  %(message)s"
    date_format = "%H:%M:%S"

    logging.basicConfig(
        level   = level,
        format  = log_format,
        datefmt = date_format,
        stream  = sys.stdout,   # send logs to stdout (not stderr)
    )

    # Return a logger named after this module
    # Other modules would use: logger = logging.getLogger(__name__)
    return logging.getLogger("main")


# Set up logging using the parsed flags
logger = setup_logging(verbose=args.verbose, quiet=args.quiet)

# Show all log levels so you can see the difference
print("  Log level examples (level set based on --verbose / --quiet):\n")
logging.getLogger("demo").debug   ("DEBUG   -- developer detail, hidden by default")
logging.getLogger("demo").info    ("INFO    -- normal flow, shown by default")
logging.getLogger("demo").warning ("WARNING -- unexpected but non-fatal")
logging.getLogger("demo").error   ("ERROR   -- something went wrong")
print()

print("=== LESSON 8: Error Handling and Exit Codes ===\n")

class ScanError(Exception):
    """Custom exception for scan-level errors in this application."""
    pass

class ConfigError(Exception):
    """Custom exception for configuration problems."""
    pass

def validate_url(url: str) -> str:
    """
    Validates a URL before scanning. Raises ScanError if invalid.

    Args:
        url (str): URL string to validate.

    Returns:
        str: The cleaned URL.

    Raises:
        ScanError: If the URL is empty or has no scheme.
    """
    url = url.strip()
    if not url:
        raise ScanError("URL cannot be empty.")
    if not url.startswith(("http://", "https://")):
        raise ScanError(
            f"URL must start with http:// or https://. Got: '{url[:40]}'"
        )
    return url

def validate_file(filepath: str) -> Path:
    """
    Validates a file path before reading. Raises ScanError if invalid.

    Args:
        filepath (str): Path to validate.

    Returns:
        Path: Validated Path object.

    Raises:
        ScanError: If the file does not exist.
    """
    path = Path(filepath)
    if not path.exists():
        raise ScanError(f"File not found: '{filepath}'")
    if not path.is_file():
        raise ScanError(f"Path is not a file: '{filepath}'")
    return path

# Show validation in action
print("  validate_url() examples:")
test_inputs = [
    "http://paypa1.xyz",
    "  https://google.com  ",
    "not-a-url",
    "",
]
for u in test_inputs:
    try:
        clean = validate_url(u)
        print(f"    VALID   : '{clean}'")
    except ScanError as e:
        print(f"    INVALID : {e}")
print()


print("=== LESSON 9: The main() Function ===\n")

def print_startup_banner():
    """Prints the startup banner. Separated for clarity and testability."""
    print(_divider("="))
    print(f"  PHISHING DETECTOR v{VERSION}")
    print(f"  Started at: {_now()}")
    print(_divider("="))
    print()

def print_top_results(detector: PhishingDetector, n: int) -> None:
    """Prints the N most dangerous scan results."""
    top = detector.top(n)
    if not top:
        print("  No results to display.")
        return

    print(f"\n  TOP {n} MOST DANGEROUS URLS:")
    print(_divider("-"))
    for i, r in enumerate(top, 1):
        print(f"\n  #{i}  Score: {r['score']}/100  ({r['risk']})")
        print(f"       URL: {r['url']}")
        for reason in r["reasons"]:
            print(f"            - {reason}")
    print()


def main() -> int:
    """
    Main entry point. Orchestrates the full scan flow.

    Flow:
        1. Print banner
        2. Determine what to scan (--url or --file or demo)
        3. Scan
        4. Report
        5. Save
        6. Show top N
        7. Return exit code

    Returns:
        int: 0 on success, 1 on error, 2 on usage error.
    """
    try:
        print_startup_banner()
        logger.info("PhishingDetector starting up")

        # ── Step 1: Create detector ────────────────────────────────────
        detector = PhishingDetector(name="Day6Detector")
        logger.debug(f"Detector created: {detector}")

        # Trust user-supplied domains
        if args.whitelist:
         for domain in args.whitelist:
          detector.trust_domain(domain)
          logger.info(f"Trusted domain added: {domain}")    
        # ── Step 2: Decide what to scan ────────────────────────────────
        if args.url:
            # Single URL mode
            logger.info(f"Single URL mode: {args.url}")
            try:
                clean_url = validate_url(args.url)
            except ScanError as e:
                logger.error(f"Invalid URL: {e}")
                return 2    # usage error

            result = detector.scan(clean_url)
            print(f"  Result: {_risk_icon(result['risk'])} "
                  f"[{_score_bar(result['score'])}] "
                  f"{result['score']}/100  {result['risk']}")
            if result["reasons"]:
                for reason in result["reasons"]:
                    print(f"          - {reason}")
            print()

        elif args.file:
            # File mode
            logger.info(f"File mode: {args.file}")
            try:
                validate_file(args.file)
            except ScanError as e:
                logger.error(f"File error: {e}")
                return 2

            batch = detector.scan_file(args.file)
            logger.info(f"Scanned {len(batch)} URLs from file")

            if args.verbose:
                for r in batch:
                    print(f"  {_risk_icon(r['risk'])} "
                          f"[{_score_bar(r['score'])}] "
                          f"{r['score']:>3}/100  {_truncate(r['url'], 44)}")
                print()

        elif args.email_subject and args.email_body:
            logger.info("Email mode")

            detector = EmailDetector()

            result = detector.scan_email(
              args.email_subject,
              args.email_body
            )

            print()
            print(
        f"  Result: {_risk_icon(result['risk'])} "
        f"[{_score_bar(result['score'])}] "
        f"{result['score']:>3}/100  {result['risk']}"
        )

            if result["reasons"]:
             for reason in result["reasons"]:
              print(f"          - {reason}")

              print()

             return 1 if result["score"] >= 70 else 0
                
        else:
            # Demo mode: no args given, run a built-in demo
            logger.info("Demo mode (no --url or --file given)")
            print("  No --url or --file given. Running built-in demo...\n")

            demo_urls = [
                "https://www.google.com/search?q=python",
                "https://github.com/user/phishing-detector",
                "https://youtube.com/watch?v=abc123",
                "http://paypa1.secure-login.xyz/verify",
                "http://192.168.1.1/admin/login",
                "http://free-prize.win/claim?user=you",
                "http://micros0ft-update.tk/download",
                "http://my-secure-bank-login.com/confirm?ssn=123",
                "https://amazon.com/products?id=123",
                "http://tw1tter-login.xyz/verify?password=abc",
            ]

            print(f"  Scanning {len(demo_urls)} demo URLs...\n")
            for url in demo_urls:
                r = detector.scan(url)
                print(f"  {_risk_icon(r['risk'])} "
                      f"[{_score_bar(r['score'])}] "
                      f"{r['score']:>3}/100  {_truncate(url, 44)}")
                if args.verbose and r["reasons"]:
                    for reason in r["reasons"]:
                        print(f"             - {reason}")
            print()

                # Filter results by minimum score
            if args.min_score > 0:
                detector.history = [
                result
                    for result in detector.history
            if result["score"] >= args.min_score
            ]

        # ── Step 3: Report ─────────────────────────────────────────────
            if not args.quiet:
              detector.report()

        # ── Step 4: Save ───────────────────────────────────────────────
        detector.save(args.output)
        logger.info(f"Report saved to '{args.output}'")

        # ── Step 5: Top N ──────────────────────────────────────────────
        if not args.quiet:
            print_top_results(detector, args.top)

        # ── Step 6: Summary log ────────────────────────────────────────
        s = detector.stats()
        logger.info(
            f"Done. {s['total']} scanned | "
            f"{s['phishing']} phishing | "
            f"avg {s['avg_score']}/100"
        )

        return 1 if s.get("phishing", 0) > 0 else 0
    
    except KeyboardInterrupt:
        # User pressed Ctrl+C -- not an error, just an interrupt
        print("\n\n  Scan interrupted by user (Ctrl+C).")
        logger.info("Interrupted by user")
        return 0

    except Exception as e:
        # Unexpected error -- log it fully and return error code
        logger.error(f"Unexpected error: {e}")
        logger.debug("Full traceback:", exc_info=True)
        return 1

print("=== LESSON 10: The if __name__ == '__main__' Guard ===\n")
print("  About to call main() via the guard...\n")
print(_divider())
print()

if __name__ == "__main__":
    exit_code = main()

    print()
    print(_divider())
    print(f"\n  Program finished with exit code: {exit_code}")
    if exit_code == 0:
        print("  (0 = success, no phishing found)")
    elif exit_code == 1:
        print("  (1 = phishing URLs were detected)")
    elif exit_code == 2:
        print("  (2 = usage error, bad argument)")
    print()

    sys.exit(exit_code)