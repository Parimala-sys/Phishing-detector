

from datetime import datetime
from urllib.parse import urlparse

print("LESSON 1: Pure Functions\n")

# IMPURE — has a side effect (modifies external state)
results_log = []

def impure_classify(score):
    label = "SAFE" if score == 0 else "PHISHING"
    results_log.append(label)    # ← SIDE EFFECT: modifies outside variable
    return label

def pure_classify(score):
    if score == 0:   return "SAFE"
    if score <= 30:  return "LOW RISK"
    if score <= 60:  return "SUSPICIOUS"
    return "PHISHING"

print("Pure:   pure_classify(0)  →", pure_classify(0))
print("Pure:   pure_classify(75) →", pure_classify(75))
print("Impure: results_log after two calls:", end=" ")
impure_classify(0)
impure_classify(75)
print(results_log, "← changed external state!\n")

print("LESSON 2: Type Hints\n")

def old_style(score, width):
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)

def score_bar(score: int, width: int = 10) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)

def find_first_phishing(results: list) -> dict | None:
    """Returns the first PHISHING result, or None if none found."""
    for r in results:
        if r.get("risk") == "PHISHING":
            return r
    return None   
print("score_bar(70)    →", score_bar(70))
print("score_bar(70, 5) →", score_bar(70, 5))

fake_results = [
    {"url": "https://google.com", "risk": "SAFE",     "score": 0},
    {"url": "http://evil.xyz",    "risk": "PHISHING",  "score": 85},
]
found = find_first_phishing(fake_results)
print("find_first_phishing →", found["url"] if found else "None")

print("LESSON 3: Docstrings\n")

def classify(score: int) -> str:
    """
    Converts a numeric risk score into a human-readable label.

    Scoring thresholds:
        0        → SAFE
        1 – 30   → LOW RISK
        31 – 60  → SUSPICIOUS
        61 – 100 → PHISHING

    Args:
        score (int): Risk score between 0 and 100.

    Returns:
        str: One of "SAFE", "LOW RISK", "SUSPICIOUS", "PHISHING".

    Example:
        >>> classify(0)
        'SAFE'
        >>> classify(45)
        'SUSPICIOUS'
        >>> classify(90)
        'PHISHING'
    """
    if score == 0:   return "SAFE"
    if score <= 30:  return "LOW RISK"
    if score <= 60:  return "SUSPICIOUS"
    return "PHISHING"

print("classify.__doc__ (first line):")
print(" ", classify.__doc__.strip().splitlines()[0])
print()

print("LESSON 4: Doctests\n")

def truncate(text: str, max_len: int = 50) -> str:
    """
    Truncates a string to max_len characters, appending '…' if cut.

    Args:
        text    (str): Input string.
        max_len (int): Maximum allowed length. Default 50.

    Returns:
        str: Possibly-shortened string.

    Examples:
        >>> truncate("hello", 10)
        'hello'
        >>> truncate("hello world", 8)
        'hello w…'
        >>> truncate("", 10)
        ''
        >>> truncate("abc", 3)
        'abc'
        >>> truncate("abcd", 3)
        'ab…'
    """
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "…"


import doctest
results = doctest.testmod(verbose=False)
print(f"Doctests run: {results.attempted}  |  Failures: {results.failed}")
print()

print("truncate examples:")
print("  truncate('hello', 10)         →", repr(truncate("hello", 10)))
print("  truncate('hello world', 8)    →", repr(truncate("hello world", 8)))
print("  truncate('http://paypa1.xyz/verify/account/update', 30) →",
      repr(truncate("http://paypa1.xyz/verify/account/update", 30)))
print()

print("LESSON 5: Guard Clauses\n")

def extract_params_nested(query: str) -> set:
    params = set()
    if query:                             # ← nesting starts
        for part in query.split("&"):
            if part:                      # ← deeper
                key = part.split("=")[0].lower()
                if key:                   # ← even deeper
                    params.add(key)
    return params


SENSITIVE_PARAMS = {
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "email",
    "token",
    "apikey",
    "api_key",
    "key",
    "secret",
    "ssn",
    "creditcard",
    "card",
    "cvv",
    "pin",
    "otp",
}

def extract_params(query: str) -> set:
    """
    Extracts parameter names from a URL query string.

    Args:
        query (str): Raw query string, e.g. "ssn=123&user=alice"

    Returns:
        set: Parameter name strings (lowercase).

    Examples:
        >>> extract_params("ssn=123&user=alice")
        {'ssn', 'user'}
        >>> extract_params("")
        set()
        >>> extract_params("password=abc")
        {'password'}
    """
    if not query:           
        return set()

    params = set()
    for part in query.split("&"):
        key = part.split("=")[0].lower()
        if not key:          
            continue
        params.add(key)
    return params

def has_sensitive_params(url: str) -> bool:
    """
    Returns True if any SENSITIVE_PARAMS appear in the URL's
    query string.

    Uses extract_params() internally.

    Args:
        url (str): Full URL to inspect.

    Returns:
        bool: True if at least one sensitive parameter is found.

    Examples:
        >>> has_sensitive_params("http://bank.com/login?ssn=123")
        True
        >>> has_sensitive_params("https://google.com?q=python")
        False
        >>> has_sensitive_params("https://site.com?user=alice&password=123")
        True
        >>> has_sensitive_params("https://example.com")
        False
    """
    query = urlparse(url).query
    params = extract_params(query)
    return any(param in SENSITIVE_PARAMS for param in params)

print(has_sensitive_params("http://bank.com/login?ssn=123"))
print(has_sensitive_params("https://google.com?q=python"))
print(has_sensitive_params("https://site.com?user=alice"))
print(has_sensitive_params("https://site.com?password=secret123"))
print(has_sensitive_params("https://example.com"))

print("extract_params('ssn=123&user=alice') →",
      extract_params("ssn=123&user=alice"))
print("extract_params('')                   →",
      extract_params(""))
print("extract_params('password=abc&')      →",
      extract_params("password=abc&"))
print()

print("LESSON 6: Default Parameters\n")

def risk_icon(risk: str, fallback: str = "?") -> str:
    """
    Returns a display icon character for a risk label.

    Args:
        risk     (str): One of SAFE / LOW RISK / SUSPICIOUS / PHISHING.
        fallback (str): Character to return if risk is unrecognised.

    Returns:
        str: Single icon character.

    Examples:
        >>> risk_icon("SAFE")
        '✓'
        >>> risk_icon("PHISHING")
        '✕'
        >>> risk_icon("UNKNOWN")
        '?'
    """
    icons = {
        "SAFE":       "✓",
        "LOW RISK":   "◎",
        "SUSPICIOUS": "⚠",
        "PHISHING":   "✕",
    }
    return icons.get(risk, fallback)

print("risk_icon('SAFE')       →", risk_icon("SAFE"))
print("risk_icon('PHISHING')   →", risk_icon("PHISHING"))
print("risk_icon('UNKNOWN')    →", risk_icon("UNKNOWN"))
print("risk_icon('UNKNOWN','X')→", risk_icon("UNKNOWN", "X"))
print()

def bad_append(item, container=[]):     # ← BUG: [] created once at import time
    container.append(item)
    return container

print("Mutable default bug:")
print(" bad_append('a') →", bad_append("a"))
print(" bad_append('b') →", bad_append("b"))   # ← 'a' is still in there!
print(" (both calls share the same list!)\n")


def safe_append(item, container=None):
    if container is None:
        container = []
    container.append(item)
    return container

print("Correct version:")
print(" safe_append('a') →", safe_append("a"))
print(" safe_append('b') →", safe_append("b"))   # fresh list each time
print()

print("LESSON 7: *args and **kwargs\n")

# *args example
def average_score(*scores: int) -> float:
    """
    Returns the average of any number of scores.

    Args:
        *scores: Any number of integer scores.

    Returns:
        float: Average, or 0.0 if no scores given.

    Examples:
        >>> average_score(10, 20, 30)
        20.0
        >>> average_score(100)
        100.0
        >>> average_score()
        0.0
    """
    if not scores:        # guard clause
        return 0.0
    return sum(scores) / len(scores)

print("average_score(10, 20, 30) →", average_score(10, 20, 30))
print("average_score(85, 90)     →", average_score(85, 90))
print("average_score()           →", average_score())
print()


def build_result(**fields) -> dict:
    """
    Builds a scan result dict from keyword arguments.
    Adds a timestamp automatically.

    Example:
        build_result(url="http://evil.xyz", score=80, risk="PHISHING")
    """
    result = dict(fields)
    result.setdefault("scanned_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return result

r = build_result(url="http://evil.xyz", score=80, risk="PHISHING")
print("build_result(url=..., score=80, risk=...) →")
for k, v in r.items():
    print(f"  {k}: {v}")
print()

print("LESSON 8: Functions as Arguments\n")

def filter_results(results: list, condition) -> list:
    """
    Returns results where condition(result) is True.

    Args:
        results   (list): List of scan result dicts.
        condition (callable): A function that takes a result and returns bool.

    Returns:
        list: Filtered results.
    """
    return [r for r in results if condition(r)]

sample = [
    {"url": "https://google.com",  "score": 0,  "risk": "SAFE"},
    {"url": "http://paypa1.xyz",   "score": 85, "risk": "PHISHING"},
    {"url": "http://free.win",     "score": 50, "risk": "SUSPICIOUS"},
    {"url": "https://github.com",  "score": 0,  "risk": "SAFE"},
    {"url": "http://evil.tk",      "score": 70, "risk": "PHISHING"},
]


def is_phishing(result):
    return result["risk"] == "PHISHING"

phishing_only = filter_results(sample, is_phishing)
print("filter_results(sample, is_phishing):")
for r in phishing_only:
    print(f"  {r['score']}/100  {r['url']}")
print()


high_risk = filter_results(sample, lambda r: r["score"] >= 50)
print("filter_results(sample, lambda r: r['score'] >= 50):")
for r in high_risk:
    print(f"  {r['score']}/100  {r['url']}")
print()


sorted_by_score = sorted(sample, key=lambda r: r["score"], reverse=True)
print("sorted by score (highest first):")
for r in sorted_by_score:
    print(f"  {r['score']:>3}/100  {r['risk']:<12}  {r['url']}")
print()


print("LESSON 9: Lambda Functions\n")

# These two are equivalent:
def double(x):
    return x * 2

double_lambda = lambda x: x * 2

print("def double(5)         →", double(5))
print("lambda double(5)      →", double_lambda(5))
print()

# Common use: key= in sorted / min / max
words = ["phishing", "safe", "suspicious", "login", "verify"]
print("sorted by length:    ", sorted(words, key=lambda w: len(w)))
print("longest word:        ", max(words, key=lambda w: len(w)))
print("shortest word:       ", min(words, key=lambda w: len(w)))
print()

# Lambda with two args
multiply = lambda a, b: a * b
print("multiply(4, 5) →", multiply(4, 5))
print()


print("=== LESSON 10: Complete Utils Module ===\n")


# ── GROUP A: Score helpers ────────────────────────────────────────────

def now() -> str:
    """
    Returns the current date and time as a formatted string.

    Returns:
        str: Timestamp in "YYYY-MM-DD HH:MM:SS" format.

    Example:
        >>> len(now())
        19
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def divider(char: str = "=", width: int = 58) -> str:
    """
    Returns a repeated-character divider line for reports.

    Args:
        char  (str): Character to repeat. Default "=".
        width (int): Total length. Default 58.

    Returns:
        str: A string of char repeated width times.

    Examples:
        >>> divider("=", 5)
        '====='
        >>> divider("-", 3)
        '---'
    """
    return char * width


# ── GROUP B: URL analysis helpers ────────────────────────────────────

def is_ip_domain(domain: str) -> bool:
    """
    Returns True if the domain is a raw IPv4 address.

    Attackers use IPs to hide the real server identity:
    http://192.168.0.1/admin/login

    Args:
        domain (str): The domain portion of a URL (no scheme).

    Returns:
        bool: True if 3 or more dot-separated parts are digits.

    Examples:
        >>> is_ip_domain("192.168.1.1")
        True
        >>> is_ip_domain("10.0.0.1")
        True
        >>> is_ip_domain("google.com")
        False
        >>> is_ip_domain("192.168.paypal.com")
        False
    """
    # Strip port number (192.168.1.1:8080) before checking
    parts = domain.split(":")[0].split(".")
    return sum(1 for p in parts if p.isdigit()) >= 3


def count_subdomains(domain: str) -> int:
    """
    Returns the number of dot-separated levels in a domain.

    More dots = deeper subdomain chain = more suspicious.
    secure.login.paypal.com.evil.xyz  has 5 dots — very suspicious.

    Args:
        domain (str): Full domain string.

    Returns:
        int: Number of dots in the domain.

    Examples:
        >>> count_subdomains("google.com")
        1
        >>> count_subdomains("www.google.com")
        2
        >>> count_subdomains("login.secure.paypal.com.evil.xyz")
        5
    """
    return domain.count(".")


def parse_base_domain(url: str) -> str:
    """
    Extracts the base domain (last two parts) from a full URL.

    Used for whitelist checking — we trust "google.com" regardless
    of subdomain, so we strip "www." and extract just "google.com".

    Args:
        url (str): Full URL string.

    Returns:
        str: Base domain, e.g. "google.com" from "www.google.com".

    Examples:
        >>> parse_base_domain("https://www.google.com/search?q=python")
        'google.com'
        >>> parse_base_domain("http://login.secure.evil.xyz/verify")
        'evil.xyz'
        >>> parse_base_domain("https://github.com/user/repo")
        'github.com'
    """
    domain = urlparse(url).netloc.lower()
    # Strip port if present: google.com:443 → google.com
    domain = domain.split(":")[0]
    parts  = domain.split(".")
    # Take the last two parts: ["www", "google", "com"] → "google.com"
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def strip_tracking_params(url: str) -> str:
    """
    Removes common tracking parameters from a URL's query string.

    Tracking params (utm_source, fbclid, etc.) clutter URLs and can
    interfere with phishing detection of query string content.

    Args:
        url (str): Full URL string.

    Returns:
        str: URL with tracking params removed.

    Examples:
        >>> strip_tracking_params("https://google.com/search?q=python&utm_source=email")
        'https://google.com/search?q=python'
        >>> strip_tracking_params("https://site.com/page?fbclid=abc&user=alice")
        'https://site.com/page?user=alice'
    """
    TRACKING_PARAMS = {
        "utm_source", "utm_medium", "utm_campaign",
        "utm_content", "utm_term", "fbclid", "gclid",
        "mc_eid", "ref", "_ga",
    }
    parsed = urlparse(url)
    if not parsed.query:
        return url

    # Keep only non-tracking params
    clean_parts = []
    for part in parsed.query.split("&"):
        key = part.split("=")[0].lower()
        if key not in TRACKING_PARAMS:
            clean_parts.append(part)

    clean_query = "&".join(clean_parts)
    # Reconstruct URL (scheme://netloc/path?query)
    if clean_query:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{clean_query}"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def has_excessive_hyphens(domain: str, threshold: int = 3) -> bool:
    """
    Returns True if the domain contains too many hyphens.

    Legitimate domains rarely use 3+ hyphens. Phishing domains
    like "my-secure-bank-login.com" use them to look official.

    Args:
        domain    (str): Domain string to check.
        threshold (int): Minimum hyphen count to flag. Default 3.

    Returns:
        bool: True if hyphen count >= threshold.

    Examples:
        >>> has_excessive_hyphens("google.com")
        False
        >>> has_excessive_hyphens("my-bank.com")
        False
        >>> has_excessive_hyphens("my-secure-bank-login.com")
        True
    """
    return domain.count("-") >= threshold


# ── GROUP C: Formatting helpers ───────────────────────────────────────

def format_result_line(result: dict, url_width: int = 44) -> str:
    """
    Formats a single scan result as a one-line display string.

    Args:
        result    (dict): Scan result with url, score, risk keys.
        url_width (int):  Max width for the URL portion. Default 44.

    Returns:
        str: Formatted single line ready to print.

    Example:
        >>> r = {"url": "http://evil.xyz", "score": 85, "risk": "PHISHING"}
        >>> "PHISHING" in format_result_line(r)
        True
    """
    icon = risk_icon(result["risk"])
    bar  = score_bar(result["score"])
    url  = truncate(result["url"], url_width)
    return (
    f"  {icon} [{bar}] "
    f"{result['score']:>3}/100  "
    f"{result['risk']:<12} "
    f"{url}"
)


def format_reasons(reasons: list, indent: int = 6) -> str:
    """
    Formats a list of reason strings into an indented block.

    Args:
        reasons (list): List of reason strings.
        indent  (int):  Number of spaces before each bullet. Default 12.

    Returns:
        str: Multi-line string with bullet points.

    Example:
        >>> print(format_reasons(["Bad TLD", "No HTTPS"]))
              • Bad TLD
              • No HTTPS
    """
    if not reasons:
        return ""
    prefix = " " * indent + "• "
    return "\n".join(prefix + r for r in reasons)


# ── GROUP D: Statistics helpers ───────────────────────────────────────

def percentage(part: int, total: int) -> str:
    """
    Returns a percentage string rounded to 1 decimal.

    Examples:
        >>> percentage(3, 10)
        '30.0%'
        >>> percentage(0, 10)
        '0.0%'
        >>> percentage(5, 0)
        '0.0%'
    """
    if total == 0:
        return "0.0%"

    return f"{(part / total) * 100:.1f}%"

def compute_stats(results: list) -> dict:
    """
    Computes a summary statistics dictionary from scan results.
    """
    if not results:
        return {"total": 0}

    total = len(results)

    return {
        "total": total,
        "safe": sum(1 for r in results if r["risk"] == "SAFE"),
        "low_risk": sum(1 for r in results if r["risk"] == "LOW RISK"),
        "suspicious": sum(1 for r in results if r["risk"] == "SUSPICIOUS"),
        "phishing": sum(1 for r in results if r["risk"] == "PHISHING"),
        "avg_score": round(sum(r["score"] for r in results) / total, 1),
        "highest": max(results, key=lambda r: r["score"]),
        "lowest": min(results, key=lambda r: r["score"]),
    }

def summarise(results: list) -> str:
    """
    Returns a one-line summary of scan results.

    Uses compute_stats() to generate the statistics.

    Args:
        results (list): List of scan result dictionaries.

    Returns:
        str: Summary string.

    Examples:
        >>> r = [
        ...     {"score": 0, "risk": "SAFE"},
        ...     {"score": 80, "risk": "PHISHING"}
        ... ]
        >>> summarise(r)
        '2 scanned | 1 safe | 0 suspicious | 1 phishing | avg 40.0/100'
    """
    stats = compute_stats(results)

    if stats["total"] == 0:
        return "0 scanned | 0 safe | 0 suspicious | 0 phishing | avg 0.0/100"

    return (
        f"{stats['total']} scanned | "
        f"{stats['safe']} safe | "
        f"{stats['suspicious']} suspicious | "
        f"{stats['phishing']} phishing | "
        f"avg {stats['avg_score']}/100"
    )


def group_by_risk(results: list) -> dict:
    """
    Groups scan results by their risk label.

    Args:
        results (list): List of scan result dicts.

    Returns:
        dict: Keys are risk labels, values are lists of matching results.

    Example:
        >>> r = [{"risk": "SAFE", "score": 0}, {"risk": "PHISHING", "score": 80}]
        >>> len(group_by_risk(r)["SAFE"])
        1
    """
    groups = {"SAFE": [], "LOW RISK": [], "SUSPICIOUS": [], "PHISHING": []}
    for result in results:
        label = result.get("risk", "UNKNOWN")
        groups.setdefault(label, []).append(result)
    return groups

def top_n(results: list, n: int = 3) -> list:
    """
    Returns the n results with the highest scores.

    Examples:
        >>> r = [{"score": 10}, {"score": 80}, {"score": 50}]
        >>> top_n(r, 2)
        [{'score': 80}, {'score': 50}]
        >>> len(top_n(r))
        3
    """
    return sorted(results, key=lambda r: r["score"], reverse=True)[:n]

def score_histogram(results: list, buckets: int = 5) -> dict:
    """
    Builds a frequency histogram of scores divided into equal buckets.

    Args:
        results (list): List of scan result dicts.
        buckets (int):  Number of score ranges to create. Default 5.

    Returns:
        dict: Keys are range strings like "0-19", values are counts.

    Example:
        >>> r = [{"score": 10}, {"score": 55}, {"score": 90}]
        >>> score_histogram(r)["0-19"]
        1
    """
    if not results:
        return {}

    size     = 100 // buckets
    hist     = {}
    for i in range(buckets):
        low  = i * size
        high = low + size - 1 if i < buckets - 1 else 100
        hist[f"{low}-{high}"] = 0

    for r in results:
        score  = r.get("score", 0)
        bucket = min(score // size, buckets - 1)
        low    = bucket * size
        high   = low + size - 1 if bucket < buckets - 1 else 100
        hist[f"{low}-{high}"] += 1

    return hist


def print_histogram(results: list) -> None:
    """
    Prints a text bar chart of score distribution.

    Args:
        results (list): List of scan result dicts with 'score' keys.

    Example output:
         0-19  | ████ (4)
        20-39  | ██ (2)
        40-59  | █ (1)
        60-79  | ███ (3)
        80-100 | █ (1)
    """
    hist = score_histogram(results)
    max_count = max(hist.values()) if hist else 1
    for label, count in hist.items():
        bar_len = round(count / max_count * 20) if max_count > 0 else 0
        bar     = "█" * bar_len
        print(f"  {label:>7}  | {bar} ({count})")

if __name__ == "__main__":

        print("── Demo: All utils in action ──\n")

    # Sample results to work with
        sample_results = [
        {"url": "https://google.com",              "score": 0,  "risk": "SAFE"},
        {"url": "https://github.com/user/repo",    "score": 0,  "risk": "SAFE"},
        {"url": "https://amazon.com/products",     "score": 0,  "risk": "SAFE"},
        {"url": "http://offers.deals.shop.tk",     "score": 35, "risk": "SUSPICIOUS"},
        {"url": "http://bit.ly/freeprize",         "score": 25, "risk": "LOW RISK"},
        {"url": "http://paypa1.secure-login.xyz",  "score": 85, "risk": "PHISHING"},
        {"url": "http://192.168.1.1/admin/login",  "score": 70, "risk": "PHISHING"},
        {"url": "http://free-prize.win/claim?ssn", "score": 100,"risk": "PHISHING"},
        {"url": "http://micros0ft-update.tk",      "score": 80, "risk": "PHISHING"},
        {"url": "https://youtube.com/watch",       "score": 0,  "risk": "SAFE"},
    ]

    # format_result_line
        print("format_result_line() output:")
        for r in sample_results:
          print(format_result_line(r))
        print()

    # format_reasons
        print("format_reasons() output:")
        reasons = ["No HTTPS", "High-risk TLD: .xyz", "Impersonates brand: 'paypa1'"]
        print(format_reasons(reasons))
        print()


# compute_stats
        s = compute_stats(sample_results)
        print("compute_stats() output:")
        print(f"  total      : {s['total']}")
        print(f"  safe       : {s['safe']}")
        print(f"  low_risk   : {s['low_risk']}")
        print(f"  suspicious : {s['suspicious']}")
        print(f"  phishing   : {s['phishing']}")
        print(f"  avg_score  : {s['avg_score']}/100")
        print(f"  highest    : {s['highest']['url']}  ({s['highest']['score']}/100)")
        print(f"  lowest     : {s['lowest']['url']}  ({s['lowest']['score']}/100)")
        print()

# group_by_risk
        groups = group_by_risk(sample_results)
        print("group_by_risk() counts:")
        for label, items in groups.items():
         print(f"  {label:<12}: {len(items)}")
         print()

    # score_histogram / print_histogram
        print("score_histogram (print_histogram):")
        print_histogram(sample_results)
        print()

    # URL helpers
        print("URL helpers:")
        print("  is_ip_domain('192.168.1.1')                →", is_ip_domain("192.168.1.1"))
        print("  is_ip_domain('google.com')                 →", is_ip_domain("google.com"))
        print("  count_subdomains('login.secure.evil.xyz')  →", count_subdomains("login.secure.evil.xyz"))
        print("  has_excessive_hyphens('my-bank-login.net') →", has_excessive_hyphens("my-bank-login.net"))
        print("  parse_base_domain('https://www.google.com')→", parse_base_domain("https://www.google.com"))

        dirty = "https://amazon.com/deal?id=123&utm_source=email&utm_campaign=promo"
        print(f"\n  strip_tracking_params:")
        print(f"    before: {dirty}")
        print(f"    after : {strip_tracking_params(dirty)}")
        print()

    # filter_results with lambda
        print("filter_results() with lambda:")
        dangerous = filter_results(sample_results, lambda r: r["score"] >= 70)
        print(f"  score >= 70:  {len(dangerous)} results")
        for r in dangerous:
         print(f"    {r['score']}/100  {r['url']}")
        print()

    # Misc
        print("Misc:")
        print("  now()          →", now())
        print("  divider('=',20)→", divider("=", 20))
        print("  divider('-',20)→", divider("-", 20))
