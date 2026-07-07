
import os
from collections import namedtuple
from enum import Enum, IntEnum

print("=== LESSON 1: Constants and Naming ===\n")

MAX_SCORE = int(os.environ.get("PHISH_MAX_SCORE", "100"))
DEFAULT_WIDTH = 58
VERSION       = "1.0.0"
DEBUG_MODE    = False

print(f"MAX_SCORE     = {MAX_SCORE}")
print(f"DEFAULT_WIDTH = {DEFAULT_WIDTH}")
print(f"VERSION       = {VERSION}")
print(f"DEBUG_MODE    = {DEBUG_MODE}")
print()


print("=== LESSON 2: Mutable vs Immutable ===\n")

# Mutable list -- can be accidentally modified
BAD_TLDS_LIST = [".xyz", ".tk", ".ml"]
BAD_TLDS_LIST.append(".evil")       # silent mutation -- no error!
print(f"After append to list: {BAD_TLDS_LIST}")   # .evil appeared!

# Immutable tuple -- protects the constant
BAD_TLDS_TUPLE = (".xyz", ".tk", ".ml")
try:
    BAD_TLDS_TUPLE.append(".evil")
except AttributeError as e:
    print(f"tuple blocks mutation: {e}")

# Immutable frozenset -- protects a set-type constant
SENSITIVE_FROZEN = frozenset({"password", "ssn"})
try:
    SENSITIVE_FROZEN.add("newparam")
except AttributeError as e:
    print(f"frozenset blocks mutation: {e}")

# Both still support 'in' checks -- the key operation for lookups
print(f"\n'.tk' in BAD_TLDS_TUPLE   -> {'.tk' in BAD_TLDS_TUPLE}")
print(f"'ssn' in SENSITIVE_FROZEN -> {'ssn' in SENSITIVE_FROZEN}")
print()

print("=== LESSON 3: Grouping Constants ===\n")

SCORE_WEIGHTS = {
    "no_https":          15,   # HTTP instead of HTTPS
    "bad_tld":           25,   # high-risk domain extension
    "fake_brand":        30,   # impersonates a known company
    "suspicious_path":   10,   # /verify /login /confirm etc.
    "ip_address":        20,   # raw IP used as domain
    "long_subdomain":    10,   # 3+ subdomain levels
    "excessive_hyphens": 15,   # 3+ hyphens in domain
    "query_sensitive":   30,   # SSN / password in query string
    "new_domain":        20,   # Domain registered < 30 days
}

# ---- RISK THRESHOLDS -------------------------------------------
# (max_score, label) pairs, sorted ascending.
# Stored as a tuple of tuples -- fully immutable.

RISK_THRESHOLDS = (
    (0,   "SAFE"),
    (30,  "LOW RISK"),
    (60,  "SUSPICIOUS"),
    (100, "PHISHING"),
)

# ---- DOMAIN BLOCKLISTS -----------------------------------------
# TLDs that are free, require no identity verification, and are
# overwhelmingly used in phishing and spam.
# Stored as tuple -- immutable, supports 'in' checks.

BAD_TLDS = (
    ".xyz",    # most abused TLD globally
    ".tk",     # free Tokelau domain, #1 phishing TLD for years
    ".ml",     # free Mali domain
    ".ga",     # free Gabon domain
    ".cf",     # free Central African Republic domain
    ".gq",     # free Equatorial Guinea domain
    ".pw",     # Palau -- heavily abused despite "professional web" branding
    ".win",    # generic, low-cost, high-abuse
    ".top",    # generic, low-cost, high-abuse
    ".click",  # used in click-fraud and phishing
    ".buzz",   # low-cost, abused
    ".loan",   # financial phishing
    ".work",   # fake job and employment scams
    ".party",  # low-cost throwaway domains
)

# TLDs that are almost impossible to abuse (restricted by policy)
TRUSTED_TLDS = (
    ".gov",    # US government -- verified identity required
    ".edu",    # accredited US universities only
    ".mil",    # US military only
)

# ---- BRAND IMPERSONATION PATTERNS ------------------------------
# Leetspeak / typosquatting patterns for well-known brands.
# Pattern: replace a letter with a visually similar digit/char.
#   a->4  e->3  g->9  i->1  l->1  o->0  s->5

FAKE_BRANDS = (
    # Payment
    "paypa1", "paypa1l", "paypai",

    # Shopping
    "amaz0n", "amazom", "arnazon",

    # Tech giants
    "g00gle", "go0gle", "micros0ft", "microsoct",
    "app1e", "netfl1x", "netf1ix",
    "spotiify", "netfilx",

    # Social media
    "faceb00k", "facebok", "inst4gram",
    "tw1tter", "twitterr", "linkedln", "lnkedin",

    # Banking
    "hsb0", "ba1rclays", "hali4ax", "lloyds1",
    "we11sfargo", "cit1bank",

)

# ---- SUSPICIOUS PATH KEYWORDS ----------------------------------
# Path words common in credential-harvesting pages.
# A path keyword alone is worth only 10pts; needs other signals.

SUSPICIOUS_PATHS = (
    "verify",       # "please verify your account"
    "login",        # fake login pages
    "update",       # "update your billing info"
    "confirm",      # "confirm your identity"
    "secure",       # fake "secure" portal
    "validate",     # "validate your account"
    "account",      # account management phishing
    "suspend",      # "your account will be suspended"
    "authenticate", # fake authentication pages
    "recover",      # "recover your account"
    "billing",      # billing info harvesting
    "password",     # password reset phishing
    "webscr",       # classic PayPal phishing path pattern
    "signin",       # sign-in page spoofs
)

# ---- SENSITIVE QUERY PARAMETERS --------------------------------
# Parameter names that should NEVER appear in a URL.
# Any legitimate site handles passwords server-side.
# frozenset: immutable + O(1) 'in' lookup (faster than list/tuple).

SENSITIVE_PARAMS = frozenset({
    "ssn",             # Social Security Number
    "social_security",
    "password",        # plaintext password
    "passwd",
    "pwd",
    "pin",             # bank PIN
    "creditcard",      # credit card number
    "cardnumber",
    "cvv",             # card verification value
    "cvc",
    "expiry",          # card expiry date
    "dob",             # date of birth
    "bankaccount",
})

# ---- TRACKING PARAMETERS TO STRIP ------------------------------
# Added by marketing tools -- strip before analysis to avoid
# false positives from "utm_source" being flagged as suspicious.

TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign",
    "utm_content", "utm_term", "utm_id",
    "fbclid",     # Facebook click ID
    "gclid",      # Google click ID
    "mc_eid",     # Mailchimp email ID
    "ref",        # generic referrer
    "_ga",        # Google Analytics
    "yclid",      # Yandex click ID
    "msclkid",    # Microsoft click ID
})

# ---- TRUSTED DOMAINS -------------------------------------------
# If the base domain is in this set, skip all checks -> SAFE.
# frozenset: immutable + O(1) lookup.

WHITELISTED_DOMAINS = frozenset({
    # Search
    "google.com", "google.co.uk", "bing.com", "duckduckgo.com",

    # Development
    "github.com", "gitlab.com", "stackoverflow.com", "pypi.org",
    "python.org", "docs.python.org", "npmjs.com",

    # Video / Social
    "youtube.com", "twitter.com", "linkedin.com", "reddit.com",

    # Shopping
    "amazon.com", "amazon.co.uk", "ebay.com",

    # Tech
    "microsoft.com", "apple.com", "mozilla.org", "cloudflare.com",

    # Knowledge
    "wikipedia.org",

    # News
    "bbc.com", "reuters.com", "apnews.com",
})
# ---- EMAIL PHISHING INDICATORS ---------------------------------
# Phrases found in phishing email bodies.
# Each is a known social-engineering technique.

URGENCY_PHRASES = (
    # Fear / account threat
    "your account will be suspended",
    "unusual activity detected",
    "unauthorized access",
    "security alert",
    # Pressure tactics
    "act now",
    "immediate action required",
    "click here immediately",
    "limited time offer",
    # Identity harvesting
    "verify your account",
    "confirm your identity",
    "update your billing",
    "validate your information",
    # Reward scams
    "you have won",
    "claim your prize",
    "congratulations, you",
    "selected as a winner",
    # Financial scams
    "wire transfer",
    "gift card payment",
    "bitcoin payment",
    "send money urgently",
)

# ---- REPORT FORMATTING -----------------------------------------
REPORT_WIDTH    = 58
REPORT_FILENAME = "scan_report.txt"
DATE_FORMAT     = "%Y-%m-%d %H:%M:%S"
SCORE_BAR_WIDTH = 10

print("Constants defined:")
print(f"  SCORE_WEIGHTS      : {len(SCORE_WEIGHTS)} checks")
print(f"  BAD_TLDS           : {len(BAD_TLDS)} TLDs  (tuple -- immutable)")
print(f"  TRUSTED_TLDS       : {len(TRUSTED_TLDS)} TLDs")
print(f"  FAKE_BRANDS        : {len(FAKE_BRANDS)} patterns")
print(f"  SUSPICIOUS_PATHS   : {len(SUSPICIOUS_PATHS)} keywords")
print(f"  SENSITIVE_PARAMS   : {len(SENSITIVE_PARAMS)} params  (frozenset -- immutable)")
print(f"  TRACKING_PARAMS    : {len(TRACKING_PARAMS)} params  (frozenset -- immutable)")
print(f"  WHITELISTED_DOMAINS: {len(WHITELISTED_DOMAINS)} domains  (frozenset -- immutable)")
print(f"  URGENCY_PHRASES    : {len(URGENCY_PHRASES)} phrases")
print()



print("=== LESSON 4: namedtuple ===\n")

# Define the namedtuple TYPE (like a tiny class blueprint)
# namedtuple("TypeName", ["field1", "field2", ...])
Check = namedtuple("Check", ["name", "weight", "description", "example"])

# Create instances -- immutable, named, no class overhead
CHECKS = (
    Check(
        name        = "no_https",
        weight      = 15,
        description = "Site uses HTTP instead of HTTPS",
        example     = "http://paypal.com  (note: missing S)",
    ),
    Check(
        name        = "bad_tld",
        weight      = 25,
        description = "Domain uses a high-risk free TLD",
        example     = "login.xyz  or  secure.tk",
    ),
    Check(
        name        = "fake_brand",
        weight      = 30,
        description = "Domain impersonates a known brand via typosquatting",
        example     = "paypa1.com  or  amaz0n.net",
    ),
    Check(
        name        = "suspicious_path",
        weight      = 10,
        description = "URL path contains a credential-harvesting keyword",
        example     = "/verify  /login  /confirm  /suspend",
    ),
    Check(
        name        = "ip_address",
        weight      = 20,
        description = "Domain is a raw IP address, hiding true identity",
        example     = "http://192.168.1.1/admin/login",
    ),
    Check(
        name        = "long_subdomain",
        weight      = 10,
        description = "Domain has 3 or more subdomain levels",
        example     = "login.secure.paypal.com.evil.xyz",
    ),
    Check(
        name        = "excessive_hyphens",
        weight      = 15,
        description = "Domain contains 3 or more hyphens",
        example     = "my-secure-bank-login.com",
    ),
    Check(
        name        = "query_sensitive",
        weight      = 30,
        description = "URL query string exposes sensitive parameters",
        example     = "?ssn=123-45-6789  or  ?password=abc",
    ),
    Check(
    name        = "new_domain",
    weight      = 20,
    description = "Domain registered < 30 days",
    example     = "newly-created-example.com",
    ),
)

# Access fields by NAME -- not fragile index numbers
print("CHECKS namedtuple:")
for c in CHECKS:
    print(f"  {c.name:<20} {c.weight:>3} pts  |  {c.description}")
print()

# Immutability check
print("namedtuple immutability:")
try:
    CHECKS[0].weight = 999
except AttributeError as e:
    print(f"  Cannot modify: {e}")

# _asdict() converts to a regular dict (useful for JSON export)
print(f"\nCHECKS[0]._asdict():")
for k, v in CHECKS[0]._asdict().items():
    print(f"  {k}: {v}")
print()


print("=== LESSON 5: Enum ===\n")

class Risk(Enum):
    """Risk classification levels. Use instead of raw strings."""
    SAFE       = "SAFE"
    LOW_RISK   = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING   = "PHISHING"

class Severity(Enum):
    """Severity level of each phishing check."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class RiskScore(IntEnum):
    """
    IntEnum: members ARE integers, so < > <= comparisons work directly.
    Used for score threshold checks.
    """
    SAFE_MAX       = 0
    LOW_RISK_MAX   = 30
    SUSPICIOUS_MAX = 60
    PHISHING_MIN   = 61

CHECK_SEVERITY = {
    "no_https": Severity.LOW,
    "bad_tld": Severity.MEDIUM,
    "fake_brand": Severity.HIGH,
    "suspicious_path": Severity.LOW,
    "ip_address": Severity.MEDIUM,
    "long_subdomain": Severity.LOW,
    "excessive_hyphens": Severity.MEDIUM,
    "query_sensitive": Severity.HIGH,
    "new_domain": Severity.MEDIUM,
}


# Access by name
print(f"Risk.PHISHING        = {Risk.PHISHING}")
print(f"Risk.PHISHING.value  = {Risk.PHISHING.value}")
print(f"Risk.PHISHING.name   = {Risk.PHISHING.name}")

# Access by value -- useful when you receive a string and need the Enum
parsed = Risk("SUSPICIOUS")
print(f"Risk('SUSPICIOUS')   = {parsed}")

# Iterate all members
print("\nAll Risk levels:")
for level in Risk:
    print(f"  Risk.{level.name:<12} = '{level.value}'")

# IntEnum comparison -- works like a regular int
score = 75
print(f"\nscore={score} > RiskScore.SUSPICIOUS_MAX({int(RiskScore.SUSPICIOUS_MAX)}) "
      f"-> {score > RiskScore.SUSPICIOUS_MAX}")

# Enum comparison
result_risk = Risk.PHISHING
print(f"\nresult_risk == Risk.PHISHING  -> {result_risk == Risk.PHISHING}")
print(f"result_risk == Risk.SAFE      -> {result_risk == Risk.SAFE}")
print()


print("=== LESSON 6: Config Validation ===\n")

def _validate_config():
    """
    Validates all constants. Raises ValueError if anything is wrong.
    Prefix with _ to mark as internal -- not part of the public API.
    Called once at module load time (see bottom of this section).
    """
    errors = []

    # MAX_SCORE must be within a reasonable range
    if MAX_SCORE < 50 or MAX_SCORE > 200:
     errors.append(
        f"MAX_SCORE must be between 50 and 200, got {MAX_SCORE}"
    )

    # Every weight must be a positive integer
    for check_name, weight in SCORE_WEIGHTS.items():
        if not isinstance(weight, int) or weight <= 0:
            errors.append( 
                f"SCORE_WEIGHTS['{check_name}'] must be a positive int, "
                f"got {weight!r}"
            )

    # Combined weights must be able to reach MAX_SCORE
    total_possible = sum(SCORE_WEIGHTS.values())
    if total_possible < MAX_SCORE:
        errors.append(
            f"SCORE_WEIGHTS total ({total_possible}) < MAX_SCORE ({MAX_SCORE}). "
            f"A URL can never reach a score of {MAX_SCORE}/100."
        )

    # RISK_THRESHOLDS must end at MAX_SCORE
    if RISK_THRESHOLDS[-1][0] != MAX_SCORE:
        errors.append(
            f"RISK_THRESHOLDS must end at {MAX_SCORE}, "
            f"got {RISK_THRESHOLDS[-1][0]}"
        )

    # RISK_THRESHOLDS must be in ascending order
    scores = [t[0] for t in RISK_THRESHOLDS]
    if scores != sorted(scores):
        errors.append("RISK_THRESHOLDS must be in ascending score order")

    # Every TLD in BAD_TLDS must start with a dot
    for tld in BAD_TLDS:
        if not tld.startswith("."):
            errors.append(f"BAD_TLDS entry {tld!r} must start with '.'")

    # REPORT_WIDTH must be wide enough to be readable
    if REPORT_WIDTH < 40:
        errors.append(f"REPORT_WIDTH must be >= 40, got {REPORT_WIDTH}")

    # CHECKS namedtuple names must exactly match SCORE_WEIGHTS keys
    check_names = {c.name for c in CHECKS}
    weight_keys = set(SCORE_WEIGHTS.keys())
    mismatch    = check_names.symmetric_difference(weight_keys)
    if mismatch:
        errors.append(
            f"CHECKS namedtuples and SCORE_WEIGHTS have mismatched keys: {mismatch}"
        )

    # Fail with ALL errors listed at once (not just the first one)
    if errors:
        raise ValueError(
            "config.py validation failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )

    return True


# Run at import time
try:
    _validate_config()
    print("Config validation: PASSED v")
except ValueError as e:
    print(f"Config validation: FAILED\n{e}")

print()

# Demonstrate a failing validation
print("Simulating bad config values:")
bad_weights = {"no_https": -5, "bad_tld": "twenty-five"}
bad_errors  = []
for name, w in bad_weights.items():
    if not isinstance(w, int) or w <= 0:
        bad_errors.append(f"  SCORE_WEIGHTS['{name}'] invalid: {w!r}")
for err in bad_errors:
    print(err)
print()


print("=== LESSON 7: Environment Variable Overrides ===\n")

ENV_REPORT_WIDTH = int(os.environ.get("PHISH_REPORT_WIDTH", str(REPORT_WIDTH)))

_debug_env = os.environ.get("PHISH_DEBUG", "false").lower()
ENV_DEBUG = _debug_env in ("1", "true", "yes")

ENV_REPORT_FILENAME = os.environ.get("PHISH_REPORT_FILE", REPORT_FILENAME)

ENV_MAX_SCORE = MAX_SCORE

from_env = lambda key: "from env" if key in os.environ else "default"

print(f"  REPORT_WIDTH    : {ENV_REPORT_WIDTH}  ({from_env('PHISH_REPORT_WIDTH')})")
print(f"  DEBUG_MODE      : {ENV_DEBUG}  ({from_env('PHISH_DEBUG')})")
print(f"  REPORT_FILENAME : {ENV_REPORT_FILENAME}  ({from_env('PHISH_REPORT_FILE')})")
print(f"  MAX_SCORE       : {ENV_MAX_SCORE}  ({from_env('PHISH_MAX_SCORE')})")


print("=== LESSON 8: __all__ ===\n")

__all__ = [
    # Scoring
    "SCORE_WEIGHTS",
    "RISK_THRESHOLDS",
    "MAX_SCORE",
    # Detection lists
    "BAD_TLDS",
    "TRUSTED_TLDS",
    "FAKE_BRANDS",
    "SUSPICIOUS_PATHS",
    "SENSITIVE_PARAMS",
    "TRACKING_PARAMS",
    "WHITELISTED_DOMAINS",
    "URGENCY_PHRASES",
    # Structured constants
    "CHECKS",
    "Check",
    "Risk",
    "RiskScore",
    # Formatting
    "REPORT_WIDTH",
    "REPORT_FILENAME",
    "DATE_FORMAT",
    "SCORE_BAR_WIDTH",
    # Environment-aware
    "ENV_REPORT_WIDTH",
    "ENV_DEBUG",
    "ENV_REPORT_FILENAME",
    "Severity",
    "CHECK_SEVERITY",
]

print(f"Public names in __all__ : {len(__all__)}")
print("Internal (not exported) :")
print("  _validate_config()   <- runs at import, not for callers to use")
print("  _debug_env           <- raw env string before bool conversion")
print("  from_env             <- lambda used only for demo printing")
print()


if __name__ == "__main__":

    print("=" * 58)
    print("  DAY 6 -- config.py Demo")
    print("=" * 58)
    print()

    # Score weights breakdown
    print("SCORE_WEIGHTS breakdown:")
    total = sum(SCORE_WEIGHTS.values())
    for name, weight in sorted(SCORE_WEIGHTS.items(), key=lambda x: x[1], reverse=True):
        bar = "X" * (weight // 3)
        print(f"  {name:<20} {weight:>3} pts  {bar}")
    print(f"  {'---'*15}")
    print(f"  {'TOTAL POSSIBLE':<20} {total:>3} pts  (capped at {MAX_SCORE})")
    print()

    # Risk thresholds table
    print("RISK_THRESHOLDS:")
    for max_score, label in RISK_THRESHOLDS:
        print(f"  score <= {max_score:>3}  ->  {label}")
    print()

    # BAD_TLDS
    print(f"BAD_TLDS ({len(BAD_TLDS)} entries, immutable tuple):")
    print("  " + "  ".join(BAD_TLDS))
    print()

    # SENSITIVE_PARAMS
    print(f"SENSITIVE_PARAMS (frozenset, O(1) lookup):")
    print("  " + "  ".join(sorted(SENSITIVE_PARAMS)))
    print()

    # CHECKS namedtuple
    print("CHECKS namedtuple -- structured, named, immutable:")
    for c in CHECKS:
        print(f"  {c.name:<20} {c.weight:>3} pts  | {c.example}")
    print()

    # Enum
    print("Risk Enum:")
    for r in Risk:
        print(f"  Risk.{r.name:<12} = '{r.value}'")
    print()

    # Type summary
    print("Type summary -- list vs tuple vs frozenset:")
    print(f"  list      : mutable, ordered, allows duplicates")
    print(f"  tuple     : IMMUTABLE, ordered, allows duplicates  <- use for constants")
    print(f"  frozenset : IMMUTABLE, unordered, no duplicates, O(1) 'in'  <- use for lookups")
    print()

    if __name__ == "__main__":

    # ...lots of print statements...

    # Validation
        print("Re-running _validate_config()...")

    try:
        passed = _validate_config()
        print(f"  Result: {'PASSED' if passed else 'FAILED'}")
    except ValueError as e:
        print("  Result: FAILED")
        print(e)

    print()