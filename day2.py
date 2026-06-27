

from urllib.parse import urlparse, parse_qs



print("=== LESSON 1: Basic URL Parsing ===")

url = "https://www.paypal.com/login?user=john&next=home"

parsed = urlparse(url)

print(f"Full URL  : {url}")
print(f"Scheme    : {parsed.scheme}")    # https
print(f"Domain    : {parsed.netloc}")    # www.paypal.com
print(f"Path      : {parsed.path}")      # /login
print(f"Query     : {parsed.query}")     # user=john&next=home
print(f"Params    : {parse_qs(parsed.query)}")  # {'user': ['john'], 'next': ['home']}
print()



print("=== LESSON 2: Scheme Check ===")

def check_scheme(url):
    parsed = urlparse(url)
    scheme = parsed.scheme

    print(f"Scheme: {scheme}")

    if scheme == "https":
        print("Secure connection (HTTPS)")
    elif scheme == "http":
        print("Not secure — no encryption!")
    else:
        print("Unknown scheme — suspicious!")

check_scheme("https://google.com")
check_scheme("http://paypa1.xyz")
print()



print("=== LESSON 3: Domain Check ===")

# Suspicious TLDs commonly used in phishing
BAD_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf",
            ".top", ".click", ".download", ".win", ".zip", ".gq", ".work"]

# Known brands that phishers try to copy
FAKE_BRANDS = ["paypa1", "amaz0n", "g00gle", "faceb00k",
               "micros0ft", "app1e", "netf1ix", "inst4gram"]

def check_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    print(f"Domain: {domain}")

    # Check 1: Domain length
    if len(domain) > 30:
        print("Very long domain — suspicious!")

    # Check 2: Too many hyphens
    if domain.count("-") >= 2:
        print("Too many hyphens — common phishing trick!")

    # Check 3: Too many dots (subdomain abuse)
    if domain.count(".") > 3:
        print("Too many dots (subdomains) — suspicious!")

    # Check 4: Suspicious TLD
    for tld in BAD_TLDS:
        if domain.endswith(tld):
            print(f"Suspicious TLD detected: '{tld}'")

    # Check 5: Fake brand name
    for brand in FAKE_BRANDS:
        if brand in domain:
            print(f"Fake brand detected: '{brand}'")

    # Check 6: IP address instead of domain
    parts = domain.split(".")
    if all(p.isdigit() for p in parts):
        print("IP address used instead of domain name!")

check_domain("https://paypal.secure-login.xyz")
print()
check_domain("https://google.com")
print()
check_domain("http://192.168.1.1")
print()



print("=== LESSON 4: Path Check ===")

SUSPICIOUS_PATH_WORDS = [
    "verify", "login", "update", "confirm",
    "secure", "account", "password", "signin"
]

def check_path(url):
    parsed = urlparse(url)
    path = parsed.path.lower()

    print(f"Path: {path}")

    found = []
    for word in SUSPICIOUS_PATH_WORDS:
        if word in path:
            found.append(word)

    if found:
        for w in found:
            print(f"Suspicious word in path: '{w}'")
    else:
        print("Path looks normal")

check_path("http://paypa1.com/verify/account/now")
print()
check_path("https://amazon.com/products/books")
print()



print("=== LESSON 5: Query Params Check ===")

SENSITIVE_PARAMS = [
    "password", "pwd", "pass", "ssn",
    "card", "token", "secret", "pin", "cvv"
]

def check_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    print(f"Query : {parsed.query}")
    print(f"Params: {params}")

    for key in params:
        if key.lower() in SENSITIVE_PARAMS:
            print(f"Sensitive data exposed in URL: '{key}'")

    if not params:
        print("No query parameters")

check_params("http://evil.com/login?password=1234&user=john")
print()
check_params("https://google.com/search?q=python+tutorial")
print()



print("=== LESSON 6: Full URL Analyzer ===")

def analyze_url(url):
    print("=" * 50)
    print(f"Analyzing: {url}")
    print("=" * 50)

    warnings = 0
    parsed = urlparse(url)

    # --- Scheme ---
    if parsed.scheme != "https":
        print("[SCHEME] Not using HTTPS")
        warnings += 1
    else:
        print("[SCHEME] HTTPS detected")

    # --- Domain ---
    domain = parsed.netloc.lower()
    for tld in BAD_TLDS:
        if domain.endswith(tld):
            print(f"[DOMAIN] Suspicious TLD: {tld}")
            warnings += 1
    for brand in FAKE_BRANDS:
        if brand in domain:
            print(f"[DOMAIN] Fake brand: {brand}")
            warnings += 1
    if domain.count("-") >= 2:
        print("[DOMAIN] Too many hyphens")
        warnings += 1

    # --- Path ---
    path = parsed.path.lower()
    for word in SUSPICIOUS_PATH_WORDS:
        if word in path:
            print(f"[PATH] Suspicious word: '{word}'")
            warnings += 1

    # --- Params ---
    params = parse_qs(parsed.query)
    for key in params:
        if key.lower() in SENSITIVE_PARAMS:
            print(f"[PARAMS] Sensitive key: '{key}'")
            warnings += 1

    # --- Final Score ---
    score=warnings*20

    print()
    print(f"Risk Score: {score}/100")

    if score == 0:
     print("RESULT: SAFE")
    elif score <= 40:
     print("RESULT: LOW RISK")
    else:
     print("RESULT: HIGH RISK")

print()


print("=== LESSON 7: Parsing 10 URLs ===")

urls = [
    "https://www.google.com/search?q=python",
    "http://paypa1.secure-login.xyz/verify",
    "https://amazon.com/products?id=123&cat=books",
    "http://192.168.1.1/admin/login",
    "https://facebook.com/profile?id=456",
    "http://free-prize.win/claim?user=you&reward=cash",
    "https://github.com/user/phishing-detector",
    "http://micros0ft-update.tk/download?file=patch",
    "https://youtube.com/watch?v=abc123",
    "http://bank-secure-login.xyz/update?ssn=123&pin=456",
]

for url in urls:
    analyze_url(url)
    
    print("=== LESSON 8: Testing New Suspicious TLDs ===")

check_domain("https://secure-bank.zip/login")
print()

check_domain("http://paypal-login.gq/verify")
print()

check_domain("https://amazon-support.work/update")
print()

check_domain("https://google.com")
print()

print("=== LESSON 9: Subdomain Abuse Check ===")

check_domain("https://evil.sub.sub.paypal.com/login")
print()

check_domain("https://www.google.com")
print()

print("=== LESSON 10: Domain Length Check ===")

def get_domain_age_warning(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    print(f"Domain: {domain}")

    if len(domain) < 4:
        print("Warning: Domain is too short!")
    elif len(domain) > 40:
        print("Warning: Domain is too long!")
    else:
        print("Domain length looks normal()")


# Test code (outside the function)

get_domain_age_warning("https://abc.com")
print()

get_domain_age_warning("https://go.com")
print()

get_domain_age_warning("https://this-is-a-very-long-domain-name-for-phishing-example.xyz")
print()


print("=== LESSON 11: Testing 5 Example Phishing URLs ===")

# Example 1
# Suspicious because it uses HTTP, a fake brand name, a suspicious TLD,
# and the path contains "verify".
analyze_url("http://paypa1-login.xyz/verify")
print()

# Example 2
# Suspicious because it uses HTTP and contains sensitive query parameters.
analyze_url("http://secure-bank.top/login?password=1234")
print()

# Example 3
# Suspicious because it uses an IP address instead of a domain name
# and the path contains "admin" and "login".
analyze_url("http://192.168.1.100/admin/login")
print()

# Example 4
# Suspicious because the domain has many hyphens and a suspicious TLD.
analyze_url("https://amazon-secure-update.click/account")
print()

# Example 5
# Suspicious because the domain has many subdomains and the path
# contains "confirm".
analyze_url("https://evil.sub.sub.paypal.com/confirm")
print()