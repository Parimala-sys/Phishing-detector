print("=== LESSON 1: Dictionaries ===")

# A dictionary stores KEY → VALUE pairs
# Like a real dictionary: word → definition

person = {
    "name": "David",
    "age": 25,
    "city": "Hyderabad"
}

print(person["name"])        # Access by key → David
print(person.get("age"))     # Safer access → 25
print(person.get("phone", "Not found"))  # Default if missing

# Add / update
person["email"] = "David@email.com"
person["age"] = 26
print(person)

# Loop through a dictionary
print("\nAll person data:")
for key, value in person.items():
    print(f"  {key}: {value}")

print()


print(" LESSON 2: Nested Dictionaries ")

# Dictionaries can contain other dictionaries — great for scan results!

scan_result = {
    "url": "http://paypa1.secure-login.xyz/verify",
    "score": 85,
    "risk": "PHISHING",
    "checks": {
        "no_https": True,
        "bad_tld": True,
        "fake_brand": True,
        "suspicious_path": True,
        "ip_address": False
    },
    "reasons": ["No HTTPS", "Bad TLD: .xyz", "Fake brand: paypa1", "Suspicious path: verify"]
}

print(f"URL   : {scan_result['url']}")
print(f"Score : {scan_result['score']}/100")
print(f"Risk  : {scan_result['risk']}")
print(f"Checks passed:")
for check, triggered in scan_result["checks"].items():
    status = "YES" if triggered else "NO"
    print(f"  {check}: {status}")

print()


print(" LESSON 3: Score-Based Detection ")

# Instead of counting reasons, each check has a WEIGHT (point value).
# A score from 0–100 tells us exactly HOW suspicious a URL is.

from urllib.parse import urlparse

# Each check name → how many points it adds to the risk score
SCORE_WEIGHTS = {
    "no_https":         15,   # not using secure connection
    "bad_tld":          25,   # dangerous domain extension
    "fake_brand":       30,   # pretending to be a real company
    "suspicious_path":  10,   # path contains risky words
    "ip_address":       20,   # using raw IP instead of domain name
    "long_subdomain":   10,   # e.g. login.verify.secure.paypal.com
    "query_ssn":        30,   # asking for SSN in URL params
    "query_password":   20,   # asking for password in URL params
    "excessive_hyphens": 15,   # domain contains too many hyphens   
}

BAD_TLDS       = [".xyz", ".tk", ".ml", ".win", ".top", ".click", ".gq", ".cf"]
FAKE_BRANDS    = ["paypa1", "amaz0n", "g00gle", "micros0ft", "app1e", "faceb00k"]
SUSPICIOUS_PATHS = ["verify", "login", "update", "confirm", "secure", "validate"]
SENSITIVE_PARAMS = {"ssn", "password", "passwd", "pwd", "social_security"}


def score_url(url):
    """
    Analyzes a URL and returns a result dictionary with:
    - score   : 0 (safe) to 100+ (dangerous)
    - risk    : SAFE / SUSPICIOUS / PHISHING
    - checks  : which checks triggered
    - reasons : human-readable explanation for each triggered check
    """
    url = url.strip()
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path.lower()
    query  = parsed.query.lower()

    triggered_checks = {}   # check_name → True/False
    reasons = []
    total_score = 0

    # --- Check 1: No HTTPS ---
    flag = parsed.scheme != "https"
    triggered_checks["no_https"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["no_https"]
        reasons.append("Uses HTTP instead of HTTPS (insecure connection)")

    # --- Check 2: Suspicious TLD ---
    flag = any(domain.endswith(tld) for tld in BAD_TLDS)
    triggered_checks["bad_tld"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["bad_tld"]
        matched = next(tld for tld in BAD_TLDS if domain.endswith(tld))
        reasons.append(f"High-risk domain extension: {matched}")

    # --- Check 3: Fake brand in domain ---
    flag = any(brand in domain for brand in FAKE_BRANDS)
    triggered_checks["fake_brand"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["fake_brand"]
        matched = next(brand for brand in FAKE_BRANDS if brand in domain)
        reasons.append(f"Impersonates a known brand: '{matched}'")

    # --- Check 4: Suspicious words in path ---
    flag = any(word in path for word in SUSPICIOUS_PATHS)
    triggered_checks["suspicious_path"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["suspicious_path"]
        matched = next(word for word in SUSPICIOUS_PATHS if word in path)
        reasons.append(f"Suspicious path keyword: '/{matched}'")

    # --- Check 5: IP address used as domain ---
    parts = domain.replace(":", "").split(".")
    flag = sum(1 for p in parts if p.isdigit()) >= 3
    triggered_checks["ip_address"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["ip_address"]
        reasons.append("Domain is a raw IP address (hides real identity)")

    # --- Check 6: Too many subdomains (long subdomain trick) ---
    subdomain_count = domain.count(".")
    flag = subdomain_count >= 3
    triggered_checks["long_subdomain"] = flag
    if flag:
        total_score += SCORE_WEIGHTS["long_subdomain"]
        reasons.append(f"Unusually long subdomain chain ({subdomain_count} dots)")

        # --- Check 7: Excessive hyphens in domain ---
    hyphen_count = domain.count("-")
    flag = hyphen_count >= 3
    triggered_checks["excessive_hyphens"] = flag

    if flag:
        total_score += SCORE_WEIGHTS["excessive_hyphens"]
        reasons.append(
            f"Domain contains excessive hyphens ({hyphen_count} hyphens)"
        )

    # --- Check 8: Sensitive data in query string ---
    query_params = set(query.replace("=", "&").split("&"))
    ssn_flag = bool(SENSITIVE_PARAMS & query_params)
    triggered_checks["query_ssn"] = ssn_flag
    if ssn_flag:
        total_score += SCORE_WEIGHTS["query_ssn"]
        reasons.append("URL contains sensitive parameter (SSN or password)")

    pwd_flag = any(p in query for p in ["password", "passwd", "pwd"])
    triggered_checks["query_password"] = pwd_flag
    if pwd_flag and not ssn_flag:   # avoid double-counting
        total_score += SCORE_WEIGHTS["query_password"]
        reasons.append("URL passes password in plain text")

    # Cap score at 100
    total_score = min(total_score, 100)

    # Determine risk label from score
    if total_score == 0:
        risk = "SAFE"
    elif total_score <= 30:
        risk = "LOW RISK"
    elif total_score <= 60:
        risk = "SUSPICIOUS"
    else:
        risk = "PHISHING"

    return {
        "url":     url,
        "score":   total_score,
        "risk":    risk,
        "checks":  triggered_checks,
        "reasons": reasons
    }


# --- Quick test ---
test_urls = [
    "https://www.google.com/search?q=python",
    "http://paypa1.secure-login.xyz/verify",
    "http://192.168.1.1/admin/login",
    "https://amazon.com/products?id=123",
    "http://bank-update.tk/confirm?ssn=123-45-6789",
    "https://my-secure-bank-login.com/account",
]

print("Testing score_url() on 5 URLs:\n")
for u in test_urls:
    r = score_url(u)
    bar = "█" * (r["score"] // 10) + "░" * (10 - r["score"] // 10)
    print(f"  {r['risk']:<12} [{bar}] {r['score']:>3}/100  →  {r['url'][:50]}")

print()


print("LESSON 4: Lists of Dictionaries")

# Store many scan results in a LIST of dictionaries — like a database table.

from datetime import datetime

def scan_many(urls):
    """Scans a list of URLs and returns a list of result dictionaries."""
    results = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for url in urls:
        url = url.strip()
        if url:
            result = score_url(url)
            result["scanned_at"] = timestamp   # add timestamp to each result
            results.append(result)

    return results


sample_urls = [
    "https://www.google.com/search?q=python",
    "http://paypa1.secure-login.xyz/verify",
    "https://amazon.com/products?id=123",
    "http://192.168.1.1/admin/login",
    "https://github.com/user/phishing-detector",
    "http://free-prize.win/claim?user=you",
    "https://youtube.com/watch?v=abc123",
    "http://micros0ft-update.tk/download",
    "https://facebook.com/profile?id=456",
    "http://bank-secure-login.xyz/update?ssn=123",
]

all_results = scan_many(sample_urls)

print(f"Scanned {len(all_results)} URLs at {all_results[0]['scanned_at']}\n")
for r in all_results:
    print(f"  Score {r['score']:>3}/100  {r['risk']:<12}  {r['url'][:50]}")

print()


print(" LESSON 5: Filtering & Sorting Results ")

# Filter: only keep dangerous ones
dangerous = [r for r in all_results if r["score"] >= 60]
print(f"Dangerous URLs ({len(dangerous)} found):")
for r in dangerous:
    print(f"  {r['score']}/100 → {r['url']}")

print()

# Sort: highest score first (most dangerous at top)
sorted_results = sorted(all_results, key=lambda r: r["score"], reverse=True)
print("All results sorted by risk (highest first):")
for r in sorted_results:
    print(f"  {r['score']:>3}/100  {r['risk']:<12}  {r['url'][:50]}")

print()

# Group results by risk level
grouped = {
    "SAFE": [],
    "LOW RISK": [],
    "SUSPICIOUS": [],
    "PHISHING": []
}

for result in all_results:
    grouped[result["risk"]].append(result)

print("\n GROUPED RESULTS ")
for risk, urls in grouped.items():
    print(f"{risk}: {len(urls)} URL(s)")

    print("\nSCORE HISTOGRAM")

histogram = {
    "0-20": 0,
    "21-40": 0,
    "41-60": 0,
    "61-80": 0,
    "81-100": 0
}

for result in all_results:
    score = result["score"]

    if score <= 20:
        histogram["0-20"] += 1
    elif score <= 40:
        histogram["21-40"] += 1
    elif score <= 60:
        histogram["41-60"] += 1
    elif score <= 80:
        histogram["61-80"] += 1
    else:
        histogram["81-100"] += 1

for score_range, count in histogram.items():
    bar = "█" * count
    print(f"{score_range:<7}: {bar} ({count})")

print()

print("\n TOP 3 MOST DANGEROUS URLS ")

top_three = sorted(all_results, key=lambda r: r["score"], reverse=True)[:3]

for i, result in enumerate(top_three, start=1):
    print(f"\n#{i}")
    print(f"URL   : {result['url']}")
    print(f"Score : {result['score']}/100")
    print(f"Risk  : {result['risk']}")
    print("Reasons:")

    for reason in result["reasons"]:
        print(f"  • {reason}")

print(" LESSON 6: Generating a Summary Report ")

def generate_report(results):
    """
    Takes a list of scan result dicts and prints a full summary report.
    Also RETURNS a stats dictionary for further use.
    """
    total   = len(results)
    safe    = sum(1 for r in results if r["risk"] == "SAFE")
    low     = sum(1 for r in results if r["risk"] == "LOW RISK")
    suspicious = sum(1 for r in results if r["risk"] == "SUSPICIOUS")
    phishing   = sum(1 for r in results if r["risk"] == "PHISHING")
    avg_score  = sum(r["score"] for r in results) / total if total else 0

    print("=" * 56)
    print("        PHISHING DETECTOR — SCAN REPORT")
    print("=" * 56)
    print(f"  Scanned at : {results[0]['scanned_at']}")
    print(f"  Total URLs : {total}")
    print(f"  Avg Score  : {avg_score:.1f}/100")
    print("-" * 56)
    print(f"  SAFE        : {safe}")
    print(f"  LOW RISK    : {low}")
    print(f"  SUSPICIOUS  : {suspicious}")
    print(f"  PHISHING    : {phishing}")
    print("=" * 56)

    if phishing > 0:
        print("\n  HIGH-RISK URLS:")
        for r in results:
            if r["risk"] == "PHISHING":
                print(f"    Score {r['score']}/100 → {r['url']}")
                for reason in r["reasons"]:
                    print(f"           • {reason}")
    print()

    return {
        "total": total,
        "safe": safe,
        "low_risk": low,
        "suspicious": suspicious,
        "phishing": phishing,
        "avg_score": round(avg_score, 1)
    }


stats = generate_report(all_results)
print(f"Stats dictionary returned: {stats}")
print()

# Find the safest URL (lowest score)
safest = min(all_results, key=lambda result: result["score"])

print(f"Safest URL: {safest['url']} with score {safest['score']}/100")


print(" LESSON 7: Save Report to File ")

def save_report(results, filename="day4_report.txt"):
    """Writes the full scan report to a text file."""
    with open(filename, "w") as f:
        total     = len(results)
        avg_score = sum(r["score"] for r in results) / total if total else 0

        f.write("PHISHING DETECTOR - SCAN REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Scanned at : {results[0]['scanned_at']}\n")
        f.write(f"Total URLs : {total}\n")
        f.write(f"Avg Score  : {avg_score:.1f}/100\n")
        f.write("=" * 50 + "\n\n")

        for r in sorted(results, key=lambda x: x["score"], reverse=True):
            f.write(f"URL    : {r['url']}\n")
            f.write(f"Score  : {r['score']}/100\n")
            f.write(f"Risk   : {r['risk']}\n")
            if r["reasons"]:
                f.write(f"Reasons:\n")
                for reason in r["reasons"]:
                    f.write(f"  - {reason}\n")
            f.write("-" * 50 + "\n")

    print(f"Report saved to '{filename}'!")


save_report(all_results)
print()

