

print(" LESSON 1: What Is a Class? ")

# So far we've written FUNCTIONS and stored data in DICTIONARIES.
# As programs grow, this gets messy:
#   - score_url() needs SCORE_WEIGHTS, BAD_TLDS, etc.
#   - scan_many() needs score_url()
#   - generate_report() needs scan_many()'s output
#   - All these pieces are scattered around the file.
#
# A CLASS bundles RELATED DATA + FUNCTIONS into one object.
# Think of it like a blueprint for a machine:
#   - The machine has SETTINGS  → these become attributes (self.xxx)
#   - The machine has BUTTONS   → these become methods (def do_thing(self))
#   - You can build many machines from one blueprint → multiple instances

# Simple example first:

class Dog:
    # __init__ runs automatically when you create a new Dog
    # 'self' always refers to THIS specific dog object
    def __init__(self, name, breed):
        self.name  = name    # store data ON the object
        self.breed = breed
        self.tricks = []     # each dog has its own empty list

    def learn_trick(self, trick):
        self.tricks.append(trick)
        print(f"{self.name} learned: {trick}")

    def show_tricks(self):
        if self.tricks:
            print(f"{self.name}'s tricks: {', '.join(self.tricks)}")
        else:
            print(f"{self.name} knows no tricks yet.")

    def describe(self):
        print(f"Dog: {self.name} ({self.breed}), {len(self.tricks)} tricks")


# Create two SEPARATE Dog objects from the same blueprint
rex   = Dog("Rex",   "German Shepherd")
buddy = Dog("Buddy", "Labrador")

rex.learn_trick("sit")
rex.learn_trick("roll over")
buddy.learn_trick("fetch")

rex.show_tricks()     # Rex's tricks: sit, roll over
buddy.show_tricks()   # Buddy's tricks: fetch  (separate from Rex!)
rex.describe()

print()


print(" LESSON 2: Why Classes Beat Loose Functions ")

# With plain functions (Day 4 style):
#   score_url(url)          ← needs BAD_TLDS from global scope
#   scan_many(urls)         ← calls score_url(), needs SCORE_WEIGHTS
#   generate_report(results)← separate function, no connection to scanner
#
# Problem: want to use different BAD_TLDS for different scans? Hard.
#          want to remember past results between calls?         Hard.
#          want to hand the whole scanner to someone else?      Messy.
#
# With a class:
#   detector = PhishingDetector()
#   detector.scan("http://evil.xyz")
#   detector.report()
#   # All settings, history, and logic live INSIDE detector.
#
# You get: encapsulation, reusability, and clean state management.

print("(explanation printed — now let's build the real class)\n")


print(" LESSON 3: Building the PhishingDetector Class ")

from urllib.parse import urlparse
from datetime import datetime


class PhishingDetector:
    """
    A complete URL phishing detection system.

    Usage:
        detector = PhishingDetector()
        result   = detector.scan("http://paypa1.xyz/verify")
        detector.report()
        detector.save("results.txt")
    """

    # Class-level constants (shared by ALL instances)
    # Put them here so every detector starts with the same defaults,
    # but an instance can override them after creation.

    DEFAULT_WEIGHTS = {
        "no_https":         15,
        "bad_tld":          25,
        "fake_brand":       30,
        "suspicious_path":  10,
        "ip_address":       20,
        "long_subdomain":   10,
        "excessive_hyphens":15,
        "query_sensitive":  30,
    }

    DEFAULT_BAD_TLDS = [
        ".xyz", ".tk", ".ml", ".win", ".top",
        ".click", ".gq", ".cf", ".pw", ".buzz"
    ]

    DEFAULT_FAKE_BRANDS = [
        "paypa1", "amaz0n", "g00gle", "micros0ft",
        "app1e", "faceb00k", "netfl1x", "inst4gram"
    ]

    DEFAULT_SUSPICIOUS_PATHS = [
        "verify", "login", "update", "confirm",
        "secure", "validate", "account", "suspend"
    ]

    DEFAULT_SENSITIVE_PARAMS = {
        "ssn", "password", "passwd", "pwd",
        "social_security", "creditcard", "cvv"
    }

    # Constructor
    def __init__(self, name="PhishingDetector v1"):
        """
        Called automatically when you do: detector = PhishingDetector()
        Sets up instance attributes — data that belongs to THIS detector.
        """
        self.name     = name
        self.history  = []           # list of all scan result dicts
        self.created  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Copy class defaults onto the instance so they can be customised
        self.weights          = dict(self.DEFAULT_WEIGHTS)
        self.bad_tlds         = list(self.DEFAULT_BAD_TLDS)
        self.fake_brands      = list(self.DEFAULT_FAKE_BRANDS)
        self.suspicious_paths = list(self.DEFAULT_SUSPICIOUS_PATHS)
        self.sensitive_params = set(self.DEFAULT_SENSITIVE_PARAMS)

        print(f"[{self.name}] Ready. Created at {self.created}")

    # Private helper (convention: leading underscore = internal use) 
    def _classify(self, score):
        """Converts a numeric score into a risk label."""
        if score == 0:   return "SAFE"
        if score <= 30:  return "LOW RISK"
        if score <= 60:  return "SUSPICIOUS"
        return "PHISHING"

    # Core scan method
    def scan(self, url):
        """
        Scans a single URL.
        Stores the result in self.history and returns it.
        """
        url    = url.strip()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()

        reasons = []
        score   = 0

        # Check 1: No HTTPS
        if parsed.scheme != "https":
            score += self.weights["no_https"]
            reasons.append("Uses HTTP instead of HTTPS")

        # Check 2: Bad TLD
        for tld in self.bad_tlds:
            if domain.endswith(tld):
                score += self.weights["bad_tld"]
                reasons.append(f"High-risk TLD: {tld}")
                break

        # Check 3: Fake brand
        for brand in self.fake_brands:
            if brand in domain:
                score += self.weights["fake_brand"]
                reasons.append(f"Impersonates brand: '{brand}'")
                break

        # Check 4: Suspicious path keyword
        for word in self.suspicious_paths:
            if word in path:
                score += self.weights["suspicious_path"]
                reasons.append(f"Suspicious path keyword: '{word}'")
                break

        # Check 5: IP address as domain
        parts = domain.replace(":", "").split(".")
        if sum(1 for p in parts if p.isdigit()) >= 3:
            score += self.weights["ip_address"]
            reasons.append("Raw IP address used as domain")

        # Check 6: Long subdomain chain
        if domain.count(".") >= 3:
            score += self.weights["long_subdomain"]
            reasons.append(f"Long subdomain chain ({domain.count('.')} dots)")

        # Check 7: Excessive hyphens in domain
        if domain.count("-") >= 3:
            score += self.weights["excessive_hyphens"]
            reasons.append(f"Excessive hyphens in domain ({domain.count('-')})")

        # Check 8: Sensitive parameters in query string
        params = set(query.replace("=", "&").split("&"))
        if self.sensitive_params & params:
            score += self.weights["query_sensitive"]
            reasons.append("Sensitive data in URL query string")

        score  = min(score, 100)
        result = {
            "url":        url,
            "score":      score,
            "risk":       self._classify(score),
            "reasons":    reasons,
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        self.history.append(result)   # remember every scan
        return result

    # Batch scan
    def scan_file(self, filepath):
        """
        Reads URLs from a text file (one per line) and scans each one.
        Returns the list of results for this batch.
        """
        batch = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    url = line.strip()
                    if url:
                        batch.append(self.scan(url))
            print(f"[{self.name}] Scanned {len(batch)} URLs from '{filepath}'")
        except FileNotFoundError:
            print(f"[{self.name}] ERROR: File '{filepath}' not found.")
        return batch

    # Stats property
    def stats(self):
        """
        Returns a summary dictionary of all scans done so far.
        Called as: detector.stats()  ← note: no arguments needed
        """
        if not self.history:
            return {"total": 0}

        total = len(self.history)
        return {
            "total":      total,
            "safe":       sum(1 for r in self.history if r["risk"] == "SAFE"),
            "low_risk":   sum(1 for r in self.history if r["risk"] == "LOW RISK"),
            "suspicious": sum(1 for r in self.history if r["risk"] == "SUSPICIOUS"),
            "phishing":   sum(1 for r in self.history if r["risk"] == "PHISHING"),
            "avg_score":  round(sum(r["score"] for r in self.history) / total, 1),
            "highest":    max(self.history, key=lambda r: r["score"]),
            "lowest":     min(self.history, key=lambda r: r["score"]),
        }
    class PhishingDetector:

         def stats(self):
          ...
          return {
            ...
        }

    # <-- ADD THE NEW METHOD HERE
    def top(self, n):
        """
        Returns the top n most dangerous URLs from history.
        Example:
            detector.top(3)
        """
        if not self.history:
            return []

        return sorted(
            self.history,
            key=lambda result: result["score"],
            reverse=True
        )[:n]

    # Existing report method
    def search(self, keyword):
     """
    Searches scan history for URLs containing the keyword.
    Example:
        detector.search("paypal")
    """
     keyword = keyword.lower()

     return [
        result
        for result in self.history
        if keyword in result["url"].lower()
    ]

    # Report
    def report(self):
        """Prints a formatted summary of all scans in history."""
        s = self.stats()
        if s["total"] == 0:
            print("No scans yet. Run detector.scan(url) first.")
            return

        print("=" * 58)
        print(f"  {self.name.upper()} SCAN REPORT")
        print("=" * 58)
        print(f"  Total scanned : {s['total']}")
        print(f"  Average score : {s['avg_score']}/100")
        print(f"  Most dangerous: {s['highest']['url'][:45]}  ({s['highest']['score']}/100)")
        print("-" * 58)
        print(f"    SAFE        : {s['safe']}")
        print(f"    LOW RISK    : {s['low_risk']}")
        print(f"    SUSPICIOUS  : {s['suspicious']}")
        print(f"    PHISHING    : {s['phishing']}")
        print("=" * 58)

        # Show details for all phishing URLs
        phishing_urls = [r for r in self.history if r["risk"] == "PHISHING"]
        if phishing_urls:
            print("\n  PHISHING URLS DETECTED:")
            for r in phishing_urls:
                print(f"\n    {r['score']}/100 → {r['url']}")
                for reason in r["reasons"]:
                    print(f"           • {reason}")
        print()

    #  Save to file
    def save(self, filename="results.txt"):
        """Saves the full history to a text file, sorted by score."""
        if not self.history:
            print("Nothing to save.")
            return

        with open(filename, "w") as f:
            s = self.stats()
            f.write(f"PHISHING DETECTOR REPORT\n")
            f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total URLs: {s['total']}  |  Avg Score: {s['avg_score']}/100\n")
            f.write("=" * 52 + "\n\n")

            for r in sorted(self.history, key=lambda x: x["score"], reverse=True):
                f.write(f"URL    : {r['url']}\n")
                f.write(f"Score  : {r['score']}/100  ({r['risk']})\n")
                if r["reasons"]:
                    for reason in r["reasons"]:
                        f.write(f"       - {reason}\n")
                f.write("-" * 52 + "\n")

        print(f"[{self.name}] Report saved to '{filename}'")

    # Allow customisation
    def add_bad_tld(self, tld):
        """Add a new TLD to watch for. e.g. detector.add_bad_tld('.scam')"""
        if not tld.startswith("."):
            tld = "." + tld
        self.bad_tlds.append(tld)
        print(f"[{self.name}] Added bad TLD: {tld}")

    def add_fake_brand(self, brand):
        """Add a new fake brand pattern. e.g. detector.add_fake_brand('tw1tter')"""
        self.fake_brands.append(brand.lower())
        print(f"[{self.name}] Added fake brand: {brand}")

    def clear_history(self):
        """Wipe all past scan results."""
        count = len(self.history)
        self.history = []
        print(f"[{self.name}] Cleared {count} results from history.")

    # __str__: what prints when you do print(detector)
    def __str__(self):
        return (f"<PhishingDetector name='{self.name}' "
                f"scans={len(self.history)} "
                f"tlds={len(self.bad_tlds)} brands={len(self.fake_brands)}>")
    
    def __len__(self):
        return len(self.history)
    
    
print()


print(" LESSON 4: Using the Class ")

# Create an instance — this calls __init__ automatically
detector = PhishingDetector()
print(detector)   # calls __str__
print()

# Scan individual URLs — result is returned AND saved to history
urls_to_test = [
    "https://www.google.com/search?q=python",
    "http://paypa1.secure-login.xyz/verify",
    "https://amazon.com/products?id=123",
    "http://192.168.1.1/admin/login",
    "https://github.com/user/phishing-detector",
    "http://free-prize.win/claim?user=you",
    "https://youtube.com/watch?v=abc123",
    "http://micros0ft-update.tk/download",
    "http://my-secure-bank-login-update.com/confirm?ssn=123",
]

print("Scanning URLs...\n")
for url in urls_to_test:
    r = detector.scan(url)
    bar = "█" * (r["score"] // 10) + "░" * (10 - r["score"] // 10)
    print(f"  {r['risk']:<12} [{bar}] {r['score']:>3}/100")

print()

# Print the full report
detector.report()
print(f"Number of scanned URLs: {len(detector)}")

print("\n SEARCH RESULTS ")

matches = detector.search("paypa1")

if matches:
    for result in matches:
        print(f"\nURL   : {result['url']}")
        print(f"Score : {result['score']}/100")
        print(f"Risk  : {result['risk']}")
else:
    print("No matching URLs found.")

# Check stats
s = detector.stats()
print(f"Quick stats: {s['phishing']} phishing, {s['safe']} safe, avg {s['avg_score']}/100\n")

print(" TOP 3 MOST DANGEROUS URLs ")

for i, result in enumerate(detector.top(3), start=1):
    print(f"\n#{i}")
    print(f"URL   : {result['url']}")
    print(f"Score : {result['score']}/100")
    print(f"Risk  : {result['risk']}")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")

# Save to file
detector.save("day5_report.txt")
print()


print("=== LESSON 5: Multiple Instances ===")

# The power of classes — create two SEPARATE detectors with
# different settings, both independent from each other.

strict   = PhishingDetector(name="StrictDetector")
lenient  = PhishingDetector(name="LenientDetector")

print("\n CUSTOM BANK DETECTOR ")

# Create a customized detector
bank_detector = PhishingDetector(name="BankDetector")

# Add fake bank brands
bank_detector.add_fake_brand("hsb0")
bank_detector.add_fake_brand("ba1rclays")
bank_detector.add_fake_brand("lloyds1")

# URLs to scan
bank_urls = [
    "http://hsb0-secure-login.xyz/verify",
    "https://ba1rclays-bank.com/account/update",
    "http://lloyds1-security.tk/login",
    "https://www.google.com/search?q=banking",
    "http://secure-hsb0-login.click/confirm?password=123"
]

print("\nScanning bank-related URLs...\n")

for url in bank_urls:
    result = bank_detector.scan(url)
    print(f"{result['risk']:<12} {result['score']:>3}/100  {url}")

print()

# Generate report
bank_detector.report()

# Customise the strict one
strict.add_bad_tld(".io")          # treat .io as risky
strict.add_fake_brand("tw1tter")
strict.weights["no_https"] = 30   # double the penalty for no HTTPS

test_url = "http://tw1tter-login.io/verify"

r_strict  = strict.scan(test_url)
r_lenient = lenient.scan(test_url)

print(f"\nSame URL, different detectors:")
print(f"  Strict   → {r_strict['score']}/100  ({r_strict['risk']})")
print(f"  Lenient  → {r_lenient['score']}/100  ({r_lenient['risk']})")
print()


print(" LESSON 6: Inheritance (Bonus) ")

# A child class INHERITS everything from the parent class,
# then adds or changes specific parts.
# Think: EmailDetector IS a PhishingDetector, but also checks email text.

class EmailDetector(PhishingDetector):
    """
    Extends PhishingDetector to also analyse email body text
    for phishing language patterns.
    """

    URGENCY_PHRASES = [
        "act now", "immediate action", "verify your account",
        "your account will be suspended", "click here immediately",
        "limited time", "you have won", "claim your prize",
        "confirm your identity", "unusual activity detected"
    ]

    PAYMENT_SCAM_PHRASES = [
        "wire transfer",
        "gift card",
        "bitcoin"
    ]


    def __init__(self):
        # Call the parent __init__ first — always do this
        super().__init__(name="EmailDetector")
        self.email_scans = []   # extra history just for emails

    def scan_email(self, subject, body):
        """
        Scans an email's subject and body for phishing language.
        Returns a result dict similar to scan().
        """
        text     = (subject + " " + body).lower()
        reasons  = []
        score    = 0

        # Check for urgency phrases
        for phrase in self.URGENCY_PHRASES:
            if phrase in text:
                score += 20
                reasons.append(f"Urgency phrase: '{phrase}'")

                        # Check for payment scam phrases
        for phrase in self.PAYMENT_SCAM_PHRASES:
            if phrase in text:
                score += 25
                reasons.append(f"Payment scam phrase: '{phrase}'")

        # Check for URLs inside the email body and scan them
        words     = body.split()
        url_score = 0
        for word in words:
            if word.startswith("http"):
                r = self.scan(word)   # reuse parent's scan()!
                url_score = max(url_score, r["score"])
                if r["score"] > 30:
                    reasons.append(f"Suspicious URL in body: {word[:40]}")

        score = min(score + url_score // 2, 100)

        result = {
            "subject":    subject,
            "score":      score,
            "risk":       self._classify(score),   # reuse parent method!
            "reasons":    reasons,
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        self.email_scans.append(result)
        return result


# Try it
email_detector = EmailDetector()
print(f"\nCreated: {email_detector}\n")

fake_email = email_detector.scan_email(
    subject="URGENT: Wire Transfer Required",
    body=(
        "Dear customer, unusual activity detected on your account. "
        "Please complete a wire transfer immediately or send a gift card "
        "payment. Bitcoin is also accepted. "
        "Click here immediately: "
        "http://paypa1.secure-login.xyz/verify?pwd=yourpassword"
    )
)

print("\nEmail scan result:")
print(f"Subject : {fake_email['subject']}")
print(f"Score   : {fake_email['score']}/100")
print(f"Risk    : {fake_email['risk']}")
print("Reasons:")
for reason in fake_email["reasons"]:
    print(f"  • {reason}")

print(f"Email scan result:")
print(f"  Subject : {fake_email['subject']}")
print(f"  Score   : {fake_email['score']}/100")
print(f"  Risk    : {fake_email['risk']}")
print(f"  Reasons :")
for r in fake_email["reasons"]:
    print(f"    • {r}")

print()

