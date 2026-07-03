


from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)
from datetime import datetime



# SECTION 1 — CONSTANTS

SCORE_WEIGHTS = {
    "no_https":          15,
    "bad_tld":           25,
    "fake_brand":        30,
    "suspicious_path":   10,
    "ip_address":        20,
    "long_subdomain":    10,
    "excessive_hyphens": 15,
    "query_sensitive":   30,
}

BAD_TLDS = [
    ".xyz", ".tk", ".ml", ".win", ".top",
    ".click", ".gq", ".cf", ".pw", ".buzz",
]

FAKE_BRANDS = [
    "paypa1", "amaz0n", "g00gle", "micros0ft",
    "app1e",  "faceb00k", "netfl1x", "inst4gram",
    "tw1tter", "linkedln",
]

SUSPICIOUS_PATHS = [
    "verify", "login", "update", "confirm",
    "secure", "validate", "account", "suspend",
]

SENSITIVE_PARAMS = {
    "ssn", "password", "passwd", "pwd",
    "social_security", "creditcard", "cvv",
}

URGENCY_PHRASES = [
    "act now", "immediate action", "verify your account",
    "your account will be suspended", "click here immediately",
    "limited time", "you have won", "claim your prize",
    "confirm your identity", "unusual activity detected",
    "wire transfer", "gift card", "bitcoin payment",
]

WHITELISTED_DOMAINS = {
    "google.com", "github.com", "youtube.com",
    "amazon.com", "facebook.com", "microsoft.com",
    "apple.com",  "twitter.com", "linkedin.com",
}

REPORT_WIDTH = 58



# SECTION 2 — PURE HELPER FUNCTIONS
# Leading underscore = internal / private convention.
# Same input → always same output. Easy to test in isolation.

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _classify(score):
    if score == 0:   return "SAFE"
    if score <= 30:  return "LOW RISK"
    if score <= 60:  return "SUSPICIOUS"
    return "PHISHING"

def _score_bar(score, width=10):
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)

def _risk_icon(risk):
    return {"SAFE": "✓", "LOW RISK": "◎", "SUSPICIOUS": "⚠", "PHISHING": "✕"}.get(risk, "?")

def _is_ip_domain(domain):
    parts = domain.replace(":", "").split(".")
    return sum(1 for p in parts if p.isdigit()) >= 3

def _extract_params(query):
    if not query:
        return set()
    return {part.split("=")[0].lower() for part in query.split("&") if part}

def _truncate(text, max_len=50):
    return text if len(text) <= max_len else text[:max_len - 1] + "…"

def _divider(char="=", width=REPORT_WIDTH):
    return char * width

def _compute_stats(results):
    if not results:
        return {"total": 0}
    total = len(results)
    return {
        "total":      total,
        "safe":       sum(1 for r in results if r["risk"] == "SAFE"),
        "low_risk":   sum(1 for r in results if r["risk"] == "LOW RISK"),
        "suspicious": sum(1 for r in results if r["risk"] == "SUSPICIOUS"),
        "phishing":   sum(1 for r in results if r["risk"] == "PHISHING"),
        "avg_score":  round(sum(r["score"] for r in results) / total, 1),
        "highest":    max(results, key=lambda r: r["score"]),
        "lowest":     min(results, key=lambda r: r["score"]),
    }



# SECTION 3 — THE CLASS

class PhishingDetector:
    """
    A complete, production-style URL phishing detection system.

    New concepts demonstrated in Day 6:
        __init__         constructor / instance setup
        _run_checks()    private method (leading underscore)
        @property        computed attribute (detector.scan_count)
        @classmethod     alternative constructor (PhishingDetector.from_list)
        @staticmethod    utility tied to class but needs no self/cls
        __len__          len(detector)
        __str__          print(detector)
        __repr__         repr(detector) / shell display
        __contains__     url in detector
        __iter__         for result in detector
        __enter__/__exit__ with PhishingDetector() as d:

    Quick start:
        detector = PhishingDetector()
        result   = detector.scan("http://paypa1.xyz/verify")
        detector.report()
        detector.save("report.txt")
    """

    # LESSON A: Class Variables 
    # Belong to the CLASS, shared by ALL instances.
    # Access as: PhishingDetector.version  or  self.version

    version         = "1.0.0"
    _instance_count = 0       # counts every detector ever created


    # LESSON B: __init__ — The Constructor 
    # Python calls this automatically when you do: d = PhishingDetector()
    # 'self' = the new object being created.
    # Set up every INSTANCE variable here so they exist from the start.

    def __init__(self, name="PhishingDetector"):
        """
        Creates a new PhishingDetector.

        Args:
            name: Label for this instance (helpful when using many detectors).

        Example:
            strict  = PhishingDetector(name="StrictDetector")
            lenient = PhishingDetector(name="LenientDetector")
        """
        self.name    = name
        self.history = []          # every scan result goes here
        self.created = _now()

        # Mutable COPIES of module constants.
        # WHY copy? So changing self.weights on one instance
        # doesn't affect other instances or the original constant.
        self.weights          = dict(SCORE_WEIGHTS)
        self.bad_tlds         = list(BAD_TLDS)
        self.fake_brands      = list(FAKE_BRANDS)
        self.suspicious_paths = list(SUSPICIOUS_PATHS)
        self.sensitive_params = set(SENSITIVE_PARAMS)
        self.whitelist        = set(WHITELISTED_DOMAINS)

        PhishingDetector._instance_count += 1
        print(f"[{self.name}] Ready (v{self.version}) — "
              f"instance #{PhishingDetector._instance_count}")


    #  LESSON C: Private Method 
    # _method() = "internal use only" (convention, not enforced).
    # Keeps scan() clean — all the check logic lives here.

    def _run_checks(self, domain, path, query, scheme):
        """
        Runs all phishing checks. Returns (score, reasons).
        Only called internally by scan(). Do not call directly.
        """
        score   = 0
        reasons = []
        params  = _extract_params(query)

        # Check 1: No HTTPS
        # Phishing sites often skip HTTPS to avoid identity verification.
        if scheme != "https":
            score += self.weights["no_https"]
            reasons.append("Uses HTTP instead of HTTPS (insecure connection)")

        # Check 2: High-risk TLD
        # .xyz .tk .ml etc. are free, require no identity, heavily abused.
        for tld in self.bad_tlds:
            if domain.endswith(tld):
                score += self.weights["bad_tld"]
                reasons.append(f"High-risk domain extension: {tld}")
                break

        # Check 3: Fake brand (typosquat / leetspeak)
        # paypa1.com, amaz0n.net — tricks users scanning URLs quickly.
        for brand in self.fake_brands:
            if brand in domain:
                score += self.weights["fake_brand"]
                reasons.append(f"Impersonates a known brand: '{brand}'")
                break

        # Check 4: Suspicious path keyword
        # /verify /login /confirm are classic credential-harvesting paths.
        for word in self.suspicious_paths:
            if word in path:
                score += self.weights["suspicious_path"]
                reasons.append(f"Suspicious path keyword: '/{word}'")
                break

        # Check 5: Raw IP address as domain
        # Hides real server identity: http://192.168.1.1/admin/login
        if _is_ip_domain(domain):
            score += self.weights["ip_address"]
            reasons.append("Raw IP address used instead of a domain name")

        # Check 6: Long subdomain chain
        # secure.login.paypal.com.evil.xyz — real domain is evil.xyz
        if domain.count(".") >= 3:
            score += self.weights["long_subdomain"]
            reasons.append(
                f"Deep subdomain chain ({domain.count('.')} levels): {domain}"
            )

        # Check 7: Excessive hyphens
        # my-secure-bank-login.com rarely appears in legitimate URLs.
        if domain.count("-") >= 3:
            score += self.weights["excessive_hyphens"]
            reasons.append(
                f"Excessive hyphens in domain ({domain.count('-')})"
            )

        # Check 8: Sensitive params in query string
        # No real bank asks for password or SSN in a URL parameter.
        if self.sensitive_params & params:
            matched = self.sensitive_params & params
            score += self.weights["query_sensitive"]
            reasons.append(f"Sensitive parameter(s) in URL: {matched}")

        return min(score, 100), reasons


    #  LESSON D: Public scan() method 
    def scan(self, url):
        """
        Scans a single URL for phishing indicators.
        Saves result to self.history and returns it.

        Args:
            url (str): The URL to analyse.

        Returns:
            dict: { url, score, risk, reasons, scanned_at }

        Example:
            r = detector.scan("http://paypa1.xyz/verify")
            print(r["risk"])     # PHISHING
            print(r["score"])    # 80
        """
        url    = url.strip()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        #  Whitelist fast-exit 
        # Trusted domain? Return SAFE immediately, skip all checks.
        # Extracts base domain: "www.google.com" → "google.com"
        base_domain = ".".join(domain.split(".")[-2:])
        if base_domain in self.whitelist:
            result = {
                "url":        url,
                "score":      0,
                "risk":       "SAFE",
                "reasons":    ["Domain is on the trusted whitelist"],
                "scanned_at": _now(),
            }
            self.history.append(result)
            return result

        score, reasons = self._run_checks(
            domain,
            parsed.path.lower(),
            parsed.query.lower(),
            parsed.scheme,
        )

        result = {
            "url":        url,
            "score":      score,
            "risk":       _classify(score),
            "reasons":    reasons,
            "scanned_at": _now(),
        }
        self.history.append(result)
        return result


    def scan_many(self, urls):
        """Scans a list of URLs. Returns list of result dicts."""
        return [self.scan(url) for url in urls if url.strip()]


    def scan_file(self, filepath):
        """
        Reads URLs from a text file (one per line) and scans each.
        Lines starting with # are treated as comments and skipped.
        """
        batch = []
        try:
            with open(filepath) as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        batch.append(self.scan(url))
            print(f"[{self.name}] Scanned {len(batch)} URLs from '{filepath}'")
        except FileNotFoundError:
            print(f"[{self.name}] ERROR: '{filepath}' not found.")
        return batch


    def stats(self):
        """Returns a summary statistics dict of all scans so far."""
        return _compute_stats(self.history)


    def report(self):
        """Prints a formatted scan report to the terminal."""
        s = self.stats()
        if s["total"] == 0:
            print("No scans yet. Run detector.scan(url) first.")
            return

        print(_divider("="))
        print(f"  {self.name.upper()} — SCAN REPORT")
        print(_divider("="))
        print(f"  Total scanned : {s['total']}")
        print(f"  Average score : {s['avg_score']}/100")
        print(f"  Most dangerous: "
              f"{_truncate(s['highest']['url'], 36)}  ({s['highest']['score']}/100)")
        print(_divider("-"))
        for label in ("SAFE", "LOW RISK", "SUSPICIOUS", "PHISHING"):
            key   = label.lower().replace(" ", "_")
            count = s.get(key, 0)
            bar   = "■" * count
            print(f"  {_risk_icon(label)}  {label:<12}: {count}  {bar}")
        print(_divider("="))

        flagged = [r for r in self.history if r["risk"] in ("SUSPICIOUS", "PHISHING")]
        if flagged:
            print("\n  FLAGGED URLS:")
            for r in sorted(flagged, key=lambda x: x["score"], reverse=True):
                print(f"\n  {_risk_icon(r['risk'])} {r['score']:>3}/100  {r['url']}")
                for reason in r["reasons"]:
                    print(f"            • {reason}")
        print()


    def save(self, filename="report.txt"):
        """Saves scan history to a text file sorted by score (highest first)."""
        if not self.history:
            print("Nothing to save.")
            return
        s = self.stats()
        with open(filename, "w") as f:
            f.write("PHISHING DETECTOR — SCAN REPORT\n")
            f.write(f"Generated : {_now()}\n")
            f.write(f"Detector  : {self.name} v{self.version}\n")
            f.write(f"Total URLs: {s['total']}  |  Avg: {s['avg_score']}/100\n")
            f.write(_divider() + "\n\n")
            for r in sorted(self.history, key=lambda x: x["score"], reverse=True):
                f.write(f"URL   : {r['url']}\n")
                f.write(f"Score : {r['score']}/100  ({r['risk']})\n")
                f.write(f"Time  : {r['scanned_at']}\n")
                for reason in r["reasons"]:
                    f.write(f"      - {reason}\n")
                f.write(_divider("-") + "\n")
        print(f"[{self.name}] Saved {s['total']} results → '{filename}'")


    def top(self, n=3):
        """Returns the n most dangerous results from history."""
        return sorted(self.history, key=lambda r: r["score"], reverse=True)[:n]


    def search(self, keyword):
        """Returns all results whose URL contains keyword."""
        return [r for r in self.history if keyword.lower() in r["url"].lower()]


    def clear(self):
        """Wipes all scan history."""
        n = len(self.history)
        self.history = []
        print(f"[{self.name}] Cleared {n} results.")


    #  Customisation helpers 
    def add_bad_tld(self, tld):
        """Add a TLD to the blocklist."""
        tld = tld if tld.startswith(".") else "." + tld
        self.bad_tlds.append(tld)
        print(f"[{self.name}] Blocklisted TLD: {tld}")

    def add_fake_brand(self, brand):
        """Add a fake brand pattern to detect."""
        self.fake_brands.append(brand.lower())
        print(f"[{self.name}] Added fake brand: {brand}")

    def trust_domain(self, domain):
        """Add a domain to the trusted whitelist."""
        self.whitelist.add(domain.lower())
        print(f"[{self.name}] Trusted: {domain}")


    #LESSON E: @property
    # @property makes a METHOD look like an ATTRIBUTE.
    # detector.scan_count   ← no parentheses, but runs code underneath.
    # Use for: computed values that shouldn't be stored as raw attributes.

    @property
    def scan_count(self):
        """Total number of URLs scanned. Usage: detector.scan_count"""
        return len(self.history)

    @property
    def phishing_count(self):
        """Number of PHISHING results. Usage: detector.phishing_count"""
        return sum(1 for r in self.history if r["risk"] == "PHISHING")

    @property
    def safe_count(self):
        """
        Returns the number of SAFE URLs.
        Usage:
            print(detector.safe_count)
        """
        return sum(1 for r in self.history if r["risk"] == "SAFE")

    @property
    def last_scan(self):
        """Most recent scan result dict, or None. Usage: detector.last_scan"""
        return self.history[-1] if self.history else None


    #  LESSON F: @classmethod 
    # Receives the CLASS (cls) instead of the instance (self).
    # Perfect for ALTERNATIVE CONSTRUCTORS — extra ways to create objects.
    # cls(...) inside is the same as PhishingDetector(...)

    @classmethod
    def from_list(cls, urls, name="ListDetector"):
        """
        Alternative constructor: create a detector and scan a list at once.

        Instead of:
            d = PhishingDetector()
            d.scan_many(["http://a.com", "https://b.com"])

        You can write:
            d = PhishingDetector.from_list(["http://a.com", "https://b.com"])
        """
        instance = cls(name=name)      # cls() = PhishingDetector()
        instance.scan_many(urls)
        return instance

    @classmethod
    def from_file(cls, filepath, name="FileDetector"):
        """
        Alternative constructor: create a detector and scan a file at once.

        Usage:
            d = PhishingDetector.from_file("urls.txt")
        """
        instance = cls(name=name)
        instance.scan_file(filepath)
        return instance

    @classmethod
    def total_instances(cls):
        """Returns how many PhishingDetector instances have been created."""
        return cls._instance_count
    
    @classmethod
    def from_dict(cls, data):
        """
        Alternative constructor: create a detector from a dictionary.

        Args:
            data (dict): Example:
                {
                    "urls": [
                        "http://evil.xyz/login",
                        "https://google.com"
                    ],
                    "name": "MyDetector"
                }

        Returns:
            PhishingDetector: A detector with all URLs scanned.
        """
        name = data.get("name", "DictDetector")
        urls = data.get("urls", [])

        instance = cls(name=name)
        instance.scan_many(urls)
        return instance


    #LESSON G: @staticmethod
    # No self or cls — just a plain function inside the class namespace.
    # Use when the logic BELONGS to the class conceptually but needs
    # no access to instance or class data.
    # Call as: PhishingDetector.risk_label(75)  or  detector.risk_label(75)
    @staticmethod
    def parse_domain(url):
        """
        Extracts the base domain from a URL.

        Example:
            PhishingDetector.parse_domain(
                "http://login.secure.paypal.com.evil.xyz/verify"
            )
            # Returns: "evil.xyz"
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port number if present
        domain = domain.split(":")[0]

        parts = domain.split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return domain

    @staticmethod
    def is_safe_score(score):
        """Returns True if a score indicates no risk."""
        return score == 0

    @staticmethod
    def risk_label(score):
        """Converts a score to a risk label without creating an instance."""
        return _classify(score)

    @staticmethod
    def explain_score(score):
        """Returns a plain-English explanation of what a score means."""
        if score == 0:
            return "No indicators detected. URL appears safe."
        if score <= 30:
            return "Minor indicators. Proceed with caution."
        if score <= 60:
            return "Multiple suspicious indicators. Avoid if possible."
        return "Strong phishing indicators. Do NOT visit this URL."


    # LESSON H: Dunder (Magic) Methods
    # Python calls these automatically for built-in operations.
    # You never call __len__ directly — Python calls it for len().

    def __len__(self):
        """
        len(detector) → number of URLs scanned.

        Python calls this automatically when you write len(detector).
        Example:
            print(len(detector))   # 9
        """
        return len(self.history)

    def __str__(self):
        """
        print(detector) → human-friendly description.

        Python calls this for print() and str().
        Example:
            print(detector)
            # PhishingDetector 'Day6Demo' | 9 scans | 3 phishing found
        """
        return (f"PhishingDetector '{self.name}' | "
                f"{self.scan_count} scans | "
                f"{self.phishing_count} phishing found")

    def __repr__(self):
        """
        repr(detector) → developer-facing string (looks like code).

        Python uses __repr__ in the interactive shell and for debugging.
        Convention: return a string that shows how to recreate the object.
        Example:
            repr(detector)
            # PhishingDetector(name='Day6Demo')
        """
        return f"PhishingDetector(name='{self.name}')"

    def __contains__(self, url):
        """
        url in detector → True if URL has already been scanned.

        Python calls __contains__ when you write: value in object
        Example:
            if "http://evil.xyz" in detector:
                print("Already scanned!")
        """
        return any(r["url"] == url for r in self.history)

    def __iter__(self):
        """
        for result in detector → iterate over scan results.

        Python calls __iter__ to get an iterator for 'for' loops.
        Example:
            for result in detector:
                print(result["score"], result["url"])
        """
        return iter(self.history)
    
    def __add__(self, other):
        """
        Merge two PhishingDetector objects using the + operator.

        Example:
            combined = detector1 + detector2

        Returns:
            A new PhishingDetector containing the scan history of both.
        """
        if not isinstance(other, PhishingDetector):
            return NotImplemented

        merged = PhishingDetector(
            name=f"{self.name}+{other.name}"
        )

        merged.history = self.history + other.history

        return merged


    #  LESSON I: Context Manager 
    # __enter__ and __exit__ enable the 'with' statement.
    # Python calls __enter__ on entry and __exit__ on exit (even on error).
    # Great for: automatic cleanup, guaranteed save, resource management.

    def __enter__(self):
        """
        Called when entering a 'with PhishingDetector() as d:' block.
        Must return self so the 'as d' variable gets the detector.

        Example:
            with PhishingDetector() as d:
                d.scan("http://evil.xyz")
            # report auto-saved here by __exit__
        """
        print(f"[{self.name}] Session started…")
        return self    # ← 'as d' receives this return value

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Called automatically when leaving the 'with' block.
        exc_type, exc_val, exc_tb hold exception info (all None if no error).
        Return False to let exceptions propagate normally.
        """
        if exc_type:
            print(f"[{self.name}] Session ended with error: {exc_val}")
        else:
            print(f"[{self.name}] Session complete — auto-saving…")
            self.save("auto_report.txt")
        return False    # False = don't suppress exceptions



# SECTION 4 — EmailDetector (Child Class)
class EmailDetector(PhishingDetector):
    """
    Extends PhishingDetector to also scan email subject + body text.

    Inherits EVERYTHING from PhishingDetector and adds:
        - scan_email(subject, body)   scans email text for phishing
        - email_report()              report for email scans only
        - email_history               separate list for email results
        - overridden __str__          shows email scan count too
    """

    def __init__(self):
        # ALWAYS call super().__init__() first in a child class.
        # This runs PhishingDetector's __init__ to set up inherited attrs.
        super().__init__(name="EmailDetector")
        self.email_history   = []
        self.urgency_phrases = list(URGENCY_PHRASES)

    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    def scan(self, url):
        """
        Overrides PhishingDetector.scan().

        Removes all utm_* tracking parameters before scanning
        and prints a message if the URL was cleaned.
        """
        parsed = urlparse(url)

        # Keep only non-utm parameters
        params = [
            (key, value)
            for key, value in parse_qsl(parsed.query)
            if not key.lower().startswith("utm_")
        ]

        cleaned_query = urlencode(params)

        cleaned_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            cleaned_query,
            parsed.fragment,
        ))

        if cleaned_url != url:
            print(f"[{self.name}] Cleaned URL:")
            print(f"  Original: {url}")
            print(f"  Cleaned : {cleaned_url}")

        # Call the parent class scan()
        return super().scan(cleaned_url)

    def scan_email(self, subject, body):
        """
        Scans an email for phishing language and suspicious embedded URLs.

        Scoring:
          - Each urgency phrase found      → +20 points
          - High-risk embedded URL found   → adds half its URL score
          - Total capped at 100

        Args:
            subject (str): Email subject line.
            body    (str): Email body text.

        Returns:
            dict: { subject, score, risk, reasons, scanned_at }
        """
        text    = (subject + " " + body).lower()
        reasons = []
        score   = 0

        # Check for social-engineering urgency language
        for phrase in self.urgency_phrases:
            if phrase in text:
                score += 20
                reasons.append(f"Urgency phrase detected: '{phrase}'")

        # Scan embedded URLs using the PARENT's scan() method
        # This is the power of inheritance — no need to rewrite scan logic
        url_score = 0
        for word in body.split():
            word = word.strip(".,<>\"'()")
            if word.startswith("http"):
                r = self.scan(word)          # ← parent method reused!
                url_score = max(url_score, r["score"])
                if r["score"] > 30:
                    reasons.append(f"Suspicious URL in body: {_truncate(word, 40)}")

        score = min(score + url_score // 2, 100)

        result = {
            "subject":    subject,
            "score":      score,
            "risk":       _classify(score),
            "reasons":    reasons,
            "scanned_at": _now(),
        }
        self.email_history.append(result)
        return result

    def email_report(self):
        """Prints a summary report for email scans only."""
        if not self.email_history:
            print("No email scans yet.")
            return
        s = _compute_stats(self.email_history)
        print(_divider("="))
        print("  EMAIL SCAN REPORT")
        print(_divider("="))
        print(f"  Emails scanned : {s['total']}")
        print(f"  Average score  : {s['avg_score']}/100")
        print(_divider("-"))
        for label in ("SAFE", "LOW RISK", "SUSPICIOUS", "PHISHING"):
            key = label.lower().replace(" ", "_")
            print(f"  {_risk_icon(label)}  {label:<12}: {s.get(key, 0)}")
        print(_divider("="))
        print()

    def __str__(self):
        # Override parent __str__ to include email scan count
        return (f"EmailDetector '{self.name}' | "
                f"{self.scan_count} URL scans | "
                f"{len(self.email_history)} email scans | "
                f"{self.phishing_count} phishing found")



# SECTION 5 — DEMO

if __name__ == "__main__":

    print("\n" + "=" * 58)
    print("  DAY 6 — detector.py Deep Dive")
    print("=" * 58 + "\n")


    # Demo 1: Basic scan 
    print("Demo 1: Basic scan\n")

    detector = PhishingDetector(name="Day6Demo")

    test_urls = [
        "https://www.google.com/search?q=python+tutorial",
        "https://github.com/user/phishing-detector",
        "https://youtube.com/watch?v=abc123",
        "https://amazon.com/products?id=123",
        "http://paypa1.secure-login.xyz/verify",
        "http://192.168.1.1/admin/login",
        "http://free-prize.win/claim?user=you",
        "http://micros0ft-update.tk/download",
        "http://my-secure-bank-login-update.com/confirm?ssn=123",
    ]

    print(f"Scanning {len(test_urls)} URLs...\n")
    for url in test_urls:
        r = detector.scan(url)
        print(f"  {_risk_icon(r['risk'])} [{_score_bar(r['score'])}]"
              f" {r['score']:>3}/100  {_truncate(url, 44)}")

    print()
    detector.report()
    detector.save("day6_report.txt")


    # Demo 2: @property
    print("Demo 2: Properties\n")
    print(f"  detector.scan_count     = {detector.scan_count}")
    print(f"  detector.phishing_count = {detector.phishing_count}")
    print(f"  detector.last_scan risk = {detector.last_scan['risk']}")
    print()


    # Demo 3: Dunder methods 
    print("Demo 3: Dunder methods\n")
    print(f"  str(detector)   → {str(detector)}")
    print(f"  repr(detector)  → {repr(detector)}")
    print(f"  len(detector)   → {len(detector)}")

    evil = "http://paypa1.secure-login.xyz/verify"
    print(f"\n  '{_truncate(evil, 35)}' in detector → {evil in detector}")
    print(f"  'https://unknown.com' in detector  → {'https://unknown.com' in detector}")

    print("\n  for result in detector:")
    for r in detector:
        print(f"    {r['score']:>3}/100  {_truncate(r['url'], 44)}")
    print()


    #Demo 4: @classmethod and @staticmethod 
    print("Demo 4: classmethod & staticmethod\n")
    print(f"  PhishingDetector.total_instances()  = {PhishingDetector.total_instances()}")
    print(f"  PhishingDetector.risk_label(75)     = {PhishingDetector.risk_label(75)}")
    print(f"  PhishingDetector.is_safe_score(0)   = {PhishingDetector.is_safe_score(0)}")
    print(f"  PhishingDetector.explain_score(85)  = {PhishingDetector.explain_score(85)}")

    print("\n  from_list() alternative constructor:")
    quick = PhishingDetector.from_list(
        ["http://evil.xyz/login", "https://google.com"],
        name="QuickScan"
    )
    print(f"  {quick}")
    print()


    #Demo 5: Context manager 
    print("Demo 5: Context manager (with statement)\n")

    with PhishingDetector(name="ContextDemo") as d:
        d.scan("http://paypa1.xyz/verify")
        d.scan("https://google.com")
        d.scan("http://free-prize.tk/claim?ssn=123")
    # auto_report.txt saved automatically by __exit__
    print()


    #Demo 6: Customised instances
    print("Demo 6: Two instances, different settings\n")

    strict  = PhishingDetector(name="StrictDetector")
    lenient = PhishingDetector(name="LenientDetector")

    strict.add_bad_tld(".io")
    strict.add_fake_brand("tw1tter")
    strict.weights["no_https"] = 30    # harsher HTTP penalty

    url = "http://tw1tter-login.io/verify"
    rs  = strict.scan(url)
    rl  = lenient.scan(url)

    print(f"\n  URL: {url}")
    print(f"  Strict  → {rs['score']}/100  ({rs['risk']})")
    print(f"  Lenient → {rl['score']}/100  ({rl['risk']})")
    print()


    #Demo 7: EmailDetector 
    print("Demo 7: EmailDetector (child class)\n")

    ed = EmailDetector()
    print(ed)
    print()

    sample_emails = [
        {
            "subject": "URGENT: Verify your account now",
            "body": (
                "Unusual activity detected. Act now to avoid suspension. "
                "Confirm your identity: http://paypa1-secure.xyz/verify?pwd=abc"
            ),
        },
        {
            "subject": "Team lunch tomorrow at 12:30",
            "body": "Hey everyone, conference room B. See you there!",
        },
        {
            "subject": "You have won a prize!",
            "body": "Claim your gift card immediately: http://free-prize.win/claim",
        },
    ]

    for email in sample_emails:
        r = ed.scan_email(email["subject"], email["body"])
        print(f"  {_risk_icon(r['risk'])} [{_score_bar(r['score'])}]"
              f" {r['score']:>3}/100  \"{_truncate(email['subject'], 34)}\"")
        for reason in r["reasons"]:
            print(f"            • {reason}")
        print()

    ed.email_report()

    print("Demo 8: from_dict() classmethod\n")

    data = {
        "name": "DictionaryDetector",
        "urls": [
            "http://paypa1.xyz/verify",
            "https://google.com",
            "http://free-prize.win/claim"
        ]
    }

    detector_from_dict = PhishingDetector.from_dict(data)

    print(detector_from_dict)
    print(f"Scans: {detector_from_dict.scan_count}")
    detector_from_dict.report()

    print("Demo 9: __add__() dunder method\n")

    detector1 = PhishingDetector(name="Detector1")
    detector1.scan("http://paypa1.xyz/login")

    detector2 = PhishingDetector(name="Detector2")
    detector2.scan("https://google.com")
    detector2.scan("http://free-prize.win/claim")

    combined = detector1 + detector2

    print(combined)
    print(f"Total scans: {combined.scan_count}")

    combined.report()

print("Demo 10: Overridden scan()\n")

ed = EmailDetector()

result = ed.scan(
    "http://paypa1.xyz/verify?utm_source=google&utm_medium=email&pwd=123"
)

print(f"Risk : {result['risk']}")
print(f"Score: {result['score']}/100")

for reason in result["reasons"]:
    print(f"  • {reason}")
    
    print("Demo 11: parse_domain() staticmethod\n")

    url = "http://login.secure.paypal.com.evil.xyz/verify"

    domain = PhishingDetector.parse_domain(url)

    print(f"URL         : {url}")
    print(f"Base Domain : {domain}")
