import os
import re
import ssl
import sys
import json
import time
import socket
import hashlib
import logging
import urllib.parse
import atexit
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlencode
import requests
print("=== LESSON 1: The Python Package Ecosystem ===\n")

# Check which packages are available
packages_to_check = ["requests", "json", "re", "socket", "ssl", "hashlib"]
for pkg in packages_to_check:
    try:
        mod = __import__(pkg)
        version = getattr(mod, "__version__", "built-in")
        print(f"  {'OK':>4}  {pkg:<15} {version}")
    except ImportError:
        print(f"  MISS  {pkg:<15} not installed (pip install {pkg})")

print()

# Import requests now that we know it's available
try:
    import requests
    from requests.exceptions import (
        RequestException,
        ConnectionError,
        Timeout,
        SSLError,
        HTTPError,
        TooManyRedirects
    )

    REQUESTS_AVAILABLE = True
    print(f"requests v{requests.__version__} ready")

except ImportError:
    REQUESTS_AVAILABLE = False
    print("requests not installed")


print("=== LESSON 2: requests Library ===\n")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

def make_request(url: str, timeout: int = 10) -> dict:
    """Fetch a URL and collect redirect/HTTP information."""

    result = {
        "ok": False,
        "status_code": None,
        "final_url": url,
        "redirect_count": 0,
        "response_time": None,
        "server": "",
        "content_type": "",
        "title": "",
        "error": None,
    }

    try:
        # --------------------------------------------------
        # Send HTTP request
        # --------------------------------------------------
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

        # --------------------------------------------------
        # Basic response information
        # --------------------------------------------------
        result["ok"] = resp.ok
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["redirect_count"] = len(resp.history)
        result["response_time"] = resp.elapsed.total_seconds()
        result["server"] = resp.headers.get("Server", "")
        result["content_type"] = resp.headers.get("Content-Type", "")

        # --------------------------------------------------
        # Extract HTML title
        # --------------------------------------------------
        if result["content_type"].startswith("text/html"):
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>",
                resp.text[:5000],
                re.IGNORECASE | re.DOTALL,
            )

            result["title"] = (
                title_match.group(1).strip()[:100]
                if title_match
                else ""
            )

    # ------------------------------------------------------
    # Exception handling
    # ------------------------------------------------------
    except SSLError as e:
        result["error"] = f"SSL_ERROR: {e}"

    except Timeout:
        result["error"] = "TIMEOUT"

    except ConnectionError as e:
        result["error"] = f"CONNECTION_ERROR: {e}"

    except TooManyRedirects:
        result["error"] = "TOO_MANY_REDIRECTS"

    except RequestException as e:
        result["error"] = f"REQUEST_ERROR: {e}"

    return result

# Test on real URLs
print("  Fetching live URLs with requests.get()...\n")
test_urls = [
    "https://httpbin.org/get",          # reliable test endpoint
    "https://httpbin.org/status/404",   # intentional 404
    "https://httpbin.org/redirect/2",   # two redirects
]

for url in test_urls:
    if REQUESTS_AVAILABLE:
        r = make_request(url, timeout=20)
        status = f"{r['status_code']}"
        redir  = f"{r['redirect_count']} redirect(s)" if r["redirect_count"] else "no redirects"
        timing = f"{r['response_time']:.2f}s"
        error  = f"  ERROR: {r['error']}" if r["error"] else ""
        print(f"  {url}")
        print(f"    status={status}  {redir}  time={timing}{error}")
        if r["server"]:
            print(f"    server={r['server']}")
    else:
        print(f"  [SKIP] {url}  (requests not installed)")
    print()

print("=== LESSON 3: DNS Lookup with socket ===\n")

def dns_lookup(domain: str) -> dict:
    """
    Performs a DNS lookup for a domain and returns structured info.

    Args:
        domain: Domain name to look up (no scheme, no path).

    Returns:
        dict: {
            "domain"    : str,  the domain queried
            "resolves"  : bool, True if DNS lookup succeeded
            "ip"        : str,  resolved IP address (or "")
            "all_ips"   : list, all resolved IPs
            "is_private": bool, True if IP is in a private range
            "error"     : str,  error type if lookup failed
        }
    """
    # Clean up domain: strip scheme, path, port
    domain = domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].split(":")[0]

    result = {
        "domain": domain, "resolves": False,
        "ip": "", "all_ips": [], "is_private": False, "error": "",
    }

    try:
        # getaddrinfo returns: [(family, type, proto, canonname, sockaddr), ...]
        # sockaddr[0] is the IP address string
        addr_info = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in addr_info})   # deduplicate

        result["resolves"] = True
        result["ip"]       = ips[0] if ips else ""
        result["all_ips"]  = ips

        # Check if IP is in a private/reserved range
        # Private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x
        ip = result["ip"]
        result["is_private"] = (
            ip.startswith("10.")        or
            ip.startswith("127.")       or
            ip.startswith("192.168.")   or
            ip.startswith("::1")        or   # IPv6 loopback
            any(ip.startswith(f"172.{i}.") for i in range(16, 32))
        )

    except socket.gaierror as e:
        # gaierror = getaddrinfo error = DNS failure
        # errno -2 / -3 = NXDOMAIN (name does not exist)
        result["error"] = f"DNS_FAILURE: {e.strerror}"

    except socket.timeout:
        result["error"] = "DNS_TIMEOUT"

    return result


# Test DNS lookups
print("  DNS lookups with socket.getaddrinfo():\n")
domains_to_check = [
    "google.com",
    "github.com",
    "this-domain-definitely-does-not-exist-xyz123.com",
    "httpbin.org",
]

for domain in domains_to_check:
    info = dns_lookup(domain)
    if info["resolves"]:
        ips = ", ".join(info["all_ips"][:3])
        priv = " (PRIVATE IP!)" if info["is_private"] else ""
        print(f"  RESOLVES  {domain:<45} -> {ips}{priv}")
    else:
        print(f"  NXDOMAIN  {domain:<45} -> {info['error']}")

print()

print("=== LESSON 4: TLS/SSL Certificate Inspection ===\n")

def get_ssl_info(domain: str, port: int = 443, timeout: int = 8) -> dict:
    """
    Connects to domain:port and retrieves SSL certificate details.

    Args:
        domain  : Domain to check (no scheme).
        port    : HTTPS port. Default 443.
        timeout : Connection timeout seconds. Default 8.

    Returns:
        dict: {
            "has_ssl"       : bool,
            "subject"       : dict,   cert subject fields
            "issuer"        : dict,   cert issuer fields
            "issued_to"     : str,    common name (CN)
            "issued_by"     : str,    issuer organisation
            "valid_from"    : str,    not-before date
            "valid_until"   : str,    not-after date
            "days_remaining": int,    days until expiry
            "is_expired"    : bool,
            "is_self_signed": bool,   issuer == subject
            "cert_age_days" : int,    days since cert was issued
            "is_new_cert"   : bool,   cert issued < 30 days ago
            "error"         : str,
        }
    """
    result = {
        "has_ssl": False, "subject": {}, "issuer": {},
        "issued_to": "", "issued_by": "", "valid_from": "",
        "valid_until": "", "days_remaining": 0, "is_expired": False,
        "is_self_signed": False, "cert_age_days": 0, "is_new_cert": False,
        "error": "",
    }

    try:
        # Create a default SSL context (verifies certificates)
        context = ssl.create_default_context()

        # Open a TCP connection and wrap it with TLS
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()

        # ── Parse certificate fields ───────────────────────────────
        # cert["subject"] is a tuple of tuples: ((("CN", "google.com"),), ...)
        def parse_fields(raw_tuple):
            return {k: v for pair in raw_tuple for k, v in pair}

        subject = parse_fields(cert.get("subject", ()))
        issuer  = parse_fields(cert.get("issuer", ()))

        result["has_ssl"]        = True
        result["subject"]        = subject
        result["issuer"]         = issuer
        result["issued_to"]      = subject.get("commonName", "")
        result["issued_by"]      = issuer.get("organizationName", issuer.get("commonName", ""))

        # Parse dates -- SSL uses format: "Nov 15 00:00:00 2023 GMT"
        date_fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(cert["notBefore"], date_fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert["notAfter"],  date_fmt).replace(tzinfo=timezone.utc)
        now        = datetime.now(timezone.utc)

        result["valid_from"]     = not_before.strftime("%Y-%m-%d")
        result["valid_until"]    = not_after.strftime("%Y-%m-%d")
        result["days_remaining"] = (not_after - now).days
        result["is_expired"]     = now > not_after
        result["cert_age_days"]  = (now - not_before).days
        result["is_new_cert"]    = result["cert_age_days"] < 30

        # Self-signed: the issuer is the same as the subject
        result["is_self_signed"] = (
            subject.get("commonName") == issuer.get("commonName") or
            subject.get("organizationName") == issuer.get("organizationName")
        )

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"CERT_VERIFY_FAILED: {str(e)[:80]}"

    except ssl.SSLError as e:
        result["error"] = f"SSL_ERROR: {str(e)[:80]}"

    except socket.timeout:
        result["error"] = "TIMEOUT"

    except (socket.gaierror, OSError) as e:
        result["error"] = f"CONNECTION_ERROR: {str(e)[:80]}"

    return result


# Check SSL certs on real domains
print("  Checking SSL certificates:\n")
ssl_domains = ["github.com", "httpbin.org", "google.com"]

for domain in ssl_domains:
    info = get_ssl_info(domain)
    if info["has_ssl"]:
        print(f"  {domain}")
        print(f"    Issued to  : {info['issued_to']}")
        print(f"    Issued by  : {info['issued_by']}")
        print(f"    Valid until: {info['valid_until']}  ({info['days_remaining']} days left)")
        print(f"    Cert age   : {info['cert_age_days']} days old")
        print(f"    Self-signed: {info['is_self_signed']}")
        print(f"    New cert   : {info['is_new_cert']} (< 30 days)")
    else:
        print(f"  {domain}  -> {info['error']}")
    print()

print("=== LESSON 5: Threat Intelligence APIs ===\n")

def check_urlhaus(url: str, timeout: int = 10) -> dict:
    """
    Checks a URL against the URLhaus malware URL database.
    URLhaus is free and requires no API key.

    API docs: https://urlhaus-api.abuse.ch/v1/url/

    Args:
        url     : The URL to check.
        timeout : Request timeout seconds.

    Returns:
        dict: {
            "found"          : bool,  True if URL is in the database
            "status"         : str,   "online" / "offline" / "unknown"
            "threat"         : str,   threat category if found
            "date_added"     : str,   when it was reported
            "tags"           : list,  threat tags
            "reporter"       : str,   who submitted it
            "in_database"    : bool,  URL exists in URLhaus
            "query_status"   : str,   raw API query status
            "error"          : str,
        }
    """
    result = {
        "found": False, "status": "unknown", "threat": "",
        "date_added": "", "tags": [], "reporter": "",
        "in_database": False, "query_status": "", "error": "",
    }

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result

    api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

    try:
        # URLhaus uses POST with form data (not JSON)
        resp = requests.post(
            api_endpoint,
            data    = {"url": url},      # form-encoded body
            timeout = timeout,
            headers = {"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()   # raises HTTPError if 4xx/5xx

        data = resp.json()

        result["query_status"] = data.get("query_status", "")

        if data.get("query_status") == "is_listed":
            result["found"]       = True
            result["in_database"] = True
            result["status"]      = data.get("url_status", "unknown")
            result["threat"]      = data.get("threat", "")
            result["date_added"]  = data.get("date_added", "")
            result["reporter"]    = data.get("reporter", "")
            result["tags"]        = data.get("tags") or []

        elif data.get("query_status") == "not_listed":
            result["in_database"] = False
            result["found"]       = False

        else:
            result["error"] = f"Unexpected query_status: {data.get('query_status')}"

    except HTTPError as e:
        result["error"] = f"HTTP_ERROR: {e.response.status_code}"

    except Timeout:
        result["error"] = "TIMEOUT: URLhaus did not respond"

    except RequestException as e:
        result["error"] = f"REQUEST_ERROR: {str(e)[:80]}"

    except (json.JSONDecodeError, KeyError) as e:
        result["error"] = f"PARSE_ERROR: {str(e)[:80]}"

    return result


def check_google_safe_browsing(url: str, api_key: str) -> dict:
    """
    Checks a URL against Google Safe Browsing v4 API.
    Requires a free API key from:
    https://developers.google.com/safe-browsing/v4/get-started

    Args:
        url     : The URL to check.
        api_key : Your Google Safe Browsing API key.

    Returns:
        dict: {
            "safe"          : bool,  True if NOT in any threat list
            "threats_found" : list,  threat types detected
            "threat_types"  : list,  MALWARE / SOCIAL_ENGINEERING / etc.
            "error"         : str,
        }
    """
    result = {"safe": True, "threats_found": [], "threat_types": [], "error": ""}

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result

    if not api_key or api_key == "YOUR_API_KEY":
        result["error"] = "No API key provided. Get one free at console.cloud.google.com"
        return result

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    # Google Safe Browsing uses a JSON POST body
    payload = {
        "client": {
            "clientId":      "phishing-detector-day8",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            # Which threat lists to check against
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                 "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        # If "matches" key exists and has items -> threats found
        matches = data.get("matches", [])
        if matches:
            result["safe"]          = False
            result["threats_found"] = matches
            result["threat_types"]  = list({m["threatType"] for m in matches})

    except HTTPError as e:
        result["error"] = f"HTTP_{e.response.status_code}"
    except RequestException as e:
        result["error"] = f"REQUEST_ERROR: {str(e)[:60]}"

    return result

def check_virustotal(url: str, api_key: str, timeout: int = 15) -> dict:
    """
    Checks a URL using the VirusTotal v3 API.

    Args:
        url: URL to scan.
        api_key: Your VirusTotal API key.

    Returns:
        dict: {
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "scan_id": str,
            "error": str,
        }
    """

    result = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "scan_id": "",
        "error": "",
    }

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result

    if not api_key:
        result["error"] = "No VirusTotal API key provided"
        return result

    endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": api_key
    }

    try:
        # Submit URL for analysis
        response = requests.post(
            endpoint,
            headers=headers,
            data={"url": url},
            timeout=timeout
        )

        response.raise_for_status()

        data = response.json()

        analysis_id = data["data"]["id"]
        result["scan_id"] = analysis_id

        # Retrieve analysis report
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=timeout
        )

        report.raise_for_status()

        stats = report.json()["data"]["attributes"]["stats"]

        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)

    except HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}"

    except RequestException as e:
        result["error"] = str(e)

    return result

# Test URLhaus on known URLs
print("  Checking URLs against URLhaus (no API key needed)...\n")
urlhaus_tests = [
    "https://www.google.com",
    "https://github.com",
    # Note: we don't test actually malicious URLs here
    # In real usage you'd pass suspicious URLs from your scan results
]

for url in urlhaus_tests:
    if REQUESTS_AVAILABLE:
        result = check_urlhaus(url, timeout=12)
        if result["error"]:
            print(f"  {url}")
            print(f"    Error: {result['error']}")
        elif result["found"]:
            print(f"  MALICIOUS  {url}")
            print(f"    Threat   : {result['threat']}")
            print(f"    Status   : {result['status']}")
            print(f"    Reported : {result['date_added']}")
        else:
            status = result["query_status"] or "not in database"
            print(f"  CLEAN      {url}")
            print(f"    URLhaus  : {status}")
    else:
        print(f"  [SKIP] {url}")
    print()

# Show the Google Safe Browsing pattern (code only, needs a key)
print("  Google Safe Browsing (needs free API key):")
gsb_result = check_google_safe_browsing("https://google.com", "YOUR_API_KEY")
print(f"    Result: {gsb_result}")
print(f"    Get a free key: https://developers.google.com/safe-browsing/v4/get-started")
print()

VT_API_KEY = "YOUR_API_KEY"
print("\nVirusTotal Demo")
vt = check_virustotal("https://github.com", VT_API_KEY)
print(vt)

print("=== LESSON 6: HTTP Headers as Phishing Signals ===\n")

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name":        "HSTS",
        "description": "Forces HTTPS for future visits",
        "risk_if_missing": 10,
    },
    "content-security-policy": {
        "name":        "CSP",
        "description": "Restricts resource loading",
        "risk_if_missing": 15,
    },
    "x-frame-options": {
        "name":        "X-Frame-Options",
        "description": "Prevents clickjacking via iframes",
        "risk_if_missing": 10,
    },
    "x-content-type-options": {
        "name":        "X-Content-Type-Options",
        "description": "Prevents MIME sniffing",
        "risk_if_missing": 5,
    },
    "referrer-policy": {
        "name":        "Referrer-Policy",
        "description": "Controls referrer header",
        "risk_if_missing": 5,
    },
}

def analyze_headers(url: str, timeout: int = 8) -> dict:
    """
    Fetches a URL (HEAD request) and analyses its security headers.
    Uses HEAD (not GET) because we only need headers, not the body.
    HEAD is faster and uses less bandwidth.

    Args:
        url     : URL to check.
        timeout : Request timeout.

    Returns:
        dict: {
            "url"              : str,
            "status_code"      : int,
            "headers_present"  : list,  security headers found
            "headers_missing"  : list,  security headers not found
            "header_score"     : int,   risk points from missing headers
            "server"           : str,   Server header value
            "powered_by"       : str,   X-Powered-By header (reveals tech)
            "all_headers"      : dict,  full header dict
            "error"            : str,
        }
    """
    result = {
        "url": url, "status_code": 0, "headers_present": [],
        "headers_missing": [], "header_score": 0,
        "server": "", "powered_by": "", "all_headers": {}, "error": "",
    }

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed"
        return result

    try:
        # HEAD request: same as GET but server sends headers only, no body
        resp = requests.head(
            url,
            timeout         = timeout,
            allow_redirects = True,
            headers         = {"User-Agent": "Mozilla/5.0 PhishingDetector/1.0"},
        )

        result["status_code"] = resp.status_code
        result["all_headers"] = dict(resp.headers)
        result["server"]      = resp.headers.get("Server", "")
        result["powered_by"]  = resp.headers.get("X-Powered-By", "")

        # Check each security header
        lowered = {k.lower(): v for k, v in resp.headers.items()}

        for header_key, meta in SECURITY_HEADERS.items():
            if header_key in lowered:
                result["headers_present"].append(meta["name"])
            else:
                result["headers_missing"].append(meta["name"])
                result["header_score"] += meta["risk_if_missing"]

    except Timeout:
        result["error"] = "TIMEOUT"
    except RequestException as e:
        result["error"] = f"REQUEST_ERROR: {str(e)[:60]}"

    return result


print("  Analysing HTTP security headers (HEAD requests):\n")
header_test_urls = ["https://github.com", "https://httpbin.org"]

for url in header_test_urls:
    if REQUESTS_AVAILABLE:
        h = analyze_headers(url, timeout=10)
        if h["error"]:
            print(f"  {url}  ->  {h['error']}")
        else:
            print(f"  {url}  (HTTP {h['status_code']})")
            print(f"    Server  : {h['server'] or 'hidden'}")
            if h["powered_by"]:
                print(f"    Tech    : {h['powered_by']}")
            print(f"    Present : {', '.join(h['headers_present']) or 'none'}")
            print(f"    Missing : {', '.join(h['headers_missing']) or 'none'}")
            print(f"    Risk pts: +{h['header_score']} from missing headers")
    else:
        print(f"  [SKIP] {url}")
    print()

print("=== LESSON 7: URL Hashing with hashlib ===\n")

def hash_url(url: str, algorithm: str = "sha256") -> str:
    """
    Returns the hash of a normalised URL.

    Normalises before hashing:
    - Lowercases the scheme and host
    - Removes trailing slash from root
    - Strips tracking parameters

    Args:
        url       : URL string to hash.
        algorithm : Hash algorithm name. Default "sha256".

    Returns:
        str: Hex digest string.
    """
    # Normalise: lowercase scheme+host, sort query params
    try:
        parsed = urlparse(url.strip().lower())
        # Reconstruct with sorted query params (for consistency)
        query_params = sorted(urllib.parse.parse_qsl(parsed.query))
        clean_query  = urllib.parse.urlencode(query_params)
        normalised   = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, clean_query, ""
        ))
    except Exception:
        normalised = url.lower().strip()

    h = hashlib.new(algorithm)
    h.update(normalised.encode("utf-8"))
    return h.hexdigest()


def build_scan_cache(results: list) -> dict:
    """
    Builds a hash -> result lookup dict from a list of scan results.
    Allows O(1) lookup: "have I already scanned this URL?"

    Args:
        results: List of scan result dicts with 'url' key.

    Returns:
        dict: {sha256_hash: result_dict}
    """
    return {hash_url(r["url"]): r for r in results}


# Demo
test_urls_hash = [
    "https://google.com/search?q=python",
    "https://GOOGLE.COM/search?q=python",    # same after normalisation
    "http://paypa1.xyz/verify",
    "http://evil.tk/login?ssn=123",
]

print("  URL hashing and normalisation:\n")
seen_hashes = {}
for url in test_urls_hash:
    h = hash_url(url)
    duplicate = " <- DUPLICATE (same hash as above)" if h in seen_hashes else ""
    print(f"  {url[:55]}")
    print(f"    sha256: {h[:32]}...{duplicate}")
    seen_hashes[h] = url

print()

# Show all 4 algorithms
url_to_hash = "http://paypa1.xyz/verify"
print(f"  Hash comparison for: {url_to_hash}\n")
for alg in ("md5", "sha1", "sha256", "sha512"):
    digest = hash_url(url_to_hash, alg)
    print(f"  {alg:<8} ({len(digest)*4:>4} bits)  {digest[:48]}...")
print()

print("=== LESSON 8: Regex for URL Pattern Analysis ===\n")

# Pre-compile patterns (faster when used many times)
PATTERNS = {
    "ip_address": re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
        # ^ start  (?:\d{1,3}\.){3}  three groups of 1-3 digits + dot
        # \d{1,3}$ final group  $end
    ),
    "excessive_subdomains": re.compile(
        r"^(?:[^.]+\.){3,}"
        # three or more subdomain levels before the TLD
    ),
    "punycode": re.compile(
        r"xn--"
        # punycode domains (internationalised) used in homograph attacks
        # e.g. xn--pple-43d.com looks like apple.com in some fonts
    ),
    "url_shortener": re.compile(
        r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|"
        r"short\.link|rb\.gy|cutt\.ly|is\.gd)",
        re.IGNORECASE
    ),
    "data_uri": re.compile(
        r"^data:"
        # data:text/html,<script>... used to embed phishing pages inline
    ),
    "javascript_uri": re.compile(
        r"^javascript:",
        re.IGNORECASE
        # javascript: URIs can execute code
    ),
    "double_slash_bypass": re.compile(
        r"/{2,}[^/]"
        # http://evil.com//paypal.com -- double slash tricks
    ),
    "at_sign_trick": re.compile(
        r"@"
        # http://google.com@evil.com -- the real domain is evil.com
        # everything before @ is treated as username:password
    ),
    "encoded_chars": re.compile(
        r"%[0-9a-fA-F]{2}"
        # percent-encoded characters -- used to obfuscate
    ),
}


def _truncate(text, max_len=50):
    return text if len(text) <= max_len else text[:max_len-1] + "~"

def find_url_patterns(url: str) -> list:
    """
    Checks a URL against all regex patterns and returns findings.

    Args:
        url: URL string to analyse.

    Returns:
        list: List of (pattern_name, description) tuples for matches.
    """
    findings = []
    domain   = urlparse(url).netloc.lower().split(":")[0]
    url_lower = url.lower()

    checks = [
        ("ip_address",           domain,    "Domain is a raw IP address"),
        ("excessive_subdomains", domain,    "Domain has 3+ subdomain levels"),
        ("punycode",             domain,    "Domain uses punycode (homograph risk)"),
        ("url_shortener",        domain,    "URL shortener detected (hides real destination)"),
        ("data_uri",             url_lower, "Data URI (inline content, no real server)"),
        ("javascript_uri",       url_lower, "JavaScript URI (executes code)"),
        ("at_sign_trick",        url_lower, "@ sign in URL (real domain is AFTER the @)"),
        ("encoded_chars",        url_lower, "Percent-encoded characters (possible obfuscation)"),
    ]

    for pattern_name, target, description in checks:
        if PATTERNS[pattern_name].search(target):
            findings.append((pattern_name, description))

    return findings


# Test the patterns
print("  Regex pattern analysis:\n")
regex_test_urls = [
    "https://google.com/search?q=python",
    "http://192.168.1.1/admin/login",
    "http://login.secure.paypal.com.evil.xyz/verify",
    "http://bit.ly/2xK9pQr",
    "http://google.com@evil.com/login",
    "http://xn--pple-43d.com",
    "http://evil.com/redirect?url=http%3A%2F%2Fpaypa1.com",
]

for url in regex_test_urls:
    findings = find_url_patterns(url)
    safe_marker = "OK   " if not findings else "WARN "
    print(f"  {safe_marker} {_truncate(url, 50)}")
    for name, desc in findings:
        print(f"         ! {desc}")
    print()

print("=== LESSON 9: EnrichedDetector — Live API Pipeline ===\n")

# Base detector logic (condensed from previous days)
from urllib.parse import urlparse as _urlparse

SCORE_WEIGHTS = {
    "no_https":15,"bad_tld":25,"fake_brand":30,"suspicious_path":10,
    "ip_address":20,"long_subdomain":10,"excessive_hyphens":15,"query_sensitive":30,
    "no_dns":40,"ssl_error":20,"missing_security_headers":15,
    "in_threat_db":60,"url_pattern_match":15,"new_domain": 20,"redirect_chain": 15,
    "redirect_domain_change": 20,"virustotal": 40,
}
BAD_TLDS = (".xyz",".tk",".ml",".win",".top",".click",".gq",".cf",".pw",".buzz")
FAKE_BRANDS = ("paypa1","amaz0n","g00gle","micros0ft","app1e","faceb00k","netfl1x","tw1tter")
SUSPICIOUS_PATHS = ("verify","login","update","confirm","secure","validate","suspend","billing")
SENSITIVE_PARAMS = frozenset({"ssn","password","passwd","pwd","creditcard","cvv","pin"})
WHITELISTED = frozenset({"google.com","github.com","youtube.com","amazon.com","microsoft.com","python.org"})


class EnrichedDetector:
    """
    Extends the base PhishingDetector with live internet lookups.

    Each enrich_* method runs independently and adds to a shared
    result dict, so partial failures don't break the whole scan.

    Usage:
        detector = EnrichedDetector()
        result = detector.scan_full("http://paypa1.xyz/verify", enrich=True)
    """

    def __init__(self, name: str = "EnrichedDetector"):
        self.name = name
        self.history = []

        # Load cache from disk
        try:
            with open("cache.json", "r") as f:
                self.cache = json.load(f)
            print(f"Loaded {len(self.cache)} cached scans.")
        except (FileNotFoundError, json.JSONDecodeError):
            self.cache = {}
    
    def save_cache(self):
      """Save scan cache to disk."""
      with open("cache.json", "w") as f:
        json.dump(self.cache, f, indent=4)
        print(f"Saved {len(self.cache)} cached scans.")
      
    def _local_scan(self, url: str) -> dict:
        """Fast local checks — no network needed."""
        url    = url.strip()
        parsed = _urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        params = {p.split("=")[0].lower() for p in query.split("&") if p}
        base   = ".".join(domain.split(".")[-2:])

        score = 0; reasons = []

        if base in WHITELISTED:
            return {"url":url,"score":0,"risk":"SAFE","reasons":["Trusted domain"],
                    "enrichment":{},"scanned_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        if parsed.scheme != "https":
            score += SCORE_WEIGHTS["no_https"]; reasons.append("HTTP (not HTTPS)")
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

        # Regex patterns
        for name, desc in find_url_patterns(url):
            if name not in ("ip_address",):   # already checked above
                score += SCORE_WEIGHTS.get("url_pattern_match", 10)
                reasons.append(f"Pattern: {desc}")

        score = min(score, 100)

        def classify(s):
            if s == 0: return "SAFE"
            if s <= 30: return "LOW RISK"
            if s <= 60: return "SUSPICIOUS"
            return "PHISHING"

        return {
            "url": url, "score": score, "risk": classify(score),
            "reasons": reasons, "enrichment": {},
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _enrich_dns(self, result: dict) -> None:
        """Adds DNS lookup results to result['enrichment']."""
        domain = _urlparse(result["url"]).netloc.split(":")[0]
        dns    = dns_lookup(domain)
        result["enrichment"]["dns"] = dns

        if not dns["resolves"]:
            result["score"] = min(result["score"] + SCORE_WEIGHTS["no_dns"], 100)
            result["reasons"].append(f"DNS failure: {dns['error']}")
            result["risk"] = "PHISHING"   # non-resolving domain used in URL = phishing

    def _enrich_ssl(self, result: dict) -> None:
        """Adds SSL certificate info to result['enrichment']."""
        url    = result["url"]
        domain = _urlparse(url).netloc.split(":")[0]

        if not url.startswith("https://"):
            result["enrichment"]["ssl"] = {"has_ssl": False, "error": "Not HTTPS"}
            return

        ssl_info = get_ssl_info(domain)
        result["enrichment"]["ssl"] = ssl_info

        if ssl_info.get("error"):
            result["score"] = min(result["score"] + SCORE_WEIGHTS["ssl_error"], 100)
            result["reasons"].append(f"SSL error: {ssl_info['error']}")
        elif ssl_info.get("is_expired"):
            result["score"] = min(result["score"] + SCORE_WEIGHTS["ssl_error"], 100)
            result["reasons"].append("SSL certificate is EXPIRED")
        elif ssl_info.get("is_new_cert"):
            result["score"] = min(result["score"] + 10, 100)
            result["reasons"].append(f"SSL cert only {ssl_info['cert_age_days']} days old (new domain risk)")

    def _enrich_headers(self, result: dict) -> None:
        """Adds HTTP header security analysis to result['enrichment']."""
        h = analyze_headers(result["url"])
        result["enrichment"]["headers"] = h

        if h.get("header_score", 0) >= 20:
            result["score"] = min(result["score"] + SCORE_WEIGHTS["missing_security_headers"], 100)
            result["reasons"].append(
                f"Missing security headers: {', '.join(h.get('headers_missing', []))}"
            )
    
    def _enrich_redirects(self, result: dict) -> None:
        """Checks redirect chains for phishing behavior."""

        request_info = make_request(result["url"])
        result["enrichment"]["redirect"] = request_info

        if request_info.get("error"):
            return

        # 1. Check redirect count
        redirect_count = request_info["redirect_count"]

        if redirect_count >= 3:
            result["score"] = min(
                result["score"] + SCORE_WEIGHTS["redirect_chain"],
                100
            )

        if redirect_count > 0:
            result["reasons"].append(
                f"Redirect chain ({redirect_count} redirects)"
            )

        # 2. Redirected to a different domain?
        original = _urlparse(result["url"]).hostname.lower()
        final    = _urlparse(request_info["final_url"]).hostname.lower()

        # Ignore www.
        original = original.removeprefix("www.")
        final    = final.removeprefix("www.")

        print("Original domain:", original)
        print("Final domain   :", final)

        if original != final:
            result["score"] = min(
                result["score"] + SCORE_WEIGHTS["redirect_domain_change"],
                100
            )
            result["reasons"].append(
                f"Redirected to different domain: {final}"
            )

    def _enrich_threat_api(self, result: dict) -> None:
        """Checks URL against URLhaus and adds domain age scoring."""
        uh = check_urlhaus(result["url"])
        result["enrichment"]["urlhaus"] = uh

        if uh.get("found"):
            result["score"] = min(
                result["score"] + SCORE_WEIGHTS["in_threat_db"],
                100
            )
            result["reasons"].append(
                f"IN THREAT DATABASE: URLhaus [{uh.get('threat', 'malware')}]"
            )
            result["risk"] = "PHISHING"

        # ---------- Domain Age Check ----------
        date_added = uh.get("date_added")

        if date_added:
            try:
                # URLhaus format: 2025-06-28 14:31:12 UTC
                registered = datetime.strptime(
                    date_added,
                    "%Y-%m-%d %H:%M:%S %Z"
                )

                age_days = (datetime.now() - registered).days

                result["enrichment"]["domain_age_days"] = age_days

                if age_days < 30:
                    result["score"] = min(
                        result["score"] + SCORE_WEIGHTS["new_domain"],
                        100
                    )
                    result["reasons"].append(
                        f"New domain ({age_days} days old)"
                    )

            except ValueError:
                pass
        
    def _enrich_virustotal(self, result: dict):
        vt = check_virustotal(
            result["url"],
            "YOUR_API_KEY"
        )

        result["enrichment"]["virustotal"] = vt

        if vt["malicious"] > 0:
            result["score"] = min(
                result["score"] + SCORE_WEIGHTS["virustotal"],
                100
            )
            result["reasons"].append(
                f"VirusTotal: {vt['malicious']} engines flagged this URL"
            )

    def scan_full(self, url: str, enrich: bool = True, timeout: int = 10) -> dict:
        """
        Full scan: local checks + optional live enrichment.

        Args:
            url    : URL to scan.
            enrich : If True, run DNS / SSL / header / API checks.
            timeout: Passed to network calls.

        Returns:
            dict: Full result with 'enrichment' key containing live data.
        """
        # Check cache first
        url_hash = hash_url(url)

        if url_hash in self.cache:
            print(f"    [cache] {url[:50]}")
            return self.cache[url_hash]

        # Step 1: fast local scan
        result = self._local_scan(url)

        if enrich and REQUESTS_AVAILABLE:
            domain = _urlparse(url).netloc.split(":")[0]

            # Step 2: DNS (always)
            self._enrich_dns(result)

            # Step 3: SSL (only for HTTPS)
            if url.startswith("https://"):
                self._enrich_ssl(result)

            # Step 4: HTTP headers (only if DNS resolved)
            dns_ok = result["enrichment"].get("dns", {}).get("resolves", False)
            if dns_ok:
                self._enrich_headers(result)
                self._enrich_redirects(result)

            # Step 5: Threat API (only if DNS resolved and not already max score)
            if dns_ok and result["score"] < 100:
                self._enrich_threat_api(result)
                self._enrich_virustotal(result)

            # Recalculate risk after enrichment
            s = result["score"]
            if   s == 0:   result["risk"] = "SAFE"
            elif s <= 30:  result["risk"] = "LOW RISK"
            elif s <= 60:  result["risk"] = "SUSPICIOUS"
            else:          result["risk"] = "PHISHING"

        self.cache[url_hash] = result
        self.history.append(result)
        return result
    def enrich_many(self, urls: list, delay: float = 1.0) -> list:
        """
        Scans multiple URLs with rate limiting.

        Args:
            urls: List of URLs to scan.
            delay: Seconds to wait between scans.

        Returns:
             list: List of scan results.
        """
        results = []

        for i, url in enumerate(urls):
            print(f"\n[{i+1}/{len(urls)}] Scanning {url}")

            result = self.scan_full(url, enrich=True)
            results.append(result)

            # Wait before the next request to avoid API rate limits
            if i < len(urls) - 1:
                print(f"    Waiting {delay:.1f}s...")
                time.sleep(delay)

        return results

    def print_result(self, result: dict, verbose: bool = True) -> None:
        """Prints a formatted result to the terminal."""
        risk  = result["risk"]
        icons = {"SAFE":"v","LOW RISK":"o","SUSPICIOUS":"!","PHISHING":"X"}
        icon  = icons.get(risk, "?")

        bar_chars = round(result["score"] / 10)
        bar = "X" * bar_chars + "." * (10 - bar_chars)

        print(f"\n  {icon} [{bar}] {result['score']:>3}/100  {risk}")
        print(f"    URL: {result['url']}")

        if verbose:
            for reason in result["reasons"]:
                print(f"         - {reason}")

        # Show enrichment summary
        enrich = result.get("enrichment", {})

        if "dns" in enrich:
            dns = enrich["dns"]
            if dns["resolves"]:
                print(f"    DNS: resolves to {dns['ip']}")
            else:
                print(f"    DNS: FAILED ({dns['error']})")

        if "ssl" in enrich and enrich["ssl"].get("has_ssl"):
            ssl = enrich["ssl"]
            print(f"    SSL: valid until {ssl['valid_until']} ({ssl['days_remaining']} days)")

        if "headers" in enrich and not enrich["headers"].get("error"):
            h = enrich["headers"]
            if h["headers_missing"]:
                print(f"    HDR: missing {', '.join(h['headers_missing'])}")

        if "redirect" in enrich:
              r = enrich["redirect"]

              if not r.get("error"):
                print( f"    REDIRECTS: {r['redirect_count']} -> {r['final_url']}")

        if "urlhaus" in enrich:
            uh = enrich["urlhaus"]
            if uh.get("found"):
                print(f"    TI:  IN URLHAUS DATABASE  threat={uh['threat']}")
            elif not uh.get("error"):
                print(f"    TI:  clean (not in URLhaus)")
        if "domain_age_days" in enrich:
                print(f"    AGE: {enrich['domain_age_days']} days")


# Run the enriched detector
print("  Running EnrichedDetector with live checks...\n")
enr = EnrichedDetector()
atexit.register(enr.save_cache)

scan_urls = [
    "https://httpbin.org/redirect/5",
    "https://httpbin.org/get",
    "http://paypa1-secure-login.xyz/verify",
]
results = enr.enrich_many(scan_urls, delay=1.0)

for result in results:
    enr.print_result(result, verbose=True)
    print()

print("=== LESSON 10: requirements.txt ===\n")

REQUIREMENTS_CONTENT = """\
# PhishingDetector Day 8 - External Libraries
# Install with: pip install -r requirements.txt

# HTTP requests library
requests>=2.28.0,<3.0.0

# Date utilities (for domain age calculation)
python-dateutil>=2.8.0

# Optional: colored terminal output (cross-platform)
# colorama>=0.4.6

# Optional: progress bars
# tqdm>=4.65.0

# Optional: WHOIS lookups (may require system whois tool)
# python-whois>=0.8.0
"""

# Write the file
req_path = Path("requirements.txt")
req_path.write_text(REQUIREMENTS_CONTENT)
print(f"  Written: requirements.txt ({req_path.stat().st_size} bytes)")
print()
print("  Contents:")
for line in REQUIREMENTS_CONTENT.strip().splitlines():
    print(f"    {line}")

print()
print("  Usage:")
print("    pip install -r requirements.txt       install dependencies")
print("    pip freeze > requirements.txt         save current environment")
print("    pip install requests --upgrade        upgrade to latest")
print("    pip list                              show all installed packages")
print()


if __name__ == "__main__":

    print("=" * 60)
    print("  DAY 8 -- External Libraries & APIs -- Summary")
    print("=" * 60)
    print()
    print("  Lessons covered:")
    lessons = [
        ("1",  "Python Package Ecosystem -- pip, PyPI, venv, requirements.txt"),
        ("2",  "requests library -- GET/POST, response objects, error handling"),
        ("3",  "DNS lookup with socket -- resolve domains, detect NXDOMAIN"),
        ("4",  "TLS/SSL inspection -- cert validity, expiry, issuer, self-signed"),
        ("5",  "Threat Intelligence APIs -- URLhaus, Google Safe Browsing pattern"),
        ("6",  "HTTP headers as signals -- HSTS, CSP, X-Frame-Options"),
        ("7",  "URL hashing with hashlib -- dedup, caching, threat feed lookup"),
        ("8",  "Regex pattern analysis -- IP, punycode, @-trick, shorteners"),
        ("9",  "EnrichedDetector -- local scan + DNS + SSL + headers + API pipeline"),
        ("10", "requirements.txt -- pinning deps, reproducible environments"),
    ]
    for num, desc in lessons:
        print(f"  Lesson {num:<3} {desc}")
    print()
    
    print("\n=== Batch Enrichment Demo ===")

    batch_urls = [
    "https://github.com",
    "https://google.com",
    "http://paypa1.xyz/verify"
     ]

    results = enr.enrich_many(batch_urls, delay=1.0)

    for result in results:
     enr.print_result(result)