url = "https://paypal1.secure-login.xyz/verify"
email = "Dear Customer, verify your account NOW!"

print("URL:", url)
print("Email:", email)
print()

print("Lowercase URL:", url.lower())
print("Starts with https?", url.startswith("https"))
print("Starts with http?", url.startswith("http"))
print("Number of dots in URL:", url.count("."))
print("Number of hyphens in URL:", url.count("-"))

clean = url.replace("http://", "")
print("URL without http://:", clean)

parts = url.split("/")
print("URL split by /:", parts)

print("Position of 'login':", url.find("login"))
print()

phishing_keywords = [
    "verify your account",
    "act now",
    "suspended",
    "click here immediately",
    "you have won",
    "enter your password"
]

for i, keyword in enumerate(phishing_keywords):
    print(f"Keyword {i+1}: {keyword}")

print()

test_url = "http://paypa1.xyz"

if test_url.startswith("https"):
    print("URL uses HTTPS — encrypted connection")
else:
    print("URL does NOT use HTTPS — unsafe connection!")

domain = test_url.replace("http://", "").split("/")[0]
print("Domain:", domain)

if len(domain) > 20:
    print("Domain is very long — suspicious!")
else:
    print("Domain length looks normal")

print()


def contains_keyword(text, keyword):
    """
    Returns True if the keyword is found in the text.
    """
    return keyword.lower() in text.lower()


def scan_for_keywords(text, keyword_list):
    """
    Loops through every keyword.
    Returns a list of keywords that were found.
    """
    found = []

    for keyword in keyword_list:
        if contains_keyword(text, keyword):
            found.append(keyword)

    return found


def basic_url_check(url):
    """
    Performs basic phishing checks on a URL.
    Returns the number of warnings.
    """
    warnings = 0

    print(f"Checking: {url}")

    if not url.startswith("https"):
        print("No HTTPS detected")
        warnings += 1

    suspicious_words = ["verify", "login", "secure", "update", "confirm"]

    for word in suspicious_words:
        if word in url.lower():
            print(f"Suspicious word found: '{word}'")
            warnings += 1

    if url.count(".") > 3:
        print("Too many dots — possible subdomain abuse")
        warnings += 1

    if warnings == 0:
        print("No issues found")

    return warnings


print()

found_keywords = scan_for_keywords(email, phishing_keywords)

if found_keywords:
    print(f"Found {len(found_keywords)} phishing keyword(s) in the email:")
    for kw in found_keywords:
        print(f"→ '{kw}'")
else:
    print("No phishing keywords found in the email")

print()

test_urls = [
    "http://paypa1.secure-login.xyz/verify",
    "https://www.google.com",
    "http://free-prize.win/claim/now",
]

for test in test_urls:
    count = basic_url_check(test)
    print(f"Total warnings: {count}")
    print()
    

phishing_keywords = [
    "verify",
    "urgent",
    "password",
    "click",
    "login",
    "bank",
    "account",
    "security",
    "confirm",
    "update"
]

sample_email = """
Dear Customer,

Your bank account has been suspended.
Please click the link below to verify and update your login information immediately.

Thank you.
"""

print("=== Keyword Check ===")
for word in phishing_keywords:
    if word.lower() in sample_email.lower():
        print("Found:", word)



def basic_url_check(url):

    suspicious = False

    if "-" in url:
        print("Hyphen found")
        suspicious = True

    if url.count(".") > 2:
        print("Too many dots")
        suspicious = True

    
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    
    parts = domain.split(".")

    for part in parts:
        if part.isdigit():
            print("IP Address detected")
            suspicious = True
            break

    if suspicious:
        return "Suspicious"
    else:
        return "Looks Safe"


print("\n=== URL Test ===")
print(basic_url_check("http://192.168.1.1/login"))



def check_domain_length(url):

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    if len(domain) > 20:
        return "Suspicious"
    else:
        return "Normal"


print("\n=== Domain Length Check ===")
print(check_domain_length("https://paypal-secure-login-update.com"))
print(check_domain_length("https://google.com"))




print("\n=== URL Scanner ===")

while True:

    user_url = input("Enter URL (or type 'quit'): ")

    if user_url.lower() == "quit":
        print("Program Ended.")
        break

    print("Result:", basic_url_check(user_url))
    print("Domain Length:", check_domain_length(user_url))
    print()
 