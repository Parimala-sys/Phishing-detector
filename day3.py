
print("=== LESSON 1: User Input ===")

# input() pauses the program and waits for user to type
name = input("Enter your name: ")
print(f"Hello, {name}! Welcome to Phishing Detector 🛡️")
print()

# Input is always a STRING even if user types a number
age = input("Enter your age: ")
print(f"You are {age} years old")
print(f"Type of age: {type(age)}")   # <class 'str'>

# Convert to integer if needed
age_number = int(age)
print(f"Next year you'll be: {age_number + 1}")
print()


print("=== LESSON 2: Input Validation ===")

def get_valid_url():
    """
    Keeps asking until user enters a valid URL.
    A valid URL must:
    1. Not be empty
    2. Start with http:// or https://
    3. Be at least 10 characters long
    """
    while True:
        url = input("Enter a URL to check: ").strip()

        if url == "":
            print("URL cannot be empty. Try again.")

        elif not url.startswith("http"):
            print("URL must start with http:// or https://")

        elif len(url) < 10:
            print("URL must be at least 10 characters long.")

        else:
            print(f"Valid URL received: {url}")
            return url

url = get_valid_url()
print(f"You entered: {url}")
print()


print("=== LESSON 3: Writing Files ===")

# Create a file and write URLs into it
# "w" mode = write (creates file if not exists, overwrites if exists)

with open("my_urls.txt", "w") as f:
    f.write("https://www.google.com/search?q=python\n")
    f.write("http://paypa1.secure-login.xyz/verify\n")
    f.write("https://amazon.com/products?id=123\n")
    f.write("http://192.168.1.1/admin/login\n")
    f.write("https://github.com/user/phishing-detector\n")
    f.write("http://free-prize.win/claim?user=you\n")
    f.write("https://youtube.com/watch?v=abc123\n")
    f.write("http://micros0ft-update.tk/download\n")
    f.write("https://facebook.com/profile?id=456\n")
    f.write("http://bank-secure-login.xyz/update?ssn=123\n")

print("File 'my_urls.txt' created with 10 URLs!")
print()


print("=== LESSON 4: Reading Files ===")

# "r" mode = read
with open("my_urls.txt", "r") as f:
    content = f.read()   # reads entire file as one string

print("Full file content:")
print(content)


# Read line by line
print("Line by line:")
with open("my_urls.txt", "r") as f:
    for line_number, line in enumerate(f, start=1):
        clean_line = line.strip()   # remove \n at end
        print(f"  Line {line_number}: {clean_line}")

print()


print("=== LESSON 5: Processing URLs from File ===")

from urllib.parse import urlparse
from datetime import datetime

BAD_TLDS = [".xyz", ".tk", ".ml", ".win", ".top", ".click"]
FAKE_BRANDS = ["paypa1", "amaz0n", "g00gle", "micros0ft", "app1e"]
SUSPICIOUS_PATH_WORDS = ["verify", "login", "update", "confirm", "secure"]

def quick_scan(url):
    """
    Scans a single URL and returns (url, risk, reasons)
    """
    url = url.strip()
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Check 1: No HTTPS
    if parsed.scheme != "https":
        reasons.append("No HTTPS")

    # Check 2: Bad TLD
    for tld in BAD_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Bad TLD: {tld}")

    # Check 3: Fake brand
    for brand in FAKE_BRANDS:
        if brand in domain:
            reasons.append(f"Fake brand: {brand}")

    # Check 4: Suspicious path
    for word in SUSPICIOUS_PATH_WORDS:
        if word in path:
            reasons.append(f"Suspicious path: {word}")

    # Check 5: IP address
    parts = domain.replace(":", "").split(".")
    if sum(1 for p in parts if p.isdigit()) >= 3:
        reasons.append("IP address used")

    # Determine risk level
    if len(reasons) == 0:
        risk = "SAFE"
    elif len(reasons) <= 2:
        risk = "SUSPICIOUS"
    else:
        risk = "PHISHING"

    return url, risk, reasons


# Read URLs from file and scan each one
print("Scanning all URLs from file...\n")

with open("my_urls.txt", "r") as f:
    urls = f.readlines()

for url in urls:
    url = url.strip()
    if url:   # skip empty lines
        scanned_url, risk, reasons = quick_scan(url)
        print(f"URL    : {scanned_url[:55]}")
        print(f"Result : {risk}")
        if reasons:
            print(f"Reasons: {', '.join(reasons)}")
        print("-" * 50)

print()


print("=== LESSON 6: Saving Results ===")
current_time = datetime.now()

# "a" mode = append (adds to file without overwriting)
with open("scan_results.txt", "w") as result_file:
    result_file.write("PHISHING DETECTOR - SCAN RESULTS\n")
    result_file.write(f"Scan Date & Time: {current_time}\n")
    result_file.write("=" * 40 + "\n\n")

    with open("my_urls.txt", "r") as url_file:
        for url in url_file:
            url = url.strip()
            if url:
                scanned_url, risk, reasons = quick_scan(url)
                result_file.write(f"URL    : {scanned_url}\n")
                result_file.write(f"Result : {risk}\n")
                if reasons:
                    result_file.write(f"Reasons: {', '.join(reasons)}\n")
                result_file.write("-" * 40 + "\n")

print("Results saved to 'scan_results.txt'!")
print()


print("=== LESSON 7: Interactive Menu ===")

def show_menu():
    print("\n--- PHISHING DETECTOR MENU ---")
    print("1. Scan a single URL")
    print("2. Scan all URLs from file")
    print("3. Add a URL to file")
    print("4. Quit")
    print("5. View saved results")
    return input("Choose option (1-5): ").strip()

def run_program():
    while True:
        choice = show_menu()

        # Option 1: Scan a single URL
        if choice == "1":
            url = input("Enter URL to scan: ").strip()
            scanned_url, risk, reasons = quick_scan(url)

            print(f"\nResult : {risk}")
            if reasons:
                print(f"Reasons: {', '.join(reasons)}")

        # Option 2: Scan all URLs from file
        elif choice == "2":
            print("\nScanning file...\n")

            total = 0
            safe_count = 0
            suspicious_count = 0
            phishing_count = 0

            with open("my_urls.txt", "r") as f:
                for url in f:
                    url = url.strip()

                    if url:
                        scanned_url, risk, reasons = quick_scan(url)

                        print(f"{risk} → {url}")

                        total += 1

                        if risk == "SAFE":
                            safe_count += 1
                        elif risk == "SUSPICIOUS":
                            suspicious_count += 1
                        elif risk == "PHISHING":
                            phishing_count += 1

            print("\n========== SCAN SUMMARY ==========")
            print(f"Total URLs Scanned : {total}")
            print(f"SAFE               : {safe_count}")
            print(f"SUSPICIOUS         : {suspicious_count}")
            print(f"PHISHING           : {phishing_count}")
            print("==================================")

        # Option 3: Add a new URL
        elif choice == "3":
            new_url = input("Enter URL to add: ").strip()

            with open("my_urls.txt", "a") as f:
                f.write(new_url + "\n")

            print(f"Added: {new_url}")

        # Option 4: Quit
        elif choice == "4":
            print("Goodbye!")
            break

        # Option 5: View saved results
        elif choice == "5":
            print("\n=== SAVED SCAN RESULTS ===\n")

            try:
                with open("scan_results.txt", "r") as f:
                    print(f.read())

            except FileNotFoundError:
                print("No scan results found. Please scan URLs first.")

        # Invalid option
        else:
            print("Invalid option. Choose 1-5.")

            # Run the interactive program
run_program()






