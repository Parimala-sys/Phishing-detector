# Phishing Detection System 🛡️

A Python-based phishing detection system built as part of my cybersecurity learning journey.

## Progress

### Day 1 - Python Basics
- Variables and Data Types
- User Input
- Functions
- Loops
- Conditional Statements

### Day 2 - URL Parsing
- URL Parsing using `urllib.parse`
- Domain Extraction
- Query Parameter Analysis
- Basic URL Validation

### Day 3 - File Handling & Phishing Scanner
- User Input Validation
- Read URLs from a file
- Write scan results to a file
- Detect phishing URLs using:
  - HTTPS check
  - Suspicious TLD detection
  - Fake brand detection
  - Suspicious path detection
  - IP address detection
- Interactive menu system
- Save scan results with date and time
- View saved scan results
- URL scan summary (SAFE, SUSPICIOUS, PHISHING)

# Day 4 - Phishing URL Detector

## Overview

This project extends the phishing URL detector by introducing score-based risk analysis using Python dictionaries and lists.

## Features

- Dictionary-based scan results
- Score-based phishing detection
- Risk levels:
  - SAFE
  - LOW RISK
  - SUSPICIOUS
  - PHISHING
- URL filtering
- Sorting URLs by risk score
- Find the safest URL
- Group URLs by risk level
- Score histogram
- Top 3 most dangerous URLs
- Generate scan reports
- Save reports to a text file

## Technologies Used

- Python 3
- urllib.parse
- datetime

## Learning Outcomes

- Dictionaries
- Nested dictionaries
- Lists of dictionaries
- Sorting with `sorted()`
- Using `min()`
- Using `lambda`
- Data grouping
- Score-based analysis
- Report generation
- File handling

## Sample Output

```text
SAFE: 3 URL(s)
LOW RISK: 1 URL(s)
SUSPICIOUS: 2 URL(s)
PHISHING: 4 URL(s)
```

## Future Improvements

- Email phishing detection
- WHOIS lookup
- Domain age analysis
- VirusTotal API integration
- Machine learning-based phishing detection

- # Day 5 – Object-Oriented Phishing Detector 🛡️

## Overview

On Day 5, I refactored my phishing URL detection project using **Object-Oriented Programming (OOP)** in Python. Instead of using standalone functions, I organized the project into reusable classes with methods, making the code more modular, maintainable, and scalable.

## Topics Covered

* Python Classes and Objects
* Constructors (`__init__`)
* Instance and Class Attributes
* Encapsulation
* Instance Methods
* Magic Methods (`__str__`, `__len__`)
* Inheritance
* Method Reusability

## Features Implemented

### PhishingDetector Class

* Scan individual URLs
* Batch scan URLs from a file
* Calculate phishing risk score
* Classify URLs (Safe, Low Risk, Suspicious, Phishing)
* Maintain scan history
* Generate scan reports
* Save reports to a text file
* Display detector statistics
* Return the top **N** most dangerous URLs
* Search scan history by keyword
* Customize detectors with new fake brands and risky TLDs
* Support `len(detector)` using the `__len__()` magic method

### EmailDetector (Inheritance)

* Inherits all functionality from `PhishingDetector`
* Detects phishing language in email subjects and bodies
* Identifies urgency phrases
* Detects payment scam phrases such as:

  * Wire Transfer
  * Gift Card
  * Bitcoin
* Scans URLs contained within email messages
* Produces an overall phishing risk score for emails

## Skills Practiced

* Object-Oriented Programming (OOP)
* Code Organization
* Python Magic Methods
* Inheritance
* List Comprehensions
* Sorting and Searching
* File Handling
* URL Analysis
* Risk Scoring

## Learning Outcome

This project strengthened my understanding of Python OOP concepts by transforming a procedural phishing detector into a reusable and extensible security tool. I also learned how inheritance, custom methods, and object state management can be used to build scalable cybersecurity applications.

**Next Goal:** Enhance the detector with domain reputation checks, WHOIS analysis, IP intelligence, and machine learning-based phishing detection.

# 🛡️ Day 6 – Advanced Object-Oriented Phishing Detector

## Overview

Day 6 focuses on applying advanced **Object-Oriented Programming (OOP)** concepts in Python by building a feature-rich phishing detection system.

The detector analyzes URLs and email content for phishing indicators, maintains scan history, generates reports, supports inheritance, demonstrates Python magic methods (dunder methods), and follows clean, production-style code organization.

---

## Features

* Analyze URLs for phishing indicators
* Calculate phishing risk score (0–100)
* Classify URLs as:

  *  SAFE
  *  LOW RISK
  *  SUSPICIOUS
  *  PHISHING
* Scan multiple URLs
* Scan URLs from a text file
* Generate detailed scan reports
* Save reports to a text file
* Search previous scan history
* Display top dangerous URLs
* Merge scan histories using the `+` operator
* Email phishing detection
* Automatic removal of `utm_*` tracking parameters before scanning
* Extract base domains from URLs
* Customizable phishing rules and trusted domains

---

## OOP Concepts Covered

* Classes and Objects
* Constructors (`__init__`)
* Instance Variables
* Class Variables
* Private Methods
* Properties (`@property`)
* Class Methods (`@classmethod`)
* Static Methods (`@staticmethod`)
* Inheritance
* Method Overriding
* Context Managers (`with`)
* Magic (Dunder) Methods

---

## Implemented Dunder Methods

* `__len__()`
* `__str__()`
* `__repr__()`
* `__contains__()`
* `__iter__()`
* `__add__()`
* `__enter__()`
* `__exit__()`

---

## Day 6 Enhancements

* Added `safe_count` property
* Added `from_dict()` class method
* Added `parse_domain()` static method
* Added `__add__()` to merge detector histories
* Overrode `scan()` in `EmailDetector`
* Automatic removal of `utm_*` tracking parameters
* Improved email phishing analysis
* Cleaner and more modular OOP design

---

## Project Structure

```text
day6_detector.py
├── Helper Functions
├── PhishingDetector Class
├── EmailDetector Class
├── Reports
└── Demo Examples
```

---

## Example Output

```text
✓ SAFE
⚠ SUSPICIOUS
✕ PHISHING

Average Score : 35.0/100
Total URLs    : 9
Most Dangerous: http://paypa1.secure-login.xyz/verify
```

---

## Skills Practiced

* Advanced Python OOP
* Clean Code Principles
* URL Parsing
* Email Security Analysis
* Report Generation
* File Handling
* Inheritance and Polymorphism
* Method Overriding
* Python Magic Methods
* Real-world Cybersecurity Project Development

---

## Learning Outcome

By completing Day 6, I strengthened my understanding of advanced Python OOP concepts by implementing a realistic phishing detection system. This project demonstrates object-oriented design, reusable code, inheritance, method overriding, custom dunder methods, and practical cybersecurity concepts used in phishing analysis.

---

### Future Improvements

* Domain reputation lookup
* WHOIS integration
* DNS analysis
* Threat intelligence feeds
* GUI version
* REST API
* Machine Learning–based phishing detection
* Export reports as PDF and CSV


