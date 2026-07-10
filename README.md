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

text
SAFE: 3 URL(s)
LOW RISK: 1 URL(s)
SUSPICIOUS: 2 URL(s)
PHISHING: 4 URL(s)


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



## Implemented Dunder Methods

* `__len__()`
* `__str__()`
* `__repr__()`
* `__contains__()`
* `__iter__()`
* `__add__()`
* `__enter__()`
* `__exit__()`



## Day 6 Enhancements

* Added `safe_count` property
* Added `from_dict()` class method
* Added `parse_domain()` static method
* Added `__add__()` to merge detector histories
* Overrode `scan()` in `EmailDetector`
* Automatic removal of `utm_*` tracking parameters
* Improved email phishing analysis
* Cleaner and more modular OOP design



## Project Structure

text
day6_detector.py
├── Helper Functions
├── PhishingDetector Class
├── EmailDetector Class
├── Reports
└── Demo Examples




## Example Output

text
✓ SAFE
⚠ SUSPICIOUS
✕ PHISHING

Average Score : 35.0/100
Total URLs    : 9
Most Dangerous: http://paypa1.secure-login.xyz/verify




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



## Learning Outcome

By completing Day 6, I strengthened my understanding of advanced Python OOP concepts by implementing a realistic phishing detection system. This project demonstrates object-oriented design, reusable code, inheritance, method overriding, custom dunder methods, and practical cybersecurity concepts used in phishing analysis.



### Future Improvements

* Domain reputation lookup
* WHOIS integration
* DNS analysis
* Threat intelligence feeds
* GUI version
* REST API
* Machine Learning–based phishing detection
* Export reports as PDF and CSV

# Day 6 – Utils Module for Phishing Detector

## Overview

This module contains reusable utility functions that support the phishing detector project. It focuses on writing clean, maintainable, and well-documented Python code using modern programming practices such as type hints, docstrings, doctests, guard clauses, lambda functions, and reusable helper functions.

## Features

### URL Analysis

* Detects IP-based domains
* Counts subdomains
* Extracts the base domain
* Removes tracking parameters from URLs
* Detects excessive hyphens in domain names
* Identifies sensitive query parameters

### Formatting Utilities

* Risk score progress bars
* Risk icons
* Result formatting helpers
* Reason list formatting
* Divider and timestamp generators
* Text truncation

### Statistics

* Computes scan statistics
* Generates summary reports
* Groups results by risk level
* Returns the highest-risk URLs
* Builds score histograms
* Calculates percentages

### Python Concepts Practiced

* Pure vs. impure functions
* Type hints
* Comprehensive docstrings
* Doctests
* Guard clauses
* Default parameters
* `*args` and `**kwargs`
* Lambda functions
* Higher-order functions
* Reusable utility modules

## Learning Outcomes

* Built reusable helper functions for larger Python projects
* Improved code readability and maintainability
* Practiced defensive programming techniques
* Learned to validate functionality with doctests
* Applied functional programming concepts to cybersecurity utilities

## Sample Output

```text
compute_stats() output:
total      : 10
safe       : 4
low_risk   : 1
suspicious : 1
phishing   : 4
avg_score  : 39.5/100

summarise():
10 scanned | 4 safe | 1 suspicious | 4 phishing | avg 39.5/100
```

## Skills Demonstrated

* Python Programming
* Modular Code Design
* URL Parsing
* Data Processing
* Functional Programming
* Code Documentation
* Defensive Programming
* Cybersecurity Utility Development

# Day 6 – Configuration Management for Phishing URL Detector

## Overview

This module centralizes all configuration used by the phishing URL detector. It demonstrates Python best practices for managing constants, immutable data structures, enums, validation, environment variables, and structured configuration.

## Features

* Centralized configuration using constants
* Immutable configuration with tuples and frozensets
* Risk scoring using configurable score weights
* Structured phishing checks using `namedtuple`
* Risk classification with `Enum` and `IntEnum`
* Added `Severity` enum (`LOW`, `MEDIUM`, `HIGH`) for categorizing phishing indicators
* Mapping of every security check to a severity level using `CHECK_SEVERITY`
* Configuration validation through `_validate_config()`
* Environment variable overrides for runtime customization
* Support for `PHISH_MAX_SCORE` with range validation (50–200)
* Detection lists for:

  * Suspicious TLDs
  * Fake brand patterns (expanded with additional typosquatting examples)
  * Suspicious URL paths
  * Sensitive query parameters
  * Trusted domains whitelist (expanded with additional trusted domains)
  * Email phishing phrases
* Public API control using `__all__`

## New Improvements

### New Detection Check

* Added `new_domain` check
* Weight: **20**
* Description: **Domain registered < 30 days**

### Expanded Fake Brand Patterns

Added additional typosquatting patterns such as:

* `spotiify`
* `twitterr`
* `netfilx`

### Severity Classification

Introduced a new `Severity` enum:

* `LOW`
* `MEDIUM`
* `HIGH`

Each phishing check is mapped to an appropriate severity level using `CHECK_SEVERITY`.

### Environment Configuration

The maximum phishing score can now be overridden using:

```bash
PHISH_MAX_SCORE=100
```

Validation ensures the value remains between **50** and **200** to prevent invalid configurations.

### Trusted Domains

Expanded the whitelist with additional trusted domains including:

* `wikipedia.org`
* `python.org`
* `docs.python.org`
* `npmjs.com`
* `cloudflare.com`

## Learning Outcomes

This project demonstrates practical use of:

* Constants and naming conventions
* Mutable vs immutable collections
* Tuples and frozensets
* `namedtuple`
* `Enum` and `IntEnum`
* Configuration validation
* Environment variables
* Defensive programming
* Python module exports (`__all__`)

## Technologies

* Python 3
* Standard Library

  * `os`
  * `collections.namedtuple`
  * `enum`

## Sample Output

* Configuration validation
* Risk threshold display
* Score weight breakdown
* Enum demonstration
* Immutable collection examples
* Environment variable overrides
* Validation error reporting for invalid configuration values

## Project Goal

Build a maintainable and production-ready configuration module for a phishing URL detection system while following clean code principles and Python best practices.

# Day 6 – Command Line Phishing Detector

## Overview
Enhanced the phishing detector by adding a command-line interface, email phishing detection, logging, whitelist support, and improved error handling.

## Features
- Scan a single URL or multiple URLs from a file
- Detect phishing emails using subject and body analysis
- Add trusted domains with `--whitelist`
- Display Top N most dangerous URLs
- Filter results using `--min-score`
- Save scan reports to `report.txt`
- Support verbose and quiet logging modes
- Handle invalid inputs and runtime errors gracefully
- Return exit codes for automation

## Usage

```bash
# Scan a URL
python day6_main.py --url http://paypa1.xyz

# Scan URLs from a file
python day6_main.py --file urls.txt --top 5 --verbose

# Scan an email
python day6_main.py --email-subject "PayPal Security Alert" --email-body "Click here immediately to verify your account."

# Trust a domain
python day6_main.py --url https://google.com --whitelist google.com
```

## Skills Practiced
- Python argparse
- Object-Oriented Programming (OOP)
- Inheritance
- Exception Handling
- Logging
- File Handling
- Command-Line Interface (CLI)
- Email & URL Phishing Detection

# Day 7 – Phishing Detector CLI

## Overview
Built a command-line interface (CLI) for the phishing URL detector using Python's `argparse` module. The application supports scanning URLs, interactive mode, configuration management, reporting, and multiple output formats.

## Features
- Scan a single URL or a file containing multiple URLs.
- Interactive REPL mode for continuous URL scanning.
- Filter scan results using the `--search` option.
- Display live progress while scanning large URL files.
- Export scan results in **Table**, **JSON**, and **CSV** formats.
- Save detector configuration using `--save-config`.
- Support for stdin piping.
- Configurable whitelist and blocked TLDs.
- Colored terminal output based on risk level.
- Command logging with configurable log levels.
- Modular CLI using subcommands (`scan`, `interactive`, `config`, `report`, `email`).

## Commands

```bash
python day7_cli.py scan --url https://example.com
python day7_cli.py scan --file urls.txt
python day7_cli.py scan --file urls.txt --search paypal
python day7_cli.py interactive
python day7_cli.py config --show-all
python day7_cli.py config --save-config my_config.json
