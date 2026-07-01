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
