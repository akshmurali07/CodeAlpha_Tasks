# Task 3: Secure Coding Review

A security audit tool and vulnerability report for a Python web application, built as part of the **CodeAlpha Cyber Security Internship**.

## Overview

This project involves auditing a deliberately vulnerable Python web application to identify common security flaws. A static analysis scanner was built to automatically detect vulnerabilities and generate a detailed HTML report with findings and remediation steps.

## Features

- Automated static analysis scanner for Python code
- Detects common vulnerabilities including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Hardcoded credentials
  - Insecure direct object references
  - Missing input validation
- Generates a detailed HTML security report
- Includes remediation recommendations for each finding

## Tech Stack

- Python (static analysis scanner)
- HTML (security report)

## How to Run

1. Run the security scanner against the vulnerable app:
 python security_scanner.py
2. Open the generated `security_report.html` in your browser to view the full findings and recommendations

## What I Learned

- How to identify common security vulnerabilities in Python web applications
- How static analysis tools work under the hood
- The importance of secure coding practices during development
- How to document security findings professionally with remediation steps
