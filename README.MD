<div align="center">

# 🛡️ BlackTerm PhishScan

### Offensive Intelligence & Threat Scanner

A modern phishing URL intelligence framework built in Python that performs comprehensive reconnaissance and threat analysis against websites using multiple intelligence sources.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

</div>

---

# 📖 Overview

BlackTerm PhishScan is a command-line phishing intelligence framework designed to rapidly analyze suspicious URLs and domains.

Instead of simply checking if a website is online, BlackTerm collects intelligence from multiple sources and combines it into a single professional report.

The project was built to simulate the type of reconnaissance and threat enrichment performed by SOC analysts, incident responders, and blue teams.

---

# ✨ Features

## 🛡 URL Intelligence

- URL validation
- Redirect handling
- HTTP/HTTPS verification
- Website reachability
- HTTP status codes

---

## 🔍 VirusTotal Integration

- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected engines
- Reputation lookup

---

## 🌍 WHOIS Intelligence

- Registrar
- Domain creation date
- Expiration date
- Domain age calculation

---

## 🔒 SSL Certificate Analysis

- Certificate issuer
- Subject
- Valid from
- Valid until
- Days remaining
- Certificate validity

---

## 🌐 DNS Intelligence

Supports lookup of:

- A Records
- AAAA Records
- MX Records
- NS Records
- TXT Records

---

## 📡 IP Intelligence

- IP Resolution
- ASN Lookup
- Network Owner
- Hosting Provider

---

## 📸 Website Screenshot Capture

Automatically captures screenshots of scanned websites using Playwright.

---

## 🧠 AI Threat Summary

Generates a human-readable threat assessment based on all collected intelligence.

Example:

> Target youtube.com was assessed as LOW risk with a score of 0/100. VirusTotal reported no malicious detections. The SSL certificate is valid, DNS records resolve successfully, and the domain belongs to Google LLC.

---

## 📄 Professional Reports

Every scan generates:

- ✅ JSON Report
- ✅ HTML Report
- ✅ Website Screenshot

---

# 🖥 Rich Terminal Dashboard

BlackTerm includes a fully interactive terminal dashboard built with **Rich**.

The dashboard displays:

- Scan Overview
- Intelligence Summary
- Module Status
- Risk Assessment
- AI Threat Summary
- Report Locations

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/cojjjj/blackterm_phishscan.git
cd blackterm_phishscan
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Install the CLI

```bash
pip install -e .
```

Install Playwright browsers

```bash
playwright install
```

---

# 💻 Usage

Interactive Mode

```bash
python main.py
```

CLI Mode

```bash
blackterm scan youtube.com
```

Disable screenshots

```bash
blackterm scan youtube.com --no-screenshot
```

---

# 📊 Example Output

```
BLACKTERM PHISHSCAN v1.0

Target            youtube.com

Risk Score        0 / 100

Threat Level      LOW

VirusTotal        CLEAN

SSL               VALID

WHOIS             COMPLETE

DNS               RESOLVED

Screenshot        CAPTURED

Reports

✔ JSON
✔ HTML
✔ PNG
```

---

# 📁 Project Structure

```
blackterm-phishscan/
│
├── main.py
├── scanner.py
├── scoring.py
├── reporter.py
├── html_reporter.py
├── screenshotter.py
├── virustotal.py
├── whois_lookup.py
├── dns_lookup.py
├── ssl_checker.py
├── ip_lookup.py
├── threat_summary.py
├── utils.py
├── reports/
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

# 🧰 Technology Stack

- Python
- Rich
- Requests
- Playwright
- VirusTotal API
- python-whois
- dnspython
- ipwhois
- Colorama

---

# 🎯 Roadmap

## Completed

- ✅ VirusTotal Integration
- ✅ WHOIS Intelligence
- ✅ SSL Analysis
- ✅ DNS Intelligence
- ✅ IP Intelligence
- ✅ Screenshot Capture
- ✅ HTML Reports
- ✅ JSON Reports
- ✅ AI Threat Summary
- ✅ Rich Dashboard
- ✅ Command Line Interface

---

## Planned Features

- Batch URL Scanning
- PDF Reports
- URLHaus Integration
- AbuseIPDB Integration
- Shodan Integration
- Passive DNS
- Threat Feed Correlation
- Docker Support
- GitHub Actions CI/CD
- Unit Tests
- Plugin System

---

# 📸 Screenshots

### Rich Dashboard

> 

### HTML Report

> *(Add a screenshot here)*

---

# ⚠ Disclaimer

BlackTerm PhishScan is intended for:

- Security Research
- Blue Team Operations
- Incident Response
- Cybersecurity Education
- Authorized Security Assessments

Do not use this tool against systems without permission.

---

# 📄 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**Tyler Deppa**

Cybersecurity Student | Python Developer | Security Researcher

- GitHub: https://github.com/cojjjj
- TryHackMe: https://tryhackme.com/p/cojjjjj

---

<div align="center">

## ⭐ If you found this project useful, consider giving it a star!

Building tools. Learning security. Sharing knowledge.

</div>
