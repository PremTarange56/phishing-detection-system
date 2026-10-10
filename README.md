# Phishing Detection System

A rule-based URL analysis web application developed as a college project for Computer and Network Security (CNS).

> **Important Security Notice:** This system performs **STATIC URL ANALYSIS ONLY**. It parses and examines URL characteristics syntactically and heuristically; it **never connects to, crawls, visits, or executes code from submitted URLs**. This ensures the analysis environment remains safe even when handling potentially malicious links.
>
> **Disclaimer:** This tool uses heuristic rule-based checks for educational and threat awareness purposes. It **cannot guarantee** that any URL is 100% safe or malicious. It is designed to assist users in identifying common deception patterns used in phishing attacks.

---

## Project Overview

The **Phishing Detection System** is a lightweight, practical cybersecurity web application built with Python Flask, HTML5, CSS3, JavaScript, and SQLite. The primary goal is to evaluate candidate website URLs and classify their risk level as **LOW (Safe)**, **SUSPICIOUS**, or **HIGH RISK (Phishing)**, while giving users a clear, transparent breakdown of the exact security indicators that influenced the decision.

---

## Problem Statement

Phishing remains one of the primary attack vectors in modern social engineering and cybercrime. Attackers create deceptive domain names, clone login pages, and distribute malicious links via email, SMS, and messaging platforms. Non-technical users often lack the awareness to spot subtle URL discrepancies—such as missing HTTPS, raw IP addresses in place of domain names, deceptive hyphenation, brand name typosquatting, or excessive subdomains.

Many commercial threat intelligence platforms rely on paid APIs, blackbox machine learning models, or active web crawling. There is a need for an open, understandable, educational, and self-contained system suitable for college-level demonstration that clearly explains the cryptographic and structural indicators of URL-based threats.

---

## Objectives

1. **Practical URL Inspection:** Build a functional web tool that extracts structural, syntactic, and security features from URLs.
2. **Transparent Scoring Model:** Implement an explainable, rule-based risk evaluation algorithm (0–100 scale) with no blackbox dependencies.
3. **CNS Educational Demonstration:** Showcase foundational Computer and Network Security principles (TLS/SSL encryption, DNS spoofing indicators, XSS defense, SQL injection prevention).
4. **Audit Logging & Analytics:** Store inspection histories in SQLite using parameterized queries for forensic review and statistical reporting.
5. **Security Awareness:** Provide a dedicated learning portal to educate users on recognizing phishing indicators and defensive best practices.

---

## Features

- **Static URL Analysis:** Safely inspects input strings without sending HTTP/TCP requests to untrusted targets.
- **Rule-Based Risk Engine:** Multi-factor heuristic inspection assessing protocol, host, domain structure, path, and keywords.
- **Three-Tier Risk Classification:**
  - 🟢 **LOW RISK (Score 0–29):** URL exhibits typical characteristics of legitimate web services.
  - 🟡 **SUSPICIOUS (Score 30–59):** URL contains multiple anomalies warranting user caution.
  - 🔴 **HIGH RISK (Score 60–100):** URL exhibits strong indicators of brand impersonation, credential harvesting, or deceptive structure.
- **Transparent Decision Explanations:** Displays positive security attributes as well as flagged risk reasons with individual point weights.
- **Interactive Web Interface:** Modern, responsive dark-themed dashboard with quick-test sample URLs.
- **Dashboard Visualizations:** Real-time distribution breakdown powered by Chart.js.
- **Analysis History:** Searchable inspection audit log with persistent SQLite storage.
- **Educational Resource ("Learn" Tab):** In-depth guides covering common attack tactics and preventative hygiene.
- **Robust REST API:** Clean JSON endpoints for programmatic URL analysis and statistics.

---

## Technologies Used

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | HTML5, CSS3, Modern JavaScript | Semantic layout, cybersecurity UI, dynamic DOM updates |
| **Styling** | Vanilla CSS (Dark Theme, Glassmorphism) | High-contrast, clean visual design without heavy external frameworks |
| **Backend** | Python 3, Flask | Routing, request validation, middleware security headers |
| **Data Storage** | SQLite 3 | Embedded database for analysis records and aggregate metrics |
| **Charts** | Chart.js (CDN) | Interactive risk level distribution donut chart |
| **URL Parsing** | Python `urllib.parse`, `ipaddress`, `re` | Standard library parsing and regex pattern detection |

---

## How It Works

```
[ User Input URL ]
        │
        ▼
[ Client-Side Validation (JavaScript) ]
        │
        ▼ (POST /api/analyze)
[ Flask Application (app.py) ]
        │  ├── Input Sanitization & Length Limits
        │  └── Security Headers Middleware
        ▼
[ Heuristic Engine (detector.py) ]
        │  ├── Feature Extraction (Protocol, Host, Subdomains, TLD, Keywords)
        │  ├── Rule Evaluation & Weight Accumulation
        │  └── Risk Level Assignment (LOW / SUSPICIOUS / HIGH)
        ▼
[ Database Manager (database.py) ]
        │  └── Parameterized INSERT into SQLite (phishing.db)
        ▼
[ JSON Response & UI Render ]
        └── Risk Badge, Score Bar, Explanations, Feature Matrix
```

---

## URL Features Analyzed

The system extracts and inspects 10 core dimensions from each candidate URL:

1. **Protocol / Scheme:** Verifies whether `https://` (TLS/SSL encryption) is enforced or insecure `http://` is used.
2. **IP Address Hostname:** Flags raw IPv4 addresses used in place of legitimate registered domain names.
3. **URL Length:** Evaluates overall string length (URLs > 75 characters often disguise malicious parameters).
4. **Domain Length:** Detects unnaturally long hostnames designed to obscure genuine endpoints.
5. **Subdomain Depth:** Counts dot-delimited subdomain levels (e.g., `login.secure.update.bank.com`).
6. **Hyphen Count:** Detects excessive hyphens in domain names used for deceptive visual mimicking (e.g., `paypal-secure-login`).
7. **Special Characters:** Inspects `@` symbols (URL authentication bypass), `//` redirects, and suspicious query parameters.
8. **Suspicious / Free TLDs:** Flags top-level domains frequently abused in automated phishing campaigns (`.tk`, `.ml`, `.ga`, `.cf`, `.top`).
9. **Credential Harvesting Keywords:** Scans path and query strings for terms like `login`, `verify`, `banking`, `secure`, `update`, `account`.
10. **Brand Impersonation Patterns:** Detects well-known brand names (PayPal, Google, Apple, Microsoft, Amazon, Netflix) embedded as subdomains or prefixes on third-party domains.

---

## Risk Scoring

Each triggered heuristic adds a defined penalty weight to the cumulative risk score (capped at 100):

| Heuristic Indicator | Security Rationale | Penalty Points |
|---|---|:---:|
| **Missing HTTPS** | Plaintext HTTP lacks cryptographic encryption and certificate validation | +15 |
| **IP Address as Host** | Avoids DNS registration to bypass reputation filters and domain blacklists | +25 |
| **Excessive URL Length (>75 chars)** | Long query strings or paths used to conceal true destinations | +10 |
| **Deep Subdomain Nesting (>3 levels)** | Masks true root domain behind deceptive subdomain chains | +15 |
| **Hyphens in Domain (>1)** | Combines brand keywords with deceptive prefixes | +5 to +10 |
| **`@` Symbol in URL** | Causes browsers to interpret preceding text as user credentials | +20 |
| **Double Slash (`//`) in Path** | Path redirection technique used to confuse parsers | +10 |
| **Suspicious / Free TLD** | Top-level domains with minimal registrar vetting (`.tk`, `.ml`, etc.) | +20 |
| **Credential Keywords** | Terms targeting authentication credentials or account access | +10 to +30 |
| **Brand Impersonation** | Recognized corporate marks embedded on unauthorized domains | +20 |

### Score Thresholds
- **0 – 29:** 🟢 **LOW RISK** (Likely legitimate)
- **30 – 59:** 🟡 **SUSPICIOUS** (Potential anomalies; caution advised)
- **60 – 100:** 🔴 **HIGH RISK** (Strong indicators of phishing)

---

## CNS Concepts Used

This project directly demonstrates key concepts from Computer and Network Security curricula:

- **Transport Layer Security (TLS/SSL):** Distinguishing encrypted HTTPS transport from unencrypted HTTP that is vulnerable to eavesdropping and Man-in-the-Middle (MitM) attacks.
- **DNS & Domain Spoofing:** Examining Domain Name System structures, subdomains, and how attackers exploit DNS hierarchies to deceive victims.
- **Social Engineering & Phishing:** Technical mechanics of typosquatting, credential harvesting, and brand impersonation.
- **SQL Injection Prevention:** Enforcing parameterized queries and prepared statements across all SQLite database interactions.
- **Cross-Site Scripting (XSS) Mitigation:** Context-aware HTML entity encoding on user-supplied inputs and strict Jinja2 templating.
- **HTTP Security Headers:** Applying defense-in-depth headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`).
- **Input Sanitization & Validation:** Enforcing length boundaries, scheme verification, and format assertions prior to backend processing.

---

## Project Structure

```
phishing-detection-system/
├── app.py                  # Flask web server, API routes, security headers
├── detector.py             # Feature extraction and rule-based heuristic scoring engine
├── database.py             # SQLite database layer with parameterized queries
├── test_detector.py        # Automated test suite for validation and verification
├── requirements.txt        # Python package dependencies (Flask, Werkzeug)
├── run.bat                 # 1-click Windows launcher script
├── README.md               # Complete project documentation and guide
├── .gitignore              # Git ignore rules for caches, venvs, and local DBs
├── database/
│   └── .gitkeep            # Tracks database folder structure without committing .db
├── templates/
│   ├── index.html          # Main analysis dashboard and scanner UI
│   ├── history.html        # Historical inspection audit log page
│   └── learn.html          # Educational guide on phishing prevention
└── static/
    ├── css/
    │   └── style.css       # Custom dark-theme cybersecurity design
    └── js/
        └── script.js       # Asynchronous API integration and Chart.js handler
```

---

## Installation

### Prerequisites
- Python 3.8 or higher installed on your system
- Git (optional, for cloning)

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Rajdeep622/phishing-detection-system.git
   cd phishing-detection-system
   ```

2. **(Optional) Create and activate a virtual environment:**
   - **Windows:**
     ```powershell
     python -m venv venv
     venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Project

### Windows Quick Launcher
Simply double-click the **`run.bat`** file located in the root directory.

### From Command Line / Terminal
```bash
python app.py
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Testing

Run the automated test suite to verify the rule engine against legitimate, suspicious, and high-risk URL patterns:

```bash
python test_detector.py
```

### Sample Validation Cases

| Test URL | Expected Risk | Rationale |
|---|:---:|---|
| `https://example.com` | **LOW** | Valid HTTPS, clean registered domain, no keywords |
| `http://192.168.1.100/login/verify` | **HIGH** | Raw IP address, missing HTTPS, sensitive keywords |
| `http://example.com/verify-account-login` | **SUSPICIOUS** | Insecure HTTP, multiple authentication keywords |
| `http://paypal-secure-login.com/update` | **HIGH** | Insecure HTTP, brand impersonation, deceptive hyphens |
| `http://free-gift-card.tk/claim` | **HIGH** | Insecure HTTP, suspicious free TLD (`.tk`), deceptive terms |

---

## Limitations

- **Static Analysis Scope:** The system analyzes URL structure only; it does not render JavaScript, inspect page DOM, or evaluate SSL certificate chains.
- **Zero-Day Phishing Domains:** Highly novel domains that utilize standard HTTPS on reputable TLDs without common keywords may score as low risk.
- **Heuristic Approximations:** Rule-based scoring uses weighted heuristics rather than live threat intelligence reputation feeds (e.g., Google Safe Browsing, VirusTotal).
- **Legitimate Complex URLs:** Some legitimate web applications using deep subdomains or hyphenated tracking links may receive elevated suspicious scores.

---

## Future Scope

- **WHOIS & Domain Age Integration:** Querying domain registration records to penalize newly registered domains (NRDs).
- **SSL/TLS Certificate Inspection:** Validating certificate authorities, validity periods, and issuer credibility.
- **Live Reputation API Integration:** Optional connectors for Google Safe Browsing and VirusTotal APIs.
- **Machine Learning Augmentation:** Training an ensemble model (Random Forest / XGBoost) on labeled datasets like PhishTank to complement heuristic scoring.
- **Browser Extension:** Packaging the detection algorithm into a Chromium extension for real-time browsing protection.

---

## Team/College Project Information

- **Course:** Computer and Network Security (CNS)
- **Project Title:** Phishing Detection System
- **Repository:** [https://github.com/Rajdeep622/phishing-detection-system](https://github.com/Rajdeep622/phishing-detection-system)
- **Author / Developer:** Rajdeep Patel ([@Rajdeep622](https://github.com/Rajdeep622))
