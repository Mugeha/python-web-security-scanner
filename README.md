# Python Web Security Scanner

A comprehensive, automated web application security scanner that detects common vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), and security misconfigurations.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

---

## Features

### Core Scanning Capabilities
- **Web Crawler** - Automatically discovers pages, forms, and parameters
- **SQL Injection Detection** - Error-based, Boolean-based, and Time-based
- **XSS Detection** - Reflected and Stored Cross-Site Scripting
- **Security Headers Analysis** - Checks for missing security headers
- **Professional Reports** - Generates HTML and JSON reports

### Detection Techniques
- **SQL Injection:**
  - Error-based detection (database error messages)
  - Boolean-based blind SQLi (true/false responses)
  - Time-based blind SQLi (SLEEP/WAITFOR delays)
  
- **Cross-Site Scripting:**
  - Reflection detection (payload appears in response)
  - Execution analysis (script tags intact)
  - Context-aware testing (HTML, JavaScript, attribute contexts)
  
- **Security Headers:**
  - Content-Security-Policy
  - X-Frame-Options
  - Strict-Transport-Security
  - X-Content-Type-Options
  - And more...

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
```bash
# 1. Clone the repository
git clone https://github.com/YOUR-USERNAME/python-web-security-scanner.git
cd python-web-security-scanner

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## Quick Start

### Basic Usage

Scan a target website:
```bash
python scanner.py -u http://localhost:5000
```

### Common Options
```bash
# Specify crawl depth
python scanner.py -u http://example.com -d 3

# Custom report name
python scanner.py -u http://example.com -o my_scan

# Only test for SQL injection
python scanner.py -u http://example.com --sqli-only

# Skip XSS testing
python scanner.py -u http://example.com --no-xss
```

---

## Command-Line Options
```
usage: scanner.py [-h] -u URL [-d DEPTH] [-o OUTPUT]
                  [--sqli-only] [--xss-only] [--headers-only]
                  [--no-sqli] [--no-xss] [--no-headers]
                  [--json-only] [--no-report]

Required Arguments:
  -u, --url URL         Target URL to scan

Optional Arguments:
  -d, --depth DEPTH     Maximum crawl depth (default: 2)
  -o, --output OUTPUT   Output report filename (without extension)

Scan Modules:
  --sqli-only          Only run SQL injection tests
  --xss-only           Only run XSS tests
  --headers-only       Only check security headers
  --no-sqli            Skip SQL injection tests
  --no-xss             Skip XSS tests
  --no-headers         Skip security headers check

Report Options:
  --json-only          Generate only JSON report (no HTML)
  --no-report          Do not generate any report files
```

---

## Output & Reports

### Console Output
Real-time colored output showing:
- Crawling progress
- Vulnerability discoveries
- Security header analysis
- Scan statistics

### HTML Report
Professional, interactive HTML report featuring:
- Executive summary
- Severity-based vulnerability categorization
- Detailed findings with proof-of-concept
- Security recommendations
- Modern, responsive design

### JSON Report
Machine-readable JSON format containing:
- Complete scan metadata
- All discovered vulnerabilities
- Security headers analysis
- Easy integration with CI/CD pipelines

---

## How It Works

### 1. Web Crawling Phase
```
Target URL → Discover Links → Find Forms → Extract Parameters
```
- Follows links within the same domain
- Respects configurable depth limit
- Extracts all forms and input fields
- Builds comprehensive site map

### 2. SQL Injection Testing
```
For Each Form:
  For Each Input Field:
    Inject Payloads → Analyze Response → Detect Vulnerability
```

**Detection Methods:**
- **Error-based:** Looks for database error messages
- **Boolean-based:** Tests true/false conditional logic
- **Time-based:** Uses database delay functions

### 3. XSS Testing
```
For Each Input:
  Inject XSS Payloads → Check Reflection → Verify Execution
```

**Detection Logic:**
- Checks if payload is reflected in response
- Verifies payload is not properly escaped
- Detects both reflected and stored XSS

### 4. Security Headers Check
```
Fetch Response → Extract Headers → Compare Against Best Practices
```

Checks for presence and proper configuration of security headers.

---

## 🔬 Technical Details

### Project Structure
```
python-web-security-scanner/
├── scanner.py              # Main CLI interface
├── modules/
│   ├── crawler.py         # Web crawling engine
│   ├── sqli_detector.py   # SQL injection detection
│   ├── xss_detector.py    # XSS detection
│   ├── headers_checker.py # Security headers analysis
│   └── reporter.py        # Report generation
├── payloads/
│   ├── sqli.txt           # SQL injection payloads
│   └── xss.txt            # XSS payloads
├── templates/
│   └── report_template.html # HTML report template
├── reports/               # Generated reports (gitignored)
├── examples/              # Usage examples
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

### Dependencies

- **requests** - HTTP requests
- **beautifulsoup4** - HTML parsing
- **colorama** - Colored terminal output
- **jinja2** - HTML report templating

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is for **educational and authorized security testing only**.

**You must:**
- Only scan systems you own or have explicit permission to test
- Obtain written authorization before testing third-party systems
- Comply with all applicable laws and regulations
- Use responsibly and ethically

**Unauthorized scanning is illegal** and may result in:
- Criminal prosecution
- Civil lawsuits
- Network bans
- Legal penalties

The authors assume **NO LIABILITY** for misuse of this tool.

---

## 🎯 Use Cases

### Application Security Testing
- Identify vulnerabilities in your own web applications
- Perform security assessments during development
- Validate security fixes

### Learning & Education
- Understand common web vulnerabilities
- Learn vulnerability detection techniques
- Practice secure coding principles

### Security Research
- Automated reconnaissance
- Baseline security assessments
- Integration with larger security workflows

---

## 🚧 Limitations

**What This Scanner Does NOT Do:**
- Advanced authentication bypass
- Business logic vulnerabilities
- Server-side request forgery (SSRF)
- File upload vulnerabilities
- API security testing
- Complex multi-step attacks
- Zero-day vulnerability discovery

**Manual testing is still essential** for comprehensive security assessments.

---

## 📈 Roadmap

Future enhancements planned:
- [ ] Session management and authentication
- [ ] CSRF token detection
- [ ] Subdomain enumeration
- [ ] SSL/TLS analysis
- [ ] API endpoint testing
- [ ] WordPress-specific checks
- [ ] Multi-threading for faster scans
- [ ] Database of known vulnerable patterns

---

## 🤝 Contributing

This is a learning project and not open for contributions. However:
- Feel free to fork for your own learning
- Report bugs via GitHub issues
- Share feedback and suggestions

---

## 📝 License

MIT License - See LICENSE file for details

---


## 🙏 Acknowledgments

- OWASP Top 10 Project
- PortSwigger Web Security Academy
- Python Security Community

---

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Security Headers Reference](https://securityheaders.com/)

---

**⭐ If you found this project helpful for learning AppSec, consider giving it a star!**

---

*Built as part of an Application Security learning journey*