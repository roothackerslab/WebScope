# 🕵️‍♂️ WebScope v2.3

<div align="center">

```
 ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗  
 ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**See Beyond The Surface** 🌐

*An Advanced Web Reconnaissance & Security Analysis Tool*

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Termux-lightgrey)](https://github.com/RootHackersLab/WebScope)
[![Version](https://img.shields.io/badge/Version-2.3-orange)](https://github.com/RootHackersLab/WebScope/releases)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Modules](#-modules)
- [Screenshots](#-screenshots)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 🎯 Overview

**WebScope Pro** is a comprehensive web reconnaissance and security analysis tool designed for ethical hackers, penetration testers, and security researchers. It performs deep scanning of web targets to uncover potential vulnerabilities, misconfigurations, and security weaknesses.

### What Makes WebScope Different?

✨ **All-in-One Solution** - Combines 9+ scanning modules in a single tool  
🚀 **Blazing Fast** - Multi-threaded architecture with intelligent rate limiting  
🎨 **Beautiful Reports** - Professional HTML & JSON reports with hacker aesthetics  
🔧 **Highly Configurable** - Extensive CLI options for customized scanning  
🛡️ **Smart Detection** - Advanced technology fingerprinting & security analysis  
📱 **Cross-Platform** - Works on Linux, Windows, macOS, and Termux  

---

## 🔥 Features

### Core Scanning Modules

| Module | Description |
|--------|-------------|
| 🌐 **WHOIS Lookup** | Domain registration details, registrar info, nameservers |
| 🔍 **DNS Analysis** | A, AAAA, MX, NS, TXT records with comprehensive DNS profiling |
| 🌍 **IP Information** | Geolocation, ISP, ASN, reverse DNS lookup |
| 🕸️ **Subdomain Enumeration** | Discover 100+ common subdomains with parallel scanning |
| 💻 **Technology Detection** | Identify web servers, frameworks, CMS, JavaScript libraries |
| 🛡️ **Security Headers** | Analyze 8 critical security headers with scoring |
| 📡 **HTTP Analysis** | Response codes, redirects, cookies, content types |
| 📂 **Exposed Files** | Scan 40+ sensitive files (.git, .env, wp-config, etc.) |
| 🔓 **Port Scanning** | Check 19 common ports (HTTP, SSH, MySQL, Redis, etc.) |

### Advanced Features

- ⚡ **Multi-threaded Scanning** - Up to 50 concurrent threads
- 🎭 **User-Agent Rotation** - Evade basic detection mechanisms
- 🔄 **Auto-Retry Logic** - Handles timeouts & failed requests gracefully
- 📊 **Security Scoring** - Automatic grading system (A+ to F)
- 🎨 **Matrix-Style UI** - Hacker-themed terminal animations
- 📝 **Detailed Logging** - Complete scan logs saved to `webscope.log`
- 🔒 **SSL Verification** - Option to skip SSL certificate validation
- 🎯 **Domain Allowlisting** - Restrict scanning to authorized targets
- 🏃 **Dry-Run Mode** - Preview scans without execution

---

## 📦 Installation

### Quick Install (Linux/Kali/Termux)

```bash
# Clone the repository
git clone https://github.com/RootHackersLab/WebScope.git
cd WebScope

# Run setup script
chmod +x setup.sh
./setup.sh

# Start scanning!
python3 WebScope.py example.com
```

### Manual Installation

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x WebScope.py

# Run
python3 WebScope.py --help
```

### Termux (Android) Installation

```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/RootHackersLab/WebScope.git
cd WebScope
pip install -r requirements.txt
python WebScope.py example.com
```

### Windows Installation

```powershell
# Clone repository
git clone https://github.com/RootHackersLab/WebScope.git
cd WebScope

# Install dependencies
pip install -r requirements.txt

# Run
python WebScope.py example.com
```

---

## 🚀 Usage

### Basic Scan

```bash
python3 WebScope.py example.com
```

### Advanced Options

```bash
# Generate only HTML report
python3 WebScope.py example.com -o html

# Generate only JSON report
python3 WebScope.py example.com -o json

# Generate both reports
python3 WebScope.py example.com -o both

# Skip SSL verification (for testing environments)
python3 WebScope.py https://target.com --skip-ssl

# Disable colored output (for logging)
python3 WebScope.py example.com --no-color | tee scan.log

# Preview scan without execution
python3 WebScope.py example.com --dry-run

# Scan subdomain with allowlist
python3 WebScope.py sub.example.com --allowlist example.com

# Verbose mode
python3 WebScope.py example.com -v
```

### Interactive Mode

Simply run without arguments for interactive menu:

```bash
python3 WebScope.py
```

---

## 📊 Output Formats

### HTML Report
Beautiful, interactive HTML reports with:
- Dark hacker-themed design
- Color-coded security grades
- Clickable sections with smooth scrolling
- Comprehensive vulnerability summaries
- Professional presentation

### JSON Report
Machine-readable JSON output containing:
- Complete scan results
- Structured data for automation
- Easy integration with other tools
- Perfect for CI/CD pipelines

### Sample Output Structure

```
WebScope_Reports/
├── WebScope_example_com_20260509_151027.html
└── WebScope_example_com_20260509_151027.json
```

---

## 🧩 Modules

### 1. WHOIS Lookup
```
Domain Registration Info
├── Registrar
├── Creation Date
├── Expiration Date
├── Nameservers
└── Registrant Details
```

### 2. DNS Records
```
DNS Configuration
├── A Records (IPv4)
├── AAAA Records (IPv6)
├── MX Records (Mail Servers)
├── NS Records (Nameservers)
└── TXT Records (SPF, DMARC, etc.)
```

### 3. Technology Stack
```
Detected Technologies
├── Web Server (Apache, Nginx, IIS)
├── Programming Language (PHP, Python, Node.js)
├── Framework (Laravel, Django, Express)
├── CMS (WordPress, Drupal, Joomla)
└── JavaScript Libraries (jQuery, React, Vue)
```

### 4. Security Headers Analysis
```
HTTP Security Headers
├── Strict-Transport-Security (HSTS)
├── Content-Security-Policy (CSP)
├── X-Frame-Options
├── X-Content-Type-Options
├── X-XSS-Protection
├── Referrer-Policy
├── Permissions-Policy
└── Cross-Origin-Embedder-Policy
```

### 5. Port Scanning
```
Open Ports Detection
├── 21  - FTP
├── 22  - SSH
├── 80  - HTTP
├── 443 - HTTPS
├── 3306 - MySQL
├── 5432 - PostgreSQL
├── 6379 - Redis
└── [+14 more common ports]
```

---

## 📸 Screenshots

### Terminal Output
```
┌─────────────────────────────────────────────────────────────────┐
│  01アイウエオカキクケコサシスセソタチツテト                          │
│  ──────────────────────────────────────────────────────────     │
│  [ WEBSCOPE PRO v2.3 — INITIALIZING ]                          │
│  ──────────────────────────────────────────────────────────     │
│  TARGET   : https://example.com                                │
│  DOMAIN   : example.com                                         │
│  IP       : 93.184.216.34                                      │
│  ══════════════════════════════════════════════════════════     │
└─────────────────────────────────────────────────────────────────┘
```

### HTML Report Preview
- Professional dark theme with green accents
- Organized sections with icons
- Security scoring with visual indicators
- Responsive design for all devices

---

## ⚖️ Legal Disclaimer

### ⚠️ **IMPORTANT - READ BEFORE USE**

This tool is intended **ONLY** for:
- ✅ Educational purposes
- ✅ Authorized security testing
- ✅ Bug bounty programs
- ✅ Penetration testing with written permission

### Unauthorized Usage is Illegal

- ❌ **DO NOT** scan websites without explicit permission
- ❌ **DO NOT** use for malicious purposes
- ❌ **DO NOT** attack systems you don't own
- ❌ **DO NOT** violate local/international laws

### Legal Consequences

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Cybercrime laws in your jurisdiction

**Always obtain written authorization before scanning any target.**

**The author and RootHackersLab are not responsible for misuse of this tool.**

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💻 Commit changes (`git commit -m 'Add AmazingFeature'`)
4. 📤 Push to branch (`git push origin feature/AmazingFeature`)
5. 🔃 Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comments for complex logic
- Test on multiple platforms
- Update documentation

---

## 🐛 Bug Reports

Found a bug? Please open an issue with:
- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version)

---

## 📝 Changelog

### v2.3 (Latest)
- ✅ Fixed all critical bugs from v2.2
- ✅ Improved subdomain enumeration
- ✅ Enhanced security header detection
- ✅ Better error handling
- ✅ Optimized performance

### v2.2
- Added private IP detection
- Improved rate limiting
- Enhanced JSON export

### v2.1
- Initial public release
- Core scanning modules
- HTML/JSON reporting

---

## 📞 Support

Need help? Reach out:

- 📧 **Email**: roothackerslab.git@gmail.com


---

## 👨‍💻 Author

<div align="center">

**Mughal__Hacker (ahsan_mughal)**

Founder & Lead Developer @ **RootHackersLab**

*Cybersecurity Enthusiast | Ethical Hacker | Tool Developer*


</div>

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024-2026 RootHackersLab | Mughal__Hacker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🌟 Star History

If you find this tool useful, please consider giving it a ⭐!

---

## 🔗 Related Projects

- [Nmap](https://nmap.org/) - Network scanning
- [Nikto](https://cirt.net/Nikto2) - Web server scanner
- [WPScan](https://wpscan.com/) - WordPress security scanner
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomain enumeration

---

<div align="center">

### 💀 Made with 💚 by RootHackersLab 💀

**See Beyond The Surface**

```
┌─────────────────────────────────────────┐
│  Keep Learning | Stay Curious | Hack Ethically  │
└─────────────────────────────────────────┘
```

⚡ **Star this repo if you found it useful!** ⭐

</div>
