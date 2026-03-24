# Security-headers-Scanner-2026
Advanced Python-based security header scanner for web and API pentesting. Supports authenticated requests, detects missing/deprecated headers, and highlights misconfigurations like weak CSP or insecure caching.

Includes scoring, redirect analysis, and exportable JSON/HTML reports for real-world assessments.

Powered by OWASP best practices. 🚀

---

## 🚀 Features

- ✅ Web & API analysis modes
- 🔑 Custom headers support (Authorization, API keys, cookies)
- ⚠️ Detection of missing & deprecated headers
- 🔍 Misconfiguration analysis (CSP, HSTS, caching, etc.)
- 🔄 Redirect chain analysis
- 📊 Security scoring system
- 📁 JSON & HTML report export
- 🎨 Colourful CLI output

---

```bash
## 📦 Requirements

- Python 3  
- requests  

```bash
pip install requests

---
## ⚡ Usage
Basic web scan

python3 security_header_analysis_2026.py -u example.com -t web

Single API target with bearer token
python3 security_header_analysis_2026.py -u https://api.example.com/v1/me -t api -H "Authorization: Bearer eyJ..." -H "Accept: application/json"

Ignore TLS validation
python3 security_header_analysis_2026.py -u https://192.168.1.10 -t web -k

Force GET
python3 security_header_analysis_2026.py -u https://example.com -t web --method GET

Multiple targets from file
python3 security_header_analysis_2026.py -f targets.txt -t web

Export JSON and HTML
python3 security_header_analysis_2026.py -f targets.txt -t web --json-out results.json --html-out report.html
