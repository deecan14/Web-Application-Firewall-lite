# 🛡️ WAF Lite – Python Web Application Firewall

A lightweight **Web Application Firewall (WAF)** built with Python and Flask.  
It filters incoming HTTP requests for common web attack patterns (SQL Injection, XSS, Path Traversal) and either **blocks** or **forwards** them to a backend service.  
All traffic is logged for review.  

---

## ✨ Features
- Detects and blocks common attacks:
  - 🚫 SQL Injection (`OR 1=1`, `UNION SELECT`, `DROP TABLE`)
  - 🚫 Cross-Site Scripting (XSS) (`<script>`, `javascript:`)
  - 🚫 Path Traversal (`../`, `..\\`)
- Logs **all requests** (blocked & allowed) to `waf_log.txt`
- Returns clear JSON response with block reason
- Forwards safe requests to a backend (default: [httpbin.org](https://httpbin.org/))
- Built with **Flask + Regex filtering**

---

## 🚀 Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/waf-lite.git
   cd waf-lite

2. Install dependencies:
   pip install flask requests

3. Run the WAF server:
   python waf_lite.py
