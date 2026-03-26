# 🛡️ CJ-SCANNER v1.0
**A Professional, Multi-Layered Clickjacking (UI Redressing) Vulnerability Scanner**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)

**CJ-SCANNER** is a high-performance terminal tool designed for security researchers and penetration testers. It automates the detection of Clickjacking vulnerabilities by performing deep analysis of HTTP response headers across multiple targets simultaneously.

---

## ✨ Key Features

- **🚀 Dual-Layer Detection:** Unlike basic scanners, CJ-SCANNER analyzes both `X-Frame-Options` and `Content-Security-Policy` (frame-ancestors) to minimize false positives.
- **🎨 Terminal Aesthetics:** Features a bold, red-themed ASCII banner with dynamic centering and color-coded results for maximum readability.
- **📊 Real-time Reporting:** Automatically generates a clean `vulnerable_report.txt` containing only confirmed vulnerable targets.
- **🛠️ Resilient Engine:** Built-in SSL warning suppression, custom User-Agent mimicking, and graceful error handling for connection timeouts.
- **💻 Cross-Platform:** Optimized for Kali Linux, but fully compatible with Windows (CMD/PowerShell) and macOS.

---

## 📸 Preview
*(Bura terminaldakı o qırmızı bannerli və nəticəli skrinşotunu əlavə et - şəkli repo-ya yükləyib linkini bura qoy)*
![CJ-SCANNER Demo](your-screenshot-link-here.png)

---

## ⚙️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/alisalive/cj-scanner.git](https://github.com/alisalive/cj-scanner.git)
   cd cj-scanner
