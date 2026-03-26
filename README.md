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
Install Dependencies:

Bash
pip install requests colorama pyfiglet
🚀 How to Use
Prepare a .txt file (e.g., domains.txt) with one domain per line.

Run the scanner:

Bash
python clickjack_checker.py
Enter the path to your file when prompted and watch the results stream in real-time.

🔍 Technical Strategy
The tool evaluates security posture based on the following logic:

VULNERABLE: If both X-Frame-Options and CSP: frame-ancestors are missing or misconfigured (e.g., allow-from or wildcards).

SECURE: If a valid DENY, SAMEORIGIN, or strict frame-ancestors directive is detected.

👤 Author
Shikhali Jamalzade

GitHub: @alisalive

Instagram: @alisalive.exe

Specialization: Cybersecurity Student & Penetration Tester

⚖️ Disclaimer
This tool is developed for authorized security auditing and educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Always obtain explicit permission before testing any target.

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/alisalive/cj-scanner.git](https://github.com/alisalive/cj-scanner.git)
   cd cj-scanner
