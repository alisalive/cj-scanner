# 🛡️ CJ-SCANNER v1.0

**A Professional, Multi-Layered Clickjacking (UI Redressing) Vulnerability Scanner**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**CJ-SCANNER** is a high-performance terminal tool designed for security researchers and penetration testers. It automates the detection of Clickjacking vulnerabilities by performing deep, dual-layer analysis of HTTP response headers across multiple targets — all from a single command.

---

## ✨ Key Features

- **🔍 Dual-Layer Detection** — Unlike basic scanners, CJ-SCANNER analyzes both `X-Frame-Options` and `Content-Security-Policy` (`frame-ancestors`) headers to minimize false positives and catch edge cases that single-header tools miss.
- **🎨 Terminal Aesthetics** — Bold red ASCII art banner with dynamic centering, color-coded `VULNERABLE` / `SECURE` verdicts, and dot-leader aligned output columns for maximum readability.
- **📄 Auto Reporting** — Automatically generates a clean `vulnerable_report.txt` file containing only confirmed vulnerable targets. The file is removed automatically if no vulnerabilities are found.
- **🛡️ Resilient Engine** — Built-in SSL fallback (HTTPS → HTTP), SSL warning suppression, browser-mimicking User-Agent, and graceful handling of timeouts and connection errors — no crashes.
- **💻 Cross-Platform** — Optimized for Kali Linux. Fully compatible with Windows CMD/PowerShell and macOS Terminal via `colorama`.

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/alisalive/cj-scanner.git
cd cj-scanner
```

### 2. Install Dependencies

```bash
pip install requests colorama pyfiglet
```

> Requires **Python 3.8+**

---

## 🚀 Usage

### Step 1 — Prepare your targets file

Create a plain `.txt` file with one domain per line. Blank lines and comments (`#`) are ignored.

```
# domains.txt
google.com
https://example.com
subdomain.target.org
# this line is ignored
```

### Step 2 — Run the scanner

```bash
python cj_scanner.py
```

When prompted, enter the full path to your domains file:

```
[?] Enter the full path to your domains .txt file: /home/user/domains.txt
```

### Step 3 — Review the output

Results stream in real-time to the terminal. Confirmed vulnerable domains are saved automatically to `vulnerable_report.txt` in the working directory.

---

## 🔍 Detection Logic

CJ-SCANNER evaluates each domain against two independent security headers:

| Header | Secure Values | Insecure / Absent |
|---|---|---|
| `X-Frame-Options` | `DENY`, `SAMEORIGIN` | Missing, `ALLOW-FROM` (deprecated) |
| `CSP: frame-ancestors` | `'none'`, `'self'` | Missing, `*`, or permissive origin list |

**Verdict rules:**

- 🔴 **VULNERABLE** — Both `X-Frame-Options` and `CSP: frame-ancestors` are absent or misconfigured.
- 🟢 **SECURE** — At least one of the two protections is correctly configured.

> `frame-ancestors` takes precedence over `X-Frame-Options` in all modern browsers. CJ-SCANNER checks both independently and reports each finding.

---

## 📂 Output Files

| File | Description |
|---|---|
| `vulnerable_report.txt` | Auto-generated list of vulnerable URLs. Created only if vulnerabilities are found; deleted automatically if none are detected. |

---

## 🧱 Project Structure

```
cj-scanner/
├── cj_scanner.py        # Main scanner script
├── domains.txt          # Example target list (add your own)
├── vulnerable_report.txt  # Auto-generated after scan (if applicable)
└── README.md
```

---

## 👤 Author

**Shikhali Jamalzade**

- 🐙 GitHub: [@alisalive](https://github.com/alisalive)
- 📸 Instagram: [@alisalive.exe](https://instagram.com/alisalive.exe)
- 🎯 Specialization: Cybersecurity Student & Penetration Tester

---

## ⚖️ Disclaimer

> This tool is developed **strictly for authorized security auditing and educational purposes only.**
> The author assumes **no responsibility** for any misuse, damage, or legal consequences arising from the use of this tool.
> **Always obtain explicit written permission before testing any target system or domain.**
> Unauthorized use may violate local, national, or international laws.
