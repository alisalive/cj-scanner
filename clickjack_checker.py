"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         CJ-SCANNER  v1.0                                    ║
║                  Clickjacking Vulnerability Checker                         ║
║              For Authorized Security Research & Pen-Testing Only            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  DEPENDENCIES  (install with pip)                                           ║
║    pip install requests colorama pyfiglet                                   ║
║                                                                             ║
║  USAGE                                                                      ║
║    python cj_scanner.py                                                     ║
║    → Enter the full path to a .txt file (one domain per line)               ║
║                                                                             ║
║  OUTPUT FILES                                                               ║
║    vulnerable_report.txt  — auto-created if any vulnerabilities are found   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ── Standard library ──────────────────────────────────────────────────────────
import sys
import os
import time

# ── Third-party ───────────────────────────────────────────────────────────────
import requests
import urllib3
import pyfiglet
from colorama import init, Fore, Style

# ── Initialise colorama ───────────────────────────────────────────────────────
# autoreset=True automatically resets colour after every print() call,
# eliminating the need to manually append Style.RESET_ALL everywhere.
# This also handles the Windows VT100 escape-code activation automatically,
# which is why the previous version showed plain text on CMD/PowerShell.
init(autoreset=True)

# Suppress SSL warnings (self-signed / expired certs are common in pen-testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

VERSION          = "v1.0"
AUTHOR           = "Shikhali Jamalzade"
REPORT_FILE      = "vulnerable_report.txt"
REQUEST_TIMEOUT  = 10           # seconds before a request gives up
STREAM_DELAY     = 0.1          # seconds between domain checks (streaming feel)
COLUMN_WIDTH     = 60           # width of the decorative separator lines

# Mimic a real browser to avoid simple bot-detection blocks
BROWSER_HEADERS  = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER & VISUAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """
    Render the ASCII-art banner using pyfiglet, then print tool metadata.
    Uses 'slant' font; falls back to 'standard' if slant is unavailable.

    Colour scheme:
      - ASCII art    : Fore.RED   + Style.BRIGHT   (high-impact title)
      - Authorship   : Fore.WHITE + Style.BRIGHT    (stands out from body text)
      - Subtitles    : Fore.WHITE + Style.NORMAL    (clean, readable)
      - Separators   : Fore.WHITE                   (unobtrusive framing)

    The authorship line is dynamically centred to the width of the widest
    line in the generated ASCII art so alignment survives any pyfiglet font
    or terminal-font combination.
    """
    try:
        ascii_art = pyfiglet.figlet_format("CJ-SCANNER", font="slant")
    except pyfiglet.FontNotFound:
        ascii_art = pyfiglet.figlet_format("CJ-SCANNER", font="standard")

    # ASCII art: RED + BRIGHT
    print(Fore.RED + Style.BRIGHT + ascii_art)

    # Dynamic width: use every line (including blank) for max accuracy
    banner_width = max(len(line) for line in ascii_art.splitlines())
    sep_width    = max(banner_width, COLUMN_WIDTH)

    # Authorship / social-media line: WHITE + BRIGHT, centred
    info_line    = (
        f"★  By: {AUTHOR}  |  {VERSION}"
        f"  |  GitHub: alisalive  |  IG: alisalive.exe  ★"
    )
    centred_info = info_line.center(sep_width)
    print(Fore.WHITE + Style.BRIGHT + centred_info)

    # Subtitle block: WHITE + NORMAL, separators in plain WHITE
    print(Fore.WHITE + "─" * sep_width)
    print(Fore.WHITE + Style.NORMAL + "  Clickjacking Vulnerability Scanner")
    print(Fore.WHITE + Style.NORMAL + "  For Authorized Security Research & Penetration Testing Only")
    print(Fore.WHITE + "─" * sep_width)
    print()


def separator(char: str = "─", colour: str = Fore.WHITE) -> None:
    """Print a full-width decorative separator line."""
    print(colour + char * COLUMN_WIDTH)


# ─────────────────────────────────────────────────────────────────────────────
#  REPORT FILE
# ─────────────────────────────────────────────────────────────────────────────

def initialize_report_file() -> None:
    """
    Wipe (or create) the vulnerable_report.txt at scan start so old results
    do not bleed into a new run.
    """
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"CJ-SCANNER {VERSION}  |  By: {AUTHOR}\n")
        f.write("Vulnerable Domains Report\n")
        f.write("=" * COLUMN_WIDTH + "\n\n")


def update_report(url: str) -> None:
    """
    Append a vulnerable URL to the report file.
    Called immediately after a domain is confirmed vulnerable so the file
    is always up-to-date even if the scan is interrupted mid-way.
    """
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(url + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  URL NORMALISATION
# ─────────────────────────────────────────────────────────────────────────────

def normalise_url(domain: str) -> str:
    """
    Prepend 'https://' to bare domains so requests can handle them.
    Already-prefixed http:// or https:// URLs are returned unchanged.
    """
    domain = domain.strip()
    if not domain.startswith(("http://", "https://")):
        return "https://" + domain
    return domain


# ─────────────────────────────────────────────────────────────────────────────
#  HEADER ANALYSIS  (private helpers used by check_clickjacking)
# ─────────────────────────────────────────────────────────────────────────────

def _check_x_frame_options(headers: dict) -> tuple[bool, str]:
    """
    Evaluate the X-Frame-Options (XFO) response header.

    Secure  : DENY, SAMEORIGIN
    Insecure: absent or ALLOW-FROM (obsolete, trivially bypassed)

    Returns (is_secure, human_readable_detail)
    """
    xfo = headers.get("X-Frame-Options", "").strip().upper()

    if not xfo:
        return False, "X-Frame-Options ......... MISSING"
    if xfo in ("DENY", "SAMEORIGIN"):
        return True,  f"X-Frame-Options ......... {xfo}"
    # ALLOW-FROM is deprecated in modern browsers
    return False, f"X-Frame-Options ......... {xfo} (weak/deprecated)"


def _check_csp_frame_ancestors(headers: dict) -> tuple[bool, str]:
    """
    Evaluate the Content-Security-Policy 'frame-ancestors' directive.

    frame-ancestors supersedes XFO in all modern browsers and is the
    recommended approach. A value of 'none' or 'self' is considered secure;
    a wildcard (*) or arbitrary origin list is permissive/insecure.

    Returns (is_secure, human_readable_detail)
    """
    csp = headers.get("Content-Security-Policy", "")

    if not csp:
        return False, "CSP frame-ancestors ...... MISSING"

    for directive in (d.strip() for d in csp.split(";")):
        if directive.lower().startswith("frame-ancestors"):
            parts  = directive.split()
            values = [v.lower() for v in parts[1:]]
            value_str = " ".join(parts[1:])

            if "'none'" in values or "'self'" in values:
                return True,  f"CSP frame-ancestors ...... {value_str}"
            return False, f"CSP frame-ancestors ...... {value_str} (permissive)"

    return False, "CSP frame-ancestors ...... NOT SET in CSP"


# ─────────────────────────────────────────────────────────────────────────────
#  CORE CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_clickjacking(url: str) -> dict:
    """
    Fetch *url* and determine whether it is protected against clickjacking.

    Strategy
    ────────
    1. Attempt HTTPS request (verify=False to handle self-signed certs).
    2. On SSLError fall back to plain HTTP.
    3. Inspect X-Frame-Options and CSP frame-ancestors independently.
    4. Mark as VULNERABLE only when BOTH protections are absent/weak.

    Returns a result dict:
        url, final_url, status_code, vulnerable (bool|None),
        xfo_secure, xfo_detail, csp_secure, csp_detail, error (str|None)
    """
    final_url = normalise_url(url)
    result = {
        "url":          url,
        "final_url":    final_url,
        "status_code":  None,
        "vulnerable":   None,
        "xfo_secure":   False,
        "xfo_detail":   "",
        "csp_secure":   False,
        "csp_detail":   "",
        "error":        None,
    }

    def _analyse(response) -> None:
        """Populate result in-place from an HTTP response object."""
        result["status_code"] = response.status_code
        h = response.headers
        result["xfo_secure"], result["xfo_detail"] = _check_x_frame_options(h)
        result["csp_secure"], result["csp_detail"] = _check_csp_frame_ancestors(h)
        result["vulnerable"] = not (result["xfo_secure"] or result["csp_secure"])

    try:
        resp = requests.get(
            final_url,
            headers=BROWSER_HEADERS,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        _analyse(resp)

    except requests.exceptions.SSLError:
        # HTTPS failed — retry over plain HTTP
        http_url = final_url.replace("https://", "http://")
        result["final_url"] = http_url
        try:
            resp = requests.get(
                http_url,
                headers=BROWSER_HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            _analyse(resp)
        except Exception as e:
            result["error"] = f"SSL fallback failed: {e}"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = f"Timed out after {REQUEST_TIMEOUT}s"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request error: {e}"

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  PER-DOMAIN OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

def print_result(result: dict, index: int, total: int) -> None:
    """
    Display a neatly aligned result block for a single domain.

    Layout
    ──────
    [index/total]  domain.com                          →  VULNERABLE / SECURE
                   Status Code ................. 200
                   X-Frame-Options ............. MISSING
                   CSP frame-ancestors ......... MISSING
    """
    domain   = result["url"]
    progress = Fore.CYAN + f"  [{index:0{len(str(total))}}/ {total}]" + Style.RESET_ALL

    separator()

    if result["error"]:
        print(f"{progress}  {Style.BRIGHT}{domain}")
        print(f"  {Fore.YELLOW}  ⚠  ERROR:{Style.RESET_ALL}  {result['error']}")
        return

    # ── Verdict label ────────────────────────────────────────────────────────
    if result["vulnerable"]:
        verdict = Fore.RED   + Style.BRIGHT + "[ VULNERABLE ]" + Style.RESET_ALL
        icon    = Fore.RED   + "✗" + Style.RESET_ALL
    else:
        verdict = Fore.GREEN + Style.BRIGHT + "[   SECURE   ]" + Style.RESET_ALL
        icon    = Fore.GREEN + "✓" + Style.RESET_ALL

    # ── Domain header row ────────────────────────────────────────────────────
    domain_col = (Style.BRIGHT + domain + Style.RESET_ALL).ljust(45)
    print(f"{progress}  {domain_col}  {verdict}")

    # ── Detail rows ──────────────────────────────────────────────────────────
    status_line = f"  Status Code ................. {result['status_code']}"
    print(f"           {Fore.WHITE}{status_line}{Style.RESET_ALL}")
    print(f"           {icon}  {result['xfo_detail']}")
    print(f"           {icon}  {result['csp_detail']}")


# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: list) -> None:
    """
    Print a final statistics block and, if applicable, the path to the
    vulnerable domains report file.
    """
    total      = len(results)
    errors     = sum(1 for r in results if r["error"])
    checked    = total - errors
    vulnerable = sum(1 for r in results if r["vulnerable"])
    secure     = checked - vulnerable

    print()
    separator("═", Fore.CYAN)
    print(Fore.CYAN + Style.BRIGHT + "  SCAN SUMMARY")
    separator("═", Fore.CYAN)

    # Stats table — aligned with dot leaders for quick reading
    print(f"  {'Total Domains':<28} {Style.BRIGHT}{total}{Style.RESET_ALL}")
    print(f"  {'Successfully Checked':<28} {Style.BRIGHT}{checked}{Style.RESET_ALL}")
    print(f"  {Fore.RED + Style.BRIGHT}{'Vulnerable':<28}{Style.RESET_ALL} "
          f"{Fore.RED + Style.BRIGHT}{vulnerable}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN + Style.BRIGHT}{'Secure':<28}{Style.RESET_ALL} "
          f"{Fore.GREEN + Style.BRIGHT}{secure}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}{'Errors':<28}{Style.RESET_ALL} "
          f"{Fore.YELLOW}{errors}{Style.RESET_ALL}")

    separator("═", Fore.CYAN)

    # ── Vulnerable domain list ────────────────────────────────────────────────
    if vulnerable:
        print(f"\n  {Fore.RED + Style.BRIGHT}Vulnerable Targets:{Style.RESET_ALL}")
        for r in results:
            if r["vulnerable"]:
                print(f"    {Fore.RED}►{Style.RESET_ALL}  {r['url']}")

        # Report file notification
        print(
            f"\n  {Fore.YELLOW + Style.BRIGHT}[✔] Report saved to:"
            f" {REPORT_FILE}{Style.RESET_ALL}"
        )
    else:
        print(
            f"\n  {Fore.GREEN + Style.BRIGHT}"
            f"[✔] All checked domains appear protected.{Style.RESET_ALL}"
        )

    separator("═", Fore.CYAN)
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  FILE LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_domains(filepath: str) -> list[str]:
    """
    Read domains from a plain-text file.
    • One domain per line.
    • Blank lines and lines starting with '#' are silently skipped.
    • Strips surrounding quotes (drag-and-drop behaviour on Windows).
    """
    filepath = filepath.strip().strip('"').strip("'")

    if not os.path.isfile(filepath):
        print(Fore.RED + Style.BRIGHT + f"\n  [✘] File not found: {filepath}\n")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    domains = [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]

    if not domains:
        print(Fore.YELLOW + f"\n  [!] No domains found in {filepath}\n")
        sys.exit(0)

    return domains


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. Banner ─────────────────────────────────────────────────────────────
    print_banner()

    # 2. User input ─────────────────────────────────────────────────────────
    filepath = input(
        Fore.YELLOW + "  [?] Enter the full path to your domains .txt file: "
        + Style.RESET_ALL
    ).strip()

    domains = load_domains(filepath)
    total   = len(domains)

    print(
        f"\n  {Fore.CYAN + Style.BRIGHT}[»] Loaded {total} domain(s).  "
        f"Starting scan…{Style.RESET_ALL}"
    )

    # 3. Prepare the report file (reset on each new run) ────────────────────
    initialize_report_file()
    report_has_entries = False

    # 4. Scan loop ──────────────────────────────────────────────────────────
    results = []
    for i, domain in enumerate(domains, start=1):

        # Streaming progress hint (overwritten by the full result block)
        print(
            f"  {Fore.CYAN}[{i}/{total}]{Style.RESET_ALL} "
            f"Scanning: {domain}…",
            end="\r",
            flush=True,
        )

        result = check_clickjacking(domain)
        results.append(result)

        # Print the detailed result block for this domain
        print_result(result, i, total)

        # Append to report immediately so it's always current
        if result["vulnerable"]:
            update_report(result["final_url"])
            report_has_entries = True

        # Small delay for the "streaming" visual effect
        time.sleep(STREAM_DELAY)

    # 5. Summary ────────────────────────────────────────────────────────────
    print_summary(results)

    # 6. Clean up empty report file if nothing was found ────────────────────
    if not report_has_entries and os.path.isfile(REPORT_FILE):
        os.remove(REPORT_FILE)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW + Style.BRIGHT}[!] Scan interrupted by user.{Style.RESET_ALL}\n")
        sys.exit(0)
