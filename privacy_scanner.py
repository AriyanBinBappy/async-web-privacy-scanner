import asyncio
import aiohttp
import os
import ssl
import json
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import whois  # for WHOIS lookup

# Configuration
HTTP_PROXY = None  # e.g. "http://127.0.0.1:8080"
EMAIL_ALERTS_ENABLED = False
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USERNAME = "user@example.com"
SMTP_PASSWORD = "password"
EMAIL_FROM = "scanner@example.com"
EMAIL_TO = "alertrecipient@example.com"

REPORT_DIR = "web_report"

def print_banner():
    banner = r"""
  ___       _          ____             _       ____      _               
 / _ \  ___| |_ ___   |  _ \  __ _ _ __| | __  / ___|   _| |__   ___ _ __ 
| | | |/ __| __/ _ \  | | | |/ _` | '__| |/ / | |  | | | | '_ \ / _ \ '__|
| |_| | (__| || (_) | | |_| | (_| | |  |   <  | |__| |_| | |_) |  __/ |   
 \___/ \___|\__\___/  |____/ \__,_|_|  |_|\_\  \____\__, |_.__/ \___|_|   
                                                    |___/                 
 ____                            _ 
/ ___|  __ _ _   _  __ _ _ __ __| |
\___ \ / _` | | | |/ _` | '__/ _` |
 ___) | (_| | |_| | (_| | | | (_| |
|____/ \__, |\__,_|\__,_|_|  \__,_|
          |_|                      

    🛠️  Web Application Privacy Scanner
    👤 Made by: Ariyan Bin Bappy
    ☠️  Group: Octo Dark Cyber Squad
    ⚠️  For authorized testing only — use for finding your vulnerable Website

    Key Features:
    - Security Headers Analysis (CSP, HSTS, X-Frame-Options, etc.)
    - Cookie Security Flags Detection (Secure, HttpOnly, SameSite)
    - Tracker Detection (Google Analytics, Facebook Pixel, etc.)
    - Privacy Keywords Detection (GDPR, CCPA, Cookie Policy)
    - TLS Certificate Info Extraction
    - WHOIS Domain Information Lookup
    - Fingerprinting Detection in Inline and External JS (with detailed explanations)
    - Parallel & Multi-threaded Async Scanning for Speed
    - Auto Scan Multiple URLs from File
    - Proxy Support for Requests
    - Detailed JSON & HTML Report Generation in 'web_report' folder
    - Email Alert Notifications on Critical Findings (configurable)
"""
    print(banner)

def send_email_alert(subject, body):
    if not EMAIL_ALERTS_ENABLED:
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        print("[*] Email alert sent.")
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")

def save_report(url, report, html_content):
    os.makedirs(REPORT_DIR, exist_ok=True)
    safe_name = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
    json_path = os.path.join(REPORT_DIR, f"{safe_name}_report.json")
    html_path = os.path.join(REPORT_DIR, f"{safe_name}_report.html")
    with open(json_path, "w") as jf:
        json.dump(report, jf, indent=4)
    with open(html_path, "w") as hf:
        hf.write(html_content)
    print(f"[+] Reports saved to {REPORT_DIR} for {url}")

async def fetch(session, url, proxy=None):
    try:
        async with session.get(url, proxy=proxy, timeout=15) as response:
            content = await response.text()
            headers = response.headers
            return content, headers
    except Exception as e:
        print(f"[!] Fetch error for {url}: {e}")
        return None, {}

def analyze_security_headers(headers):
    results = {}
    results["Content-Security-Policy"] = headers.get("Content-Security-Policy", None)
    results["Strict-Transport-Security"] = headers.get("Strict-Transport-Security", None)
    results["X-Frame-Options"] = headers.get("X-Frame-Options", None)
    results["X-Content-Type-Options"] = headers.get("X-Content-Type-Options", None)
    results["Referrer-Policy"] = headers.get("Referrer-Policy", None)
    results["Permissions-Policy"] = headers.get("Permissions-Policy", None)
    return results

def analyze_cookie_security(headers):
    cookies = headers.get("Set-Cookie", "")
    cookie_report = []
    if cookies:
        cookie_parts = cookies.split(",")  # rough split for multiple cookies
        for c in cookie_parts:
            c = c.strip()
            secure = "Secure" in c
            http_only = "HttpOnly" in c
            same_site = None
            if "SameSite=Strict" in c:
                same_site = "Strict"
            elif "SameSite=Lax" in c:
                same_site = "Lax"
            elif "SameSite=None" in c:
                same_site = "None"
            cookie_report.append({
                "cookie": c,
                "secure": secure,
                "http_only": http_only,
                "same_site": same_site
            })
    return cookie_report

def detect_trackers(headers, content):
    trackers_found = []
    trackers = [
        "google-analytics.com",
        "googletagmanager.com",
        "facebook.net",
        "doubleclick.net",
        "ads.yahoo.com",
        "adservice.google.com",
        "pixel.facebook.com"
    ]
    for tracker in trackers:
        if tracker in content or tracker in str(headers):
            trackers_found.append(tracker)
    return trackers_found

def detect_privacy_keywords(content):
    keywords = [
        "gdpr",
        "cookie policy",
        "privacy policy",
        "data protection",
        "consent",
        "ccpa",
        "california privacy",
        "user data"
    ]
    found = []
    lower = content.lower()
    for kw in keywords:
        if kw in lower:
            found.append(kw)
    return found

def get_domain_from_url(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path  # fallback if netloc empty
    except Exception:
        return url

def get_tls_certificate_info(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": f"TLS cert fetch failed: {e}"}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        result = {}
        for key, value in w.items():
            if isinstance(value, (list, tuple)):
                result[key] = [str(v) for v in value]
            elif hasattr(value, 'isoformat'):
                result[key] = value.isoformat()
            else:
                result[key] = str(value)
        return result
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

async def analyze_fingerprinting_all(session, url, content, proxy=None):
    # Fingerprinting detection with inline scripts and external JS fetch & analyze

    report = {"inline_scripts": [], "external_scripts": []}

    # Inline scripts fingerprint detection heuristics (simple patterns)
    soup = BeautifulSoup(content, "html.parser")
    inline_scripts = soup.find_all("script", src=False)
    for script in inline_scripts:
        js = script.string or ""
        if not js.strip():
            continue
        detected = detect_fingerprinting_methods(js)
        if detected:
            report["inline_scripts"].append({
                "script": js[:300] + ("..." if len(js) > 300 else ""),
                "methods_detected": detected,
                "explanations": explain_fingerprinting(detected)
            })

    # External scripts fingerprint detection (fetch and analyze)
    external_scripts = soup.find_all("script", src=True)
    tasks = []
    for script in external_scripts:
        src = script.get("src")
        if not src.startswith("http"):
            # Make relative URLs absolute
            parsed = urlparse(url)
            src = f"{parsed.scheme}://{parsed.netloc}{src}" if src.startswith("/") else f"{parsed.scheme}://{parsed.netloc}/{src}"
        tasks.append(fetch_external_js_and_analyze(session, src, proxy))
    external_results = await asyncio.gather(*tasks)
    for ext in external_results:
        if ext:
            report["external_scripts"].append(ext)

    return report

def detect_fingerprinting_methods(js_code):
    # Very basic heuristic checks
    methods = []
    checks = {
        "Canvas Fingerprinting": ["getContext('2d')", "toDataURL"],
        "WebGL Fingerprinting": ["WebGLRenderingContext", "getParameter"],
        "Audio Fingerprinting": ["AudioContext", "createAnalyser"],
        "Font Fingerprinting": ["document.fonts", "FontFace"],
        "Battery Status API": ["navigator.getBattery"],
        "Touch Events": ["ontouchstart", "TouchEvent"],
        "Device Memory API": ["navigator.deviceMemory"],
        "Media Devices": ["navigator.mediaDevices.getUserMedia"],
    }
    for name, patterns in checks.items():
        for pat in patterns:
            if pat in js_code:
                methods.append(name)
                break
    return methods

def explain_fingerprinting(methods):
    explanations = {
        "Canvas Fingerprinting": "Uses HTML5 Canvas to draw and extract image data to uniquely identify your device.",
        "WebGL Fingerprinting": "Uses WebGL APIs to gather graphic hardware information.",
        "Audio Fingerprinting": "Uses AudioContext to analyze audio processing which can be unique per device.",
        "Font Fingerprinting": "Detects installed fonts by measuring text dimensions.",
        "Battery Status API": "Reads battery status, which can help in fingerprinting.",
        "Touch Events": "Detects if device supports touch input which narrows device types.",
        "Device Memory API": "Reads RAM size info for fingerprinting.",
        "Media Devices": "Accesses media devices info like cameras and microphones."
    }
    return {method: explanations.get(method, "No explanation available.") for method in methods}

async def fetch_external_js_and_analyze(session, url, proxy=None):
    try:
        content, _ = await fetch(session, url, proxy=proxy)
        if content:
            detected = detect_fingerprinting_methods(content)
            if detected:
                return {
                    "url": url,
                    "methods_detected": detected,
                    "explanations": explain_fingerprinting(detected),
                    "snippet": content[:300] + ("..." if len(content) > 300 else "")
                }
    except Exception as e:
        print(f"[!] External JS fetch error for {url}: {e}")
    return None

def generate_html_report(url, report):
    import html
    def safe_json(obj):
        return html.escape(json.dumps(obj, indent=4))
    html_report = f"""
<html><head><title>Privacy Scan Report for {url}</title></head><body>
<h1>Privacy Scan Report for {url}</h1>
<h2>Security Headers</h2>
<pre>{safe_json(report.get("security_headers", {}))}</pre>
<h2>Cookie Security</h2>
<pre>{safe_json(report.get("cookie_security", []))}</pre>
<h2>Trackers Detected</h2>
<pre>{safe_json(report.get("trackers", []))}</pre>
<h2>Privacy Keywords Found</h2>
<pre>{safe_json(report.get("privacy_keywords", []))}</pre>
<h2>TLS Certificate Info</h2>
<pre>{safe_json(report.get("tls_cert", {}))}</pre>
<h2>WHOIS Information</h2>
<pre>{safe_json(report.get("whois", {}))}</pre>
<h2>Fingerprinting Detection - Inline Scripts</h2>
<pre>{safe_json(report.get("fingerprinting", {}).get("inline_scripts", []))}</pre>
<h2>Fingerprinting Detection - External Scripts</h2>
<pre>{safe_json(report.get("fingerprinting", {}).get("external_scripts", []))}</pre>
</body></html>
"""
    return html_report

async def scan_url(url, selected_scans, proxy=None):
    print(f"[*] Scanning: {url}")
    timeout = aiohttp.ClientTimeout(total=20)
    conn = aiohttp.TCPConnector(ssl=False)
    proxy_to_use = proxy

    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
        content, headers = await fetch(session, url, proxy=proxy_to_use)
        if content is None:
            print(f"[!] Failed to fetch {url}")
            return

        report = {}

        if "security_headers" in selected_scans:
            report["security_headers"] = analyze_security_headers(headers)

        if "cookie_security" in selected_scans:
            report["cookie_security"] = analyze_cookie_security(headers)

        if "trackers" in selected_scans:
            report["trackers"] = detect_trackers(headers, content)

        if "privacy_keywords" in selected_scans:
            report["privacy_keywords"] = detect_privacy_keywords(content)

        if "tls_cert" in selected_scans:
            domain = get_domain_from_url(url)
            cert = get_tls_certificate_info(domain)
            report["tls_cert"] = cert

        if "whois" in selected_scans:
            domain = get_domain_from_url(url)
            w_info = get_whois_info(domain)
            report["whois"] = w_info

        if "fingerprinting" in selected_scans:
            fingerprint_report = await analyze_fingerprinting_all(session, url, content, proxy=proxy_to_use)
            report["fingerprinting"] = fingerprint_report

        # Save reports
        html_report = generate_html_report(url, report)
        save_report(url, report, html_report)

        # Send alert on critical issues (example: no HSTS or critical trackers found)
        critical_issues = []
        sec_headers = report.get("security_headers", {})
        if not sec_headers.get("Strict-Transport-Security"):
            critical_issues.append("Missing HSTS header")

        trackers = report.get("trackers", [])
        if trackers:
            critical_issues.append(f"Trackers detected: {', '.join(trackers)}")

        if critical_issues:
            subject = f"[ALERT] Critical Privacy Issues Found on {url}"
            body = f"Critical issues found:\n" + "\n".join(critical_issues)
            send_email_alert(subject, body)

async def main():
    print_banner()
    print("Enter URLs to scan (comma separated), or filename with URLs (one per line):")
    user_input = input().strip()
    urls = []

    # Check if input is filename
    if os.path.isfile(user_input):
        with open(user_input, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [u.strip() for u in user_input.split(",") if u.strip()]

    print("\nSelect scans to perform (comma separated):")
    print("1 - Security Headers")
    print("2 - Cookie Security")
    print("3 - Tracker Detection")
    print("4 - Privacy Keywords")
    print("5 - TLS Certificate Info")
    print("6 - WHOIS Lookup")
    print("7 - Fingerprinting Detection")
    print("all - Run All Scans")
    selection = input("Your choice(s): ").strip().lower()

    map_options = {
        "1": "security_headers",
        "2": "cookie_security",
        "3": "trackers",
        "4": "privacy_keywords",
        "5": "tls_cert",
        "6": "whois",
        "7": "fingerprinting",
    }

    if selection == "all":
        selected_scans = list(map_options.values())
    else:
        selected_scans = []
        for sel in selection.split(","):
            sel = sel.strip()
            if sel in map_options:
                selected_scans.append(map_options[sel])
        if not selected_scans:
            print("[!] No valid scan options selected. Exiting.")
            return

    sem = asyncio.Semaphore(5)

    async def sem_scan(url):
        async with sem:
            await scan_url(url, selected_scans, proxy=HTTP_PROXY)

    await asyncio.gather(*[sem_scan(u) for u in urls])

if __name__ == "__main__":
    asyncio.run(main())
