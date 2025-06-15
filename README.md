# Web Application Privacy Scanner



---

## 🛠️ Overview

The **Web Application Privacy Scanner** is an advanced tool designed to analyze websites for privacy and security best practices. It helps detect security headers, cookie flags, trackers, privacy policy keywords, TLS certificate info, WHOIS data, and fingerprinting techniques. Built with asynchronous scanning capabilities, it is optimized for speed and multi-threaded scanning.

---

## 🚀 Features

- **Security Headers Analysis**: Checks for CSP, HSTS, X-Frame-Options, and more.
- **Cookie Security Flags**: Detects Secure, HttpOnly, and SameSite flags.
- **Tracker Detection**: Finds common trackers like Google Analytics, Facebook Pixel.
- **Privacy Keywords**: Searches for GDPR, CCPA, cookie policy mentions.
- **TLS Certificate Info**: Retrieves certificate details.
- **WHOIS Lookup**: Provides domain registration info.
- **Fingerprinting Detection**: Analyzes inline and external JavaScript for fingerprinting techniques.
- **Parallel & Asynchronous Scanning**: Efficiently scans multiple URLs.
- **Proxy Support**: Optional HTTP proxy for requests.
- **Report Generation**: Saves detailed JSON & HTML reports.
- **Email Alerts**: Sends notifications on critical issues (configurable).

---

## ⚙️ Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/AriyanBinBappy/yourrepo.git
    cd yourrepo
    ```

2. Create a Python virtual environment (recommended):

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

---

## 🧑‍💻 Usage

Run the scanner script:

```bash
python scanner.py
