# =============================================================================
# PhishTriage - SOC Phishing Email Analysis Platform
# =============================================================================
# A Streamlit-based phishing triage tool for Security Operations Centers.
# Parses .eml files or raw email headers and performs:
#   - Header analysis (SPF/DKIM/DMARC/originating IP)
#   - URL extraction with defanging
#   - Attachment hashing (MD5 + SHA-256)
#   - Threat intelligence lookup (mock database, VirusTotal-ready)
#   - Visual risk scoring
#   - Incident report generation
# =============================================================================

import streamlit as st
import email
from email import message_from_bytes, message_from_string
from email.policy import default as email_default_policy
import re
import hashlib
import ipaddress
import html
from datetime import datetime
from urllib.parse import urlparse

# ==============================================================================
# PAGE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title="MailScanner | Phishing Analysis Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==============================================================================
# DARK SOC THEME — CSS
# ==============================================================================
CUSTOM_CSS = """
<style>
    /* ---- Core Layout ---- */
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    .block-container { padding-top: 1rem; }

    /* ---- Cards ---- */
    .analysis-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }

    /* ---- Risk Level Banners ---- */
    .risk-low {
        background-color: #0d4a23; color: #56d364;
        border: 1px solid #238636; border-radius: 6px;
        padding: 10px 16px; font-weight: bold;
        text-align: center; font-size: 1.25em;
    }
    .risk-medium {
        background-color: #4a3000; color: #e3b341;
        border: 1px solid #9e6a03; border-radius: 6px;
        padding: 10px 16px; font-weight: bold;
        text-align: center; font-size: 1.25em;
    }
    .risk-high {
        background-color: #4a0000; color: #f85149;
        border: 1px solid #da3633; border-radius: 6px;
        padding: 10px 16px; font-weight: bold;
        text-align: center; font-size: 1.25em;
    }

    /* ---- Auth Badges ---- */
    .badge-pass   { background:#0d4a23; color:#56d364; border-radius:4px; padding:3px 10px; font-size:.85em; font-weight:bold; }
    .badge-fail   { background:#4a0000; color:#f85149; border-radius:4px; padding:3px 10px; font-size:.85em; font-weight:bold; }
    .badge-neutral{ background:#1f1f1f; color:#8b949e; border-radius:4px; padding:3px 10px; font-size:.85em; font-weight:bold; }
    .badge-warning{ background:#4a3000; color:#e3b341; border-radius:4px; padding:3px 10px; font-size:.85em; font-weight:bold; }

    /* ---- URL Items ---- */
    .url-item {
        background:#0d1117; border:1px solid #30363d; border-radius:4px;
        padding:6px 10px; margin:4px 0; font-family:monospace;
        font-size:.82em; color:#58a6ff; word-break:break-all;
    }
    .url-item-malicious {
        background:#300d0d; border:1px solid #da3633; border-radius:4px;
        padding:6px 10px; margin:4px 0; font-family:monospace;
        font-size:.82em; color:#f85149; word-break:break-all;
    }
    .url-item-suspicious {
        background:#2d2200; border:1px solid #9e6a03; border-radius:4px;
        padding:6px 10px; margin:4px 0; font-family:monospace;
        font-size:.82em; color:#e3b341; word-break:break-all;
    }

    /* ---- Intel Result Blocks ---- */
    .intel-malicious  { background:#300d0d; border-left:4px solid #f85149; padding:10px; border-radius:4px; margin:4px 0; }
    .intel-clean      { background:#0d1f12; border-left:4px solid #56d364; padding:10px; border-radius:4px; margin:4px 0; }
    .intel-suspicious { background:#2d2200; border-left:4px solid #e3b341; padding:10px; border-radius:4px; margin:4px 0; }
    .intel-neutral    { background:#1c2128; border-left:4px solid #8b949e; padding:10px; border-radius:4px; margin:4px 0; }

    /* ---- Misc ---- */
    .section-header {
        color:#58a6ff; border-bottom:1px solid #30363d;
        padding-bottom:6px; margin-bottom:14px;
        font-size:1.05em; font-weight:bold;
    }
    .hash-display {
        font-family:'Courier New',monospace; font-size:.76em; color:#8b949e;
        word-break:break-all; background:#0d1117; padding:4px 8px;
        border-radius:4px; border:1px solid #21262d;
    }
    .risk-meter-container {
        background:#1c2128; border:1px solid #30363d;
        border-radius:8px; padding:18px; margin:12px 0;
    }
    .app-header {
        background:linear-gradient(135deg,#0d1117 0%,#1c2128 100%);
        border-bottom:2px solid #1f6feb; padding:18px 24px;
        margin-bottom:20px; border-radius:8px;
    }

    /* ---- Streamlit overrides ---- */
    .stTextArea textarea {
        background-color:#0d1117 !important; color:#c9d1d9 !important;
        border:1px solid #30363d !important;
        font-family:'Courier New',monospace !important; font-size:.82em !important;
    }
    .stButton > button {
        background-color:#1f6feb; color:white;
        border:none; border-radius:6px; font-weight:bold;
    }
    .stButton > button:hover { background-color:#388bfd; color:white; }
    h1,h2,h3 { color:#e6edf3 !important; }
    #MainMenu { visibility:hidden; }
    footer { visibility:hidden; }

    /* ---- Tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        background-color:#161b22; border-bottom:1px solid #30363d;
    }
    .stTabs [data-baseweb="tab"]          { color:#8b949e; }
    .stTabs [aria-selected="true"]        { color:#58a6ff; border-bottom:2px solid #58a6ff; }
</style>
"""

# ==============================================================================
# THREAT INTELLIGENCE MOCK DATABASE
# ==============================================================================
# Replace the `threat_intel_lookup()` function body with real API calls to use
# live data.  See the Threat Intel tab in the app for full VirusTotal guidance.
# ==============================================================================
MOCK_THREAT_DB = {
    "ips": {
        "185.220.101.42":  {"verdict": "malicious",  "score": 95, "category": "Phishing C2",             "reports": 47},
        "194.165.16.78":   {"verdict": "malicious",  "score": 88, "category": "Spam/Phishing",            "reports": 23},
        "45.142.212.100":  {"verdict": "malicious",  "score": 91, "category": "Malware Distribution",     "reports": 61},
        "103.75.190.11":   {"verdict": "suspicious", "score": 55, "category": "Open Proxy",               "reports":  8},
        "91.108.4.0":      {"verdict": "suspicious", "score": 40, "category": "Unusual Traffic Patterns", "reports":  3},
        "198.51.100.1":    {"verdict": "clean",      "score":  5, "category": "Known Safe",               "reports":  0},
        "203.0.113.42":    {"verdict": "clean",      "score":  0, "category": "Documentation IP",         "reports":  0},
    },
    "urls": {
        "http://evil-phish.xyz/login":           {"verdict": "malicious",  "score": 98, "category": "Credential Harvesting"},
        "http://update-required.tk/download":    {"verdict": "malicious",  "score": 92, "category": "Malware Download"},
        "https://secure-login-verify.ml/verify": {"verdict": "malicious",  "score": 89, "category": "Phishing Page"},
        "http://paypa1-secure.ru/update":        {"verdict": "malicious",  "score": 97, "category": "Brand Impersonation"},
        "http://bit.ly/2xFake99":                {"verdict": "suspicious", "score": 60, "category": "URL Shortener"},
        "https://www.google.com":                {"verdict": "clean",      "score":  0, "category": "Trusted Domain"},
        "https://www.microsoft.com":             {"verdict": "clean",      "score":  0, "category": "Trusted Domain"},
    },
}

# Extensions that are commonly weaponised
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".scr", ".pif", ".reg", ".ps1",
    ".psm1", ".psd1", ".hta", ".cpl", ".jar", ".lnk", ".url", ".iso",
    ".img", ".docm", ".xlsm", ".pptm", ".xlsb", ".xls", ".doc",
    ".rar", ".7z", ".ace", ".arj",
}

# ==============================================================================
# SAMPLE PHISHING EMAIL (for the demo button)
# ==============================================================================
SAMPLE_EML = """\
From: PayPal Security <security@paypa1-updates.ru>
To: victim@example.com
Subject: Urgent: Your PayPal Account Has Been Limited
Date: Mon, 14 Apr 2025 09:15:32 +0000
Message-ID: <20250414091532.123456@paypa1-updates.ru>
Return-Path: <bounce@spamhost.xyz>
Reply-To: collect@evil-phish.xyz
X-Originating-IP: 185.220.101.42
Received: from mail.paypa1-updates.ru ([185.220.101.42]) by mx.example.com
Received-SPF: fail (domain paypa1-updates.ru does not designate 185.220.101.42 as permitted sender)
Authentication-Results: mx.example.com;
    dkim=fail (signature verification failed) header.d=paypa1-updates.ru;
    dmarc=fail (p=REJECT) header.from=paypa1-updates.ru;
    spf=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_123456"
X-Mailer: PhishKit v3.2

------=_Part_123456
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Dear Valued Customer,</p>
<p>Your PayPal account has been limited. Please verify your information immediately.</p>
<p><a href="http://evil-phish.xyz/login">Click here to verify your account</a></p>
<p>Also check: <a href="https://secure-login-verify.ml/verify">Account Verification Page</a></p>
<p>Or visit http://paypa1-secure.ru/update to update your details.</p>
<p>Thank you,<br>PayPal Security Team</p>
</body></html>

------=_Part_123456
Content-Type: application/vnd.ms-excel
Content-Disposition: attachment; filename="invoice_urgent.xlsm"
Content-Transfer-Encoding: base64

VGhpcyBpcyBhIG1vY2sgYXR0YWNobWVudCBmb3IgZGVtbyBwdXJwb3Nlcy4=

------=_Part_123456--
"""

# ==============================================================================
# ANALYSIS ENGINE
# ==============================================================================

def parse_email_content(content: bytes | str) -> email.message.Message:
    """Parse raw email bytes or string into an email.message.Message object."""
    if isinstance(content, bytes):
        try:
            return message_from_bytes(content, policy=email_default_policy)
        except Exception:
            return message_from_bytes(content)
    try:
        return message_from_string(content, policy=email_default_policy)
    except Exception:
        return message_from_string(content)


def extract_headers(msg: email.message.Message) -> dict:
    """
    Extract and normalise key security-relevant email headers.
    Returns a structured dict containing SPF/DKIM/DMARC results,
    originating IP, and common metadata fields.
    """
    results = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "reply_to": msg.get("Reply-To", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "spf":   {"result": "none", "details": ""},
        "dkim":  {"result": "none", "details": ""},
        "dmarc": {"result": "none", "details": ""},
        "originating_ip": "",
        "received_chain": [],
    }

    # --- SPF ---
    received_spf = msg.get("Received-SPF", "")
    if received_spf:
        spf_lower = received_spf.lower()
        for token in ("pass", "softfail", "fail", "neutral", "none", "temperror", "permerror"):
            if token in spf_lower:
                results["spf"]["result"] = token
                break
        results["spf"]["details"] = received_spf[:300]

    # --- DKIM / DMARC from Authentication-Results ---
    auth_headers = msg.get_all("Authentication-Results") or []
    arc_auth = msg.get("ARC-Authentication-Results", "")
    auth_text = " ".join(auth_headers + ([arc_auth] if arc_auth else [])).lower()

    if auth_text:
        dkim_m  = re.search(r"dkim=(\S+)",  auth_text)
        dmarc_m = re.search(r"dmarc=(\S+)", auth_text)
        if dkim_m:
            results["dkim"]["result"] = dkim_m.group(1).strip(";,")
        if dmarc_m:
            results["dmarc"]["result"] = dmarc_m.group(1).strip(";,")
        results["dkim"]["details"]  = auth_text[:400]
        results["dmarc"]["details"] = auth_text[:400]

    # --- Originating IP from Received chain ---
    received_headers = msg.get_all("Received") or []
    results["received_chain"] = received_headers

    # Walk chain bottom-up (last Received = first hop from external)
    _ip_re = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    for recv in reversed(received_headers):
        for ip in _ip_re.findall(recv):
            try:
                addr = ipaddress.ip_address(ip)
                if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                    results["originating_ip"] = ip
                    break
            except ValueError:
                pass
        if results["originating_ip"]:
            break

    # Fallback: X-Originating-IP header
    if not results["originating_ip"] and results["x_originating_ip"]:
        results["originating_ip"] = re.sub(r"[\[\]\s]", "", results["x_originating_ip"])

    return results


def extract_urls(msg: email.message.Message) -> list[str]:
    """
    Walk all MIME parts and collect every URL from HTML and plain-text bodies.
    Returns a de-duplicated, sorted list.
    """
    urls: set[str] = set()
    _url_re = re.compile(
        r"https?://[^\s\"'<>\[\]{}|\\^`\x00-\x1f\x7f-\xff]+",
        re.IGNORECASE,
    )

    def _clean(u: str) -> str:
        return re.sub(r"[.,;:!?)]+$", "", html.unescape(u)).strip()

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            body = payload.decode(charset, errors="replace")
        except Exception:
            body = payload.decode("utf-8", errors="replace")

        if ctype == "text/html":
            for attr in ("href", "src", "action"):
                for val in re.findall(rf'{attr}=["\']([^"\']+)["\']', body, re.IGNORECASE):
                    val = _clean(val)
                    if val.startswith(("http://", "https://")):
                        urls.add(val)
        for u in _url_re.findall(body):
            urls.add(_clean(u))

    return sorted(urls)


def defang_url(url: str) -> str:
    """
    Return a defanged (safe-to-share) version of a URL.
    Replaces http(s):// with hxxp(s):// and dots in the host with [.]
    """
    defanged = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            defanged = defanged.replace(parsed.netloc, parsed.netloc.replace(".", "[.]"), 1)
    except Exception:
        pass
    return defanged


def analyze_attachments(msg: email.message.Message) -> list[dict]:
    """
    Enumerate MIME attachments, compute MD5 and SHA-256 hashes,
    and flag suspicious file extensions.
    """
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if not (filename or disposition == "attachment"):
            continue
        if not filename:
            filename = f"unnamed_attachment_{len(attachments) + 1}"

        payload = part.get_payload(decode=True)
        if payload:
            md5    = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            size   = len(payload)
        else:
            md5 = sha256 = "N/A (empty payload)"
            size = 0

        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        attachments.append({
            "filename":     filename,
            "content_type": part.get_content_type(),
            "size":         size,
            "extension":    ext,
            "md5":          md5,
            "sha256":       sha256,
            "is_suspicious": ext in SUSPICIOUS_EXTENSIONS,
        })
    return attachments


def threat_intel_lookup(ip: str | None = None, urls: list[str] | None = None) -> dict:
    """
    Mock Threat Intelligence Lookup.

    HOW TO PLUG IN REAL VIRUSTOTAL DATA
    ------------------------------------
    1.  pip install requests
    2.  Get a free API key at https://www.virustotal.com/gui/join-community
    3.  Store it in .streamlit/secrets.toml:
            VT_API_KEY = "your_key_here"
    4.  Replace the lookup logic below with:

        import requests
        VT_KEY = st.secrets.get("VT_API_KEY", "")
        VT_HDR = {"x-apikey": VT_KEY}

        def _vt_ip(ip):
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=VT_HDR, timeout=10)
            if r.status_code != 200:
                return {"verdict": "unknown", "score": 0, "category": "API error", "reports": 0}
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal   = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "verdict":  "malicious" if mal > 3 else "suspicious" if mal > 0 else "clean",
                "score":    int(mal / total * 100),
                "category": "VirusTotal",
                "reports":  mal,
            }

        def _vt_url(url):
            import base64
            uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers=VT_HDR, timeout=10)
            if r.status_code != 200:
                return {"verdict": "unknown", "score": 0, "category": "API error"}
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal   = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "verdict":  "malicious" if mal > 3 else "suspicious" if mal > 0 else "clean",
                "score":    int(mal / total * 100),
                "category": "VirusTotal",
            }
    """
    result = {"ip": None, "urls": []}

    # ---- IP lookup ----
    if ip:
        db_entry = MOCK_THREAT_DB["ips"].get(ip)
        result["ip"] = {"indicator": ip, **(db_entry or {
            "verdict": "unknown", "score": 0,
            "category": "Not in threat database", "reports": 0,
        })}

    # ---- URL lookup (cap at 20) ----
    for url in (urls or [])[:20]:
        entry = MOCK_THREAT_DB["urls"].get(url)
        if entry:
            result["urls"].append({"indicator": url, **entry})
            continue
        # Domain-level fallback
        try:
            dom = urlparse(url).netloc.lower()
            for known, data in MOCK_THREAT_DB["urls"].items():
                if urlparse(known).netloc.lower() == dom:
                    result["urls"].append({"indicator": url, **data, "note": "domain match"})
                    break
            else:
                result["urls"].append({"indicator": url, "verdict": "unknown", "score": 0,
                                       "category": "Not in threat database"})
        except Exception:
            result["urls"].append({"indicator": url, "verdict": "unknown", "score": 0,
                                   "category": "Not in threat database"})
    return result


def calculate_risk_score(headers: dict, attachments: list,
                         intel: dict, urls: list) -> dict:
    """
    Aggregate all findings into a 0-100 risk score and a risk level
    (LOW / MEDIUM / HIGH) with per-finding detail.
    """
    score    = 0
    findings = []

    def add(sev, msg_, pts):
        nonlocal score
        score += pts
        findings.append({"severity": sev, "finding": msg_})

    # SPF
    spf = headers.get("spf", {}).get("result", "none")
    if spf == "fail":
        add("HIGH",   "SPF check FAILED — sending server not authorised by domain",        35)
    elif spf == "softfail":
        add("MEDIUM", "SPF SOFTFAIL — sending server weakly unauthorised",                 20)
    elif spf in ("none", "neutral"):
        add("LOW",    f"SPF result: {spf.upper()} — no strong policy enforced",            10)

    # DKIM
    dkim = headers.get("dkim", {}).get("result", "none")
    if dkim == "fail":
        add("HIGH",   "DKIM signature FAILED — email may have been tampered with",         25)
    elif dkim in ("none", ""):
        add("LOW",    "DKIM signature absent or unverified",                                8)

    # DMARC
    dmarc = headers.get("dmarc", {}).get("result", "none")
    if dmarc == "fail":
        add("HIGH",   "DMARC policy check FAILED — authentication failure",                30)
    elif dmarc in ("none", ""):
        add("LOW",    "DMARC result not found",                                             5)

    # From / Return-Path domain mismatch
    from_addr   = headers.get("from", "")
    return_path = headers.get("return_path", "")
    _dom = lambda s: (re.search(r"@([\w.-]+)", s) or [None, ""])[1].lower()
    fd, rpd = _dom(from_addr), _dom(return_path)
    if fd and rpd and fd != rpd:
        add("HIGH",   f"From/Return-Path domain mismatch: '{fd}' vs '{rpd}'",              20)

    # Reply-To mismatch
    rtd = _dom(headers.get("reply_to", ""))
    if fd and rtd and fd != rtd:
        add("MEDIUM", f"Reply-To domain '{rtd}' differs from From domain '{fd}'",          15)

    # Originating IP intel
    ip_intel = intel.get("ip")
    if ip_intel:
        verd = ip_intel.get("verdict")
        if verd == "malicious":
            add("CRITICAL", f"Originating IP {ip_intel['indicator']} is MALICIOUS — "
                            f"{ip_intel.get('category','')}", 40)
        elif verd == "suspicious":
            add("MEDIUM",   f"Originating IP {ip_intel['indicator']} is SUSPICIOUS",       20)

    # URL intel
    mal_urls = [u for u in intel.get("urls", []) if u.get("verdict") == "malicious"]
    sus_urls = [u for u in intel.get("urls", []) if u.get("verdict") == "suspicious"]
    if mal_urls:
        add("CRITICAL", f"{len(mal_urls)} MALICIOUS URL(s) detected in email body",        30)
    if sus_urls:
        add("MEDIUM",   f"{len(sus_urls)} suspicious URL(s) found",                        10)

    # Attachments
    for att in attachments:
        if att.get("is_suspicious"):
            add("HIGH", f"Suspicious attachment: {att['filename']} ({att['extension']})",  35)

    # Volume indicator
    if len(urls) > 10:
        add("LOW",    f"Unusually high URL count ({len(urls)}) — possible bulk phishing",  10)

    score = min(100, score)

    if score >= 60:
        level, color, emoji = "HIGH",   "#f85149", "🔴"
    elif score >= 30:
        level, color, emoji = "MEDIUM", "#e3b341", "🟡"
    else:
        level, color, emoji = "LOW",    "#56d364", "🟢"

    return {"score": score, "level": level, "color": color,
            "emoji": emoji, "findings": findings}


def generate_incident_report(filename: str, headers: dict, urls: list,
                              attachments: list, intel: dict, risk: dict) -> str:
    """Produce a plain-text incident report suitable for ServiceNow / Jira."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sep = "=" * 70
    div = "-" * 70
    lines = [
        sep,
        "         PHISHING TRIAGE — INCIDENT REPORT",
        sep,
        f"Generated      : {ts}",
        f"Source File    : {filename}",
        f"Tool           : PhishTriage v1.0",
        "",
        div, "EXECUTIVE SUMMARY", div,
        f"Risk Level     : {risk['level']}  ({risk['score']}/100)",
        f"Total Findings : {len(risk['findings'])}",
        "",
        div, "EMAIL METADATA", div,
        f"From           : {headers.get('from','N/A')}",
        f"To             : {headers.get('to','N/A')}",
        f"Subject        : {headers.get('subject','N/A')}",
        f"Date           : {headers.get('date','N/A')}",
        f"Message-ID     : {headers.get('message_id','N/A')}",
        f"Return-Path    : {headers.get('return_path','N/A')}",
        f"Reply-To       : {headers.get('reply_to','N/A') or 'N/A'}",
        f"Originating IP : {headers.get('originating_ip','N/A') or 'N/A'}",
        f"X-Mailer       : {headers.get('x_mailer','N/A') or 'N/A'}",
        "",
        div, "AUTHENTICATION RESULTS", div,
        f"SPF            : {headers.get('spf',{}).get('result','N/A').upper()}",
        f"DKIM           : {headers.get('dkim',{}).get('result','N/A').upper()}",
        f"DMARC          : {headers.get('dmarc',{}).get('result','N/A').upper()}",
        "",
        div, "EXTRACTED URLs (defanged)", div,
    ]
    if urls:
        lines += [f"  {defang_url(u)}" for u in urls]
    else:
        lines.append("  None found")

    lines += ["", div, "ATTACHMENTS", div]
    if attachments:
        for a in attachments:
            lines += [
                f"  Filename  : {a['filename']}",
                f"  MIME Type : {a['content_type']}",
                f"  Size      : {a['size']:,} bytes",
                f"  MD5       : {a['md5']}",
                f"  SHA-256   : {a['sha256']}",
                f"  Flagged   : {'YES — SUSPICIOUS EXTENSION' if a['is_suspicious'] else 'No'}",
                "",
            ]
    else:
        lines.append("  None")

    lines += ["", div, "THREAT INTELLIGENCE", div]
    ip_i = intel.get("ip")
    if ip_i:
        lines.append(f"  IP {ip_i['indicator']}: {ip_i.get('verdict','?').upper()} "
                     f"(score {ip_i.get('score',0)}/100) — {ip_i.get('category','')}")
    else:
        lines.append("  No originating IP found")

    mal_u = [u for u in intel.get("urls", []) if u.get("verdict") == "malicious"]
    sus_u = [u for u in intel.get("urls", []) if u.get("verdict") == "suspicious"]
    if mal_u:
        lines.append(f"\n  MALICIOUS URLs ({len(mal_u)}):")
        for u in mal_u:
            lines += [f"    {defang_url(u['indicator'])}", f"    Category: {u.get('category','')}"]
    if sus_u:
        lines.append(f"\n  SUSPICIOUS URLs ({len(sus_u)}):")
        for u in sus_u:
            lines.append(f"    {defang_url(u['indicator'])}")

    lines += ["", div, "RISK FINDINGS", div]
    for f in risk["findings"]:
        lines.append(f"  [{f['severity']:8s}] {f['finding']}")

    lines += ["", div, "RECOMMENDED ACTIONS", div]
    if risk["level"] == "HIGH":
        lines += [
            "  [CRITICAL] Block sender domain and originating IP immediately",
            "  [CRITICAL] Quarantine email; notify affected recipients",
            "  [CRITICAL] Escalate to Tier 2 / Incident Response",
            "  [  HIGH  ] Submit IOCs to threat-intel platform",
            "  [  HIGH  ] Check if other users received the same campaign",
            "  [  HIGH  ] Confirm no user clicked links or opened attachments",
        ]
    elif risk["level"] == "MEDIUM":
        lines += [
            "  [ MEDIUM ] Monitor sender reputation over next 24 h",
            "  [ MEDIUM ] Notify end-user of potential phishing attempt",
            "  [  LOW   ] Add sender/IP to watchlist",
        ]
    else:
        lines += [
            "  [  LOW   ] Log findings for tracking",
            "  [  LOW   ] No immediate action required — continue monitoring",
        ]

    lines += ["", sep, "END OF REPORT — PhishTriage v1.0", sep]
    return "\n".join(lines)


# ==============================================================================
# UI HELPERS
# ==============================================================================

def _badge(result: str) -> str:
    r = (result or "none").lower()
    if r == "pass":
        return '<span class="badge-pass">✓ PASS</span>'
    if r in ("fail", "failed"):
        return '<span class="badge-fail">✗ FAIL</span>'
    if r == "softfail":
        return '<span class="badge-warning">⚠ SOFTFAIL</span>'
    return f'<span class="badge-neutral">— {r.upper()}</span>'


def _verdict_icon(verdict: str) -> str:
    return {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢"}.get(verdict, "⚪")


def _score_bar(score: int, color: str) -> str:
    return (
        f'<div style="background:#21262d;border-radius:4px;height:8px;margin-top:6px;">'
        f'<div style="background:{color};width:{score}%;height:8px;border-radius:4px;"></div>'
        f"</div>"
    )


# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

def main() -> None:
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # ── App Header ────────────────────────────────────────────────────────────
    st.markdown(
        '<div class="app-header">'
        '<h1 style="margin:0;color:#e6edf3;">🛡️ PhishTriage</h1>'
        '<p style="margin:4px 0 0 0;color:#8b949e;font-size:.95em;">'
        "Security Operations Center &nbsp;|&nbsp; Phishing Email Analysis Platform"
        "</p></div>",
        unsafe_allow_html=True,
    )

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 📂 Email Input")
        st.markdown("---")
        method = st.radio(
            "Input Method",
            ["Upload .eml File", "Paste Raw Email", "Load Demo Sample"],
        )

        raw_content: bytes | None = None
        filename = "unknown.eml"

        if method == "Upload .eml File":
            f = st.file_uploader("Drop .eml file here", type=["eml", "msg", "txt"])
            if f:
                raw_content = f.read()
                filename    = f.name
                st.success(f"✓ Loaded: {filename}")

        elif method == "Paste Raw Email":
            pasted = st.text_area(
                "Paste raw email (headers + body)",
                height=280,
                placeholder="Paste full email source here …",
            )
            if pasted:
                raw_content = pasted.encode("utf-8")
                filename    = "pasted_email.eml"

        elif method == "Load Demo Sample":
            if st.button("🧪 Load Phishing Demo", use_container_width=True):
                st.session_state["_demo"]     = SAMPLE_EML.encode("utf-8")
                st.session_state["_demo_fn"]  = "demo_phishing.eml"
                st.success("✓ Demo sample loaded!")
            if "_demo" in st.session_state:
                raw_content = st.session_state["_demo"]
                filename    = st.session_state["_demo_fn"]

        st.markdown("---")
        st.markdown("### ⚙️ Display Options")
        show_raw     = st.checkbox("Show raw headers",    value=False)
        show_rcvd    = st.checkbox("Show received chain", value=False)
        st.markdown("---")
        st.markdown(
            '<div style="color:#8b949e;font-size:.78em;line-height:1.7;">'
            '<strong style="color:#58a6ff;">PhishTriage v1.0</strong><br>'
            "SOC Phishing Analysis Tool<br><br>"
            "<em>For authorised security use only.</em>"
            "</div>",
            unsafe_allow_html=True,
        )

    # ── Landing / Empty State ─────────────────────────────────────────────────
    if raw_content is None:
        cols = st.columns(3)
        tiles = [
            ("📧", "Header Analysis",    "Extract SPF, DKIM, DMARC and originating IP"),
            ("🔗", "URL Extraction",     "Identify and defang all URLs for safe sharing"),
            ("📎", "Attachment Hashing", "Compute MD5 / SHA-256 hashes for IOC creation"),
            ("🕵️", "Threat Intel",       "Check IPs and URLs against reputation databases"),
            ("🎯", "Risk Scoring",       "Visual meter with detailed findings breakdown"),
            ("📋", "Incident Report",    "Generate copy-ready reports for ServiceNow / Jira"),
        ]
        for i, (icon, title, desc) in enumerate(tiles):
            with cols[i % 3]:
                st.markdown(
                    f'<div class="analysis-card" style="text-align:center;">'
                    f'<div style="font-size:2em;">{icon}</div>'
                    f'<div style="color:#58a6ff;font-weight:bold;margin:8px 0;">{title}</div>'
                    f'<div style="color:#8b949e;font-size:.85em;">{desc}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
        st.markdown(
            '<div style="text-align:center;margin-top:40px;color:#8b949e;">'
            "👈 Upload a <strong>.eml</strong> file, paste raw email, "
            "or use <strong>Load Demo Sample</strong> to begin."
            "</div>",
            unsafe_allow_html=True,
        )
        return

    # ── Run Analysis ──────────────────────────────────────────────────────────
    with st.spinner("🔍 Analysing email …"):
        try:
            msg         = parse_email_content(raw_content)
            headers     = extract_headers(msg)
            urls        = extract_urls(msg)
            attachments = analyze_attachments(msg)
            intel       = threat_intel_lookup(
                ip=headers.get("originating_ip") or None,
                urls=urls,
            )
            risk = calculate_risk_score(headers, attachments, intel, urls)
        except Exception as exc:
            st.error(f"Failed to parse email: {exc}")
            return

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview & Risk",
        "📧 Headers",
        "🔗 URLs & Links",
        "📎 Attachments",
        "🕵️ Threat Intel",
    ])

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TAB 1 — Overview & Risk
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with tab1:
        left, right = st.columns(2)

        # ── Risk Meter ──────────────────────────────────────────────────────
        with left:
            st.markdown('<div class="section-header">🎯 Risk Assessment</div>', unsafe_allow_html=True)
            score = risk["score"]
            lvl   = risk["level"]
            clr   = risk["color"]
            cls   = f"risk-{lvl.lower()}"
            st.markdown(
                f'<div class="risk-meter-container">'
                f'<div class="{cls}">{risk["emoji"]} {lvl} RISK — {score} / 100</div>'
                f'<div style="background:#21262d;border-radius:4px;height:14px;margin-top:12px;">'
                f'<div style="background:{clr};width:{score}%;height:14px;border-radius:4px;"></div></div>'
                f'<div style="display:flex;justify-content:space-between;color:#8b949e;font-size:.74em;margin-top:4px;">'
                f"<span>0 — Low</span><span>30 — Medium</span><span>60 — High</span><span>100</span>"
                f"</div></div>",
                unsafe_allow_html=True,
            )
            m1, m2, m3 = st.columns(3)
            mal_count = sum(1 for u in intel.get("urls", []) if u.get("verdict") == "malicious")
            m1.metric("URLs Found",   len(urls))
            m2.metric("Attachments",  len(attachments))
            m3.metric("Malicious IOCs", mal_count,
                      delta=f"+{mal_count}" if mal_count else None,
                      delta_color="inverse" if mal_count else "off")

        # ── Findings ────────────────────────────────────────────────────────
        with right:
            st.markdown('<div class="section-header">⚠️ Findings</div>', unsafe_allow_html=True)
            if risk["findings"]:
                sev_map = {
                    "CRITICAL": ("🔴", "intel-malicious"),
                    "HIGH":     ("🟠", "intel-malicious"),
                    "MEDIUM":   ("🟡", "intel-suspicious"),
                    "LOW":      ("🔵", "intel-neutral"),
                }
                for f in risk["findings"]:
                    icon, css = sev_map.get(f["severity"], ("⚪", "intel-neutral"))
                    st.markdown(
                        f'<div class="{css}" style="margin:4px 0;">'
                        f'<span style="font-size:.85em;">{icon} <strong>[{f["severity"]}]</strong> {f["finding"]}</span>'
                        f"</div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    '<div class="intel-clean"><span style="font-size:.85em;">🟢 No significant risk findings</span></div>',
                    unsafe_allow_html=True,
                )

        # ── Auth Summary ────────────────────────────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-header">🔐 Authentication Summary</div>', unsafe_allow_html=True)
        ac1, ac2, ac3 = st.columns(3)
        for col, key, label, note_key in (
            (ac1, "spf",   "SPF — Sender Policy Framework",    "details"),
            (ac2, "dkim",  "DKIM — DomainKeys Identified Mail", "details"),
            (ac3, "dmarc", "DMARC — Domain-based Auth",         "details"),
        ):
            res  = headers.get(key, {}).get("result", "none")
            det  = headers.get(key, {}).get(note_key, "No data")[:120]
            with col:
                st.markdown(
                    f'<div class="analysis-card" style="text-align:center;">'
                    f'<div style="font-size:.82em;color:#8b949e;margin-bottom:6px;">{label}</div>'
                    f"{_badge(res)}"
                    f'<div style="font-size:.73em;color:#8b949e;margin-top:6px;">{det}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )

        # ── Incident Report Generator ────────────────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-header">📋 Incident Report</div>', unsafe_allow_html=True)
        if st.button("📄 Generate Incident Report", type="primary"):
            report = generate_incident_report(
                filename, headers, urls, attachments, intel, risk)
            st.text_area(
                "Copy this report into ServiceNow / Jira / your ticketing system:",
                value=report, height=420,
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TAB 2 — Email Headers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with tab2:
        st.markdown('<div class="section-header">📧 Email Header Analysis</div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)

        _dom = lambda s: (re.search(r"@([\w.-]+)", s) or [None, ""])[1].lower()
        fd  = _dom(headers.get("from", ""))
        rpd = _dom(headers.get("return_path", ""))
        rtd = _dom(headers.get("reply_to", ""))

        with c1:
            for label, key in [("From", "from"), ("Subject", "subject"),
                                ("Date", "date"), ("Message-ID", "message_id")]:
                st.markdown(f"**{label}:**")
                st.code(headers.get(key, "N/A") or "N/A", language=None)

        with c2:
            st.markdown("**Return-Path:**")
            rp = headers.get("return_path", "N/A")
            if fd and rpd and fd != rpd:
                st.markdown(
                    f'<span style="color:#f85149;">⚠️ {rp}  (domain mismatch with From!)</span>',
                    unsafe_allow_html=True)
            else:
                st.code(rp or "N/A", language=None)

            st.markdown("**Reply-To:**")
            rt = headers.get("reply_to", "")
            if rt:
                if fd and rtd and fd != rtd:
                    st.markdown(
                        f'<span style="color:#e3b341;">⚠️ {rt}  (differs from From domain)</span>',
                        unsafe_allow_html=True)
                else:
                    st.code(rt, language=None)
            else:
                st.code("Not set", language=None)

            st.markdown("**Originating IP:**")
            ip = headers.get("originating_ip", "")
            if ip:
                ip_i = intel.get("ip", {})
                verd = ip_i.get("verdict", "unknown") if ip_i else "unknown"
                if verd == "malicious":
                    st.markdown(
                        f'<span style="color:#f85149;">🔴 {ip} — MALICIOUS ({ip_i.get("category","")})</span>',
                        unsafe_allow_html=True)
                elif verd == "suspicious":
                    st.markdown(
                        f'<span style="color:#e3b341;">🟡 {ip} — SUSPICIOUS</span>',
                        unsafe_allow_html=True)
                else:
                    st.code(ip, language=None)
            else:
                st.code("Not found in headers", language=None)

            st.markdown("**X-Mailer:**")
            st.code(headers.get("x_mailer", "N/A") or "N/A", language=None)

        st.markdown("---")
        spf_det  = headers.get("spf",  {}).get("details", "")
        auth_det = headers.get("dkim", {}).get("details", "")
        if spf_det:
            st.markdown("**Received-SPF (raw):**")
            st.code(spf_det, language=None)
        if auth_det:
            st.markdown("**Authentication-Results (raw):**")
            st.code(auth_det[:500], language=None)

        if show_rcvd and headers.get("received_chain"):
            st.markdown("---")
            st.markdown("**Received Header Chain** *(bottom = originating hop)*")
            for i, recv in enumerate(reversed(headers["received_chain"])):
                st.markdown(
                    f'<div style="color:#8b949e;font-size:.76em;background:#0d1117;'
                    f'border:1px solid #30363d;border-radius:4px;padding:8px;margin:3px 0;'
                    f'font-family:monospace;">[{i+1}] {recv[:350]}</div>',
                    unsafe_allow_html=True,
                )

        if show_raw:
            st.markdown("---")
            st.markdown("**All Raw Headers:**")
            raw_txt = "\n".join(f"{k}: {v}" for k, v in msg.items())
            st.text_area("", value=raw_txt, height=300)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TAB 3 — URLs & Links
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with tab3:
        st.markdown('<div class="section-header">🔗 URL & Link Extraction</div>', unsafe_allow_html=True)
        if not urls:
            st.info("No URLs found in this email.")
        else:
            st.markdown(
                f"Found **{len(urls)}** URL(s). All displayed URLs are **defanged** "
                f"(`http://` → `hxxp://`, dots in domain → `[.]`):"
            )
            mal_set = {u["indicator"] for u in intel.get("urls", []) if u.get("verdict") == "malicious"}
            sus_set = {u["indicator"] for u in intel.get("urls", []) if u.get("verdict") == "suspicious"}

            for url in urls:
                df = defang_url(url)
                if url in mal_set:
                    st.markdown(
                        f'<div class="url-item-malicious">🔴 [MALICIOUS] {df}</div>',
                        unsafe_allow_html=True)
                elif url in sus_set:
                    st.markdown(
                        f'<div class="url-item-suspicious">🟡 [SUSPICIOUS] {df}</div>',
                        unsafe_allow_html=True)
                else:
                    st.markdown(
                        f'<div class="url-item">🔗 {df}</div>',
                        unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("**Defanged URL list (copyable):**")
            st.text_area("", value="\n".join(defang_url(u) for u in urls), height=140)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TAB 4 — Attachments
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with tab4:
        st.markdown('<div class="section-header">📎 Attachment Analysis</div>', unsafe_allow_html=True)
        if not attachments:
            st.info("No attachments found in this email.")
        else:
            for att in attachments:
                label = f"{'🔴 ' if att['is_suspicious'] else '📄 '}{att['filename']}  ({att['size']:,} bytes)"
                with st.expander(label, expanded=att["is_suspicious"]):
                    ca, cb = st.columns(2)
                    with ca:
                        st.markdown(f"**Filename:** `{att['filename']}`")
                        st.markdown(f"**MIME Type:** `{att['content_type']}`")
                        st.markdown(f"**Extension:** `{att['extension'] or 'none'}`")
                        st.markdown(f"**Size:** `{att['size']:,} bytes`")
                        if att["is_suspicious"]:
                            st.markdown(
                                f'<div class="intel-malicious">'
                                f"⚠️ <strong>SUSPICIOUS EXTENSION</strong><br>"
                                f'<span style="font-size:.82em;">{att["extension"]} is '
                                f"commonly used in malware delivery</span></div>",
                                unsafe_allow_html=True,
                            )
                    with cb:
                        st.markdown("**MD5:**")
                        st.markdown(f'<div class="hash-display">{att["md5"]}</div>', unsafe_allow_html=True)
                        st.markdown("**SHA-256:**")
                        st.markdown(f'<div class="hash-display">{att["sha256"]}</div>', unsafe_allow_html=True)
                        st.markdown(
                            '<div style="color:#8b949e;font-size:.78em;margin-top:10px;">'
                            "🔍 Submit hashes to VirusTotal or MalwareBazaar for lookup"
                            "</div>",
                            unsafe_allow_html=True,
                        )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # TAB 5 — Threat Intel
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with tab5:
        st.markdown('<div class="section-header">🕵️ Threat Intelligence Results</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="intel-suspicious" style="margin-bottom:14px;">'
            '<span style="font-size:.85em;">⚠️ <strong>Demo Mode:</strong> '
            "Using simulated threat database.  "
            "See the VirusTotal integration guide below to use live data.</span></div>",
            unsafe_allow_html=True,
        )

        # IP
        st.markdown("#### 🌐 IP Reputation")
        orig_ip = headers.get("originating_ip", "")
        ip_i    = intel.get("ip")
        if not orig_ip:
            st.markdown(
                '<div class="intel-neutral"><span style="font-size:.85em;">ℹ️ No originating IP extracted</span></div>',
                unsafe_allow_html=True)
        elif ip_i:
            verd  = ip_i.get("verdict", "unknown")
            score = ip_i.get("score", 0)
            css   = "intel-malicious" if verd=="malicious" else ("intel-suspicious" if verd=="suspicious" else "intel-clean")
            bar_c = "#f85149" if verd=="malicious" else ("#e3b341" if verd=="suspicious" else "#56d364")
            st.markdown(
                f'<div class="{css}">'
                f'<div style="font-weight:bold;">{_verdict_icon(verd)} {ip_i["indicator"]}</div>'
                f'<div style="font-size:.83em;margin-top:4px;">'
                f'Verdict: <strong>{verd.upper()}</strong> &nbsp;|&nbsp; '
                f'Score: {score}/100 &nbsp;|&nbsp; Category: {ip_i.get("category","?")} &nbsp;|&nbsp; '
                f'Reports: {ip_i.get("reports",0)}'
                f"</div>"
                f"{_score_bar(score, bar_c)}</div>",
                unsafe_allow_html=True,
            )

        st.markdown("---")
        # URLs
        st.markdown("#### 🔗 URL Reputation")
        url_intel_list = intel.get("urls", [])
        if not url_intel_list:
            st.info("No URLs to check.")
        else:
            for ud in url_intel_list:
                verd  = ud.get("verdict", "unknown")
                score = ud.get("score", 0)
                css   = "intel-malicious" if verd=="malicious" else ("intel-suspicious" if verd=="suspicious" else "intel-clean")
                bar_c = "#f85149" if verd=="malicious" else ("#e3b341" if verd=="suspicious" else "#56d364")
                st.markdown(
                    f'<div class="{css}" style="margin:4px 0;">'
                    f'<div style="font-family:monospace;font-size:.82em;word-break:break-all;">'
                    f'{_verdict_icon(verd)} {defang_url(ud["indicator"])}</div>'
                    f'<div style="font-size:.76em;color:#8b949e;margin-top:2px;">'
                    f'Verdict: <strong>{verd.upper()}</strong> | Score: {score}/100 | {ud.get("category","")}'
                    f"</div>"
                    f"{_score_bar(score, bar_c)}</div>",
                    unsafe_allow_html=True,
                )

        st.markdown("---")
        with st.expander("🔑 VirusTotal API Integration Guide"):
            st.markdown(
                """
**Step 1 — Install requests:**
```bash
pip install requests
```

**Step 2 — Store your API key in `.streamlit/secrets.toml`:**
```toml
VT_API_KEY = "your_key_here"
```
Get a free key at https://www.virustotal.com/gui/join-community

**Step 3 — Replace the body of `threat_intel_lookup()` in `app.py`:**
```python
import requests, base64

VT_KEY = st.secrets.get("VT_API_KEY", "")
VT_HDR = {"x-apikey": VT_KEY}

def _vt_ip(ip: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=VT_HDR, timeout=10)
    if r.status_code != 200:
        return {"verdict": "unknown", "score": 0, "category": "API error", "reports": 0}
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    mal   = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {"verdict": "malicious" if mal > 3 else "suspicious" if mal else "clean",
            "score": int(mal/total*100), "category": "VirusTotal", "reports": mal}

def _vt_url(url: str) -> dict:
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    r   = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{uid}",
        headers=VT_HDR, timeout=10)
    if r.status_code != 200:
        return {"verdict": "unknown", "score": 0, "category": "API error"}
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    mal   = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {"verdict": "malicious" if mal > 3 else "suspicious" if mal else "clean",
            "score": int(mal/total*100), "category": "VirusTotal"}

# Then in threat_intel_lookup():
#   result["ip"] = {"indicator": ip, **_vt_ip(ip)}
#   for url in urls:
#       result["urls"].append({"indicator": url, **_vt_url(url)})
```
"""
            )


if __name__ == "__main__":
    main()
