#!/usr/bin/env python3
"""
Phishing Awareness Resource - Basic Phishing Detector
Rule-based screener for email phishing, smishing (SMS) and BEC, aligned with
the Phishing Awareness Resource topics: common signs, email header analysis,
URL checking, TLS certificate checks, social engineering tactics, and
incident response tips (containment, eradication, recovery, MFA audit).

Standard library only.

Usage:
    python phishing_detector.py message.eml              # analyze an email
    python phishing_detector.py message.txt              # analyze plain text
    cat message.eml | python phishing_detector.py -      # read stdin
    python phishing_detector.py --sms "Your parcel is held, pay fee: http://x.top"
    python phishing_detector.py --url "http://paypa1-login.top/verify"
    python phishing_detector.py message.eml --check-tls  # also test HTTPS certs
                                                         # (makes network requests)

Heuristic only: a low score does not prove a message is safe.
"""

import argparse
import email
import re
import socket
import ssl
import sys
import time
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# ----------------------------- Configuration -----------------------------

# (label, phrases, points, social-engineering tactic, message-type flag)
TEXT_RULES = [
    ("Urgency or threat language",
     ["urgent", "immediately", "act now", "within 24 hours", "final notice",
      "account will be closed", "account suspended", "suspended", "verify now",
      "limited time", "last warning", "expires today", "action required"],
     2, "Urgency / fear", None),
    ("Requests for credentials or payment info",
     ["password", "verify your account", "confirm your identity", "login details",
      "one-time code", "otp", "security code", "update your payment",
      "card number", "bank details", "click here to log in", "your pin"],
     2, "Pretexting / credential harvesting", None),
    ("Prize, refund or reward bait",
     ["you have won", "claim your prize", "lottery", "free gift",
      "refund is waiting", "inheritance"],
     2, "Greed / curiosity", None),
    ("Authority impersonation wording",
     ["from the desk of", "it department", "bank security", "security team",
      "head office", "ceo", "managing director", "compliance department"],
     1, "Authority", None),
    ("Secrecy or bypass-procedure wording",
     ["keep this confidential", "do not tell", "don't tell", "between us",
      "do not call", "don't call", "i am in a meeting", "i'm in a meeting"],
     2, "Secrecy / bypassing procedure", None),
    ("BEC-style payment language",
     ["change of bank", "new bank account", "updated banking", "wire transfer",
      "process the payment", "gift card", "invoice attached", "are you available",
      "urgent payment", "bank account has changed"],
     3, "Authority / financial redirection", "BEC"),
    ("Smishing-style wording",
     ["delivery fee", "parcel", "package is held", "mobile money", "momo",
      "account locked", "bank alert", "reply stop", "redelivery", "customs fee"],
     2, "Urgency / impersonation", "SMISHING"),
    ("Generic greeting",
     ["dear customer", "dear user", "dear client", "dear member",
      "dear account holder"],
     1, "Impersonation", None),
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk",
                   "ml", "cf", "ga", "work", "support", "rest", "icu"}
RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".iso",
                    ".img", ".lnk", ".hta", ".zip", ".rar", ".7z", ".docm",
                    ".xlsm", ".pptm")
TWO_PART_TLDS = {"co.uk", "org.uk", "co.za", "com.au", "co.bw", "co.jp", "com.br"}

# brand keyword -> legitimate registrable domains (extend for your environment)
KNOWN_BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com", "fb.com"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "standardbank": {"standardbank.com", "standardbank.co.bw"},
    "fnb": {"fnb.co.za", "fnbbotswana.co.bw"},
    "absa": {"absa.co.za", "absa.com"},
}

MEDIUM_AT = 3
HIGH_AT = 7


# ------------------------------- Helpers ---------------------------------

class Result:
    def __init__(self):
        self.findings = {}      # reason -> points
        self.tactics = set()
        self.flags = set()      # BEC, SMISHING, SPEAR...

    def add(self, pts, reason):
        self.findings[reason] = max(pts, self.findings.get(reason, 0))

    def extend(self, items):
        for pts, reason in items:
            self.add(pts, reason)

    @property
    def score(self):
        return sum(self.findings.values())


class LinkParser(HTMLParser):
    """Collects (href, visible_text) pairs from HTML."""

    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def registrable_domain(host):
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


# ----------------------- Topic: checking URLs ----------------------------

def analyze_url(url):
    """Return list of (points, reason) for a single URL."""
    out = []
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return [(1, f"Malformed URL: {url[:60]}")]
    if not host:
        return out

    if is_ip(host):
        out.append((3, f"URL uses a raw IP address: {host}"))
    if "@" in parsed.netloc:
        out.append((3, f"URL contains '@' (can hide the real host): {url[:60]}"))
    if host.startswith("xn--") or ".xn--" in host:
        out.append((3, f"Punycode domain (possible lookalike characters): {host}"))
    if parsed.scheme == "http":
        out.append((1, f"Link is not encrypted (http): {host}"))
    if host in SHORTENERS:
        out.append((2, f"URL shortener hides the destination: {host}"))
    if host.count(".") >= 4:
        out.append((1, f"Unusually many subdomains: {host}"))
    if len(url) > 120:
        out.append((1, "Very long URL"))

    reg = registrable_domain(host)
    tld = reg.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        out.append((1, f"Frequently abused TLD: .{tld} ({host})"))

    label = reg.split(".")[0]
    for brand, legit in KNOWN_BRANDS.items():
        if reg in legit:
            break
        if brand in host.replace("-", "").replace(".", ""):
            out.append((3, f"Possible '{brand}' impersonation: {host}"))
            break
        if len(label) > 3 and levenshtein(label, brand) == 1:
            out.append((3, f"Lookalike of '{brand}': {host}"))
            break
    return out


# -------------------- Topic: understanding TLS certificates ---------------

def check_tls(host, port=443, timeout=5):
    """Validate the HTTPS certificate of a host. Makes a network connection."""
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        now = time.time()
        issued = ssl.cert_time_to_seconds(cert["notBefore"])
        if (now - issued) / 86400 < 14:
            out.append((1, f"TLS certificate for {host} was issued <14 days ago "
                           "(weak signal; common for throwaway sites)"))
    except ssl.SSLCertVerificationError as e:
        out.append((3, f"TLS certificate INVALID for {host}: {e.verify_message}"))
    except (socket.timeout, OSError):
        out.append((1, f"Could not complete a TLS connection to {host}"))
    return out


# --------------------- Topic: analyzing email headers ---------------------

def analyze_headers(msg, res):
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    from_reg = registrable_domain(from_domain) if from_domain else ""

    # Display-name spoofing
    for brand, legit in KNOWN_BRANDS.items():
        if brand in from_name.lower().replace(" ", "") and from_reg not in legit:
            res.add(4, f"Display name mentions '{brand}' but sender domain is "
                       f"{from_domain}")
            res.tactics.add("Impersonation")
            break

    # Reply-To / Return-Path / Message-ID mismatches
    for header, pts in (("Reply-To", 2), ("Return-Path", 2)):
        _, addr = parseaddr(str(msg.get(header, "")))
        if addr and "@" in addr and from_reg:
            d = registrable_domain(addr.split("@")[-1])
            if d != from_reg:
                res.add(pts, f"{header} domain ({d}) differs from From domain "
                             f"({from_reg})")
    mid = re.search(r"@([\w.-]+)>", str(msg.get("Message-ID", "")))
    if mid and from_reg and registrable_domain(mid.group(1)) != from_reg:
        res.add(1, f"Message-ID domain ({mid.group(1)}) differs from sender domain")

    # SPF / DKIM / DMARC
    auth = (str(msg.get("Authentication-Results", "")) + " " +
            str(msg.get("Received-SPF", ""))).lower()
    for check in ("spf", "dkim", "dmarc"):
        if re.search(rf"{check}\s*=\s*(fail|softfail|none|permerror)", auth):
            res.add(2, f"{check.upper()} check did not pass")
    if re.match(r"\s*(fail|softfail)", str(msg.get("Received-SPF", "")).lower()):
        res.add(2, "SPF check did not pass")

    if from_domain:
        res.extend((p, "Sender domain: " + r)
                   for p, r in analyze_url(from_domain) if p >= 3)


# ------------------------------ Analysis ---------------------------------

def scan_text(text, res):
    t = text.lower()
    for label, phrases, pts, tactic, flag in TEXT_RULES:
        hits = [p for p in phrases if re.search(r"\b" + re.escape(p) + r"\b", t)]
        if hits:
            res.add(pts, f"{label}: {', '.join(hits[:4])}")
            res.tactics.add(tactic)
            if flag:
                res.flags.add(flag)


def scan_links(link_pairs, res, tls):
    seen_urls, tls_hosts = set(), set()
    for href, shown in link_pairs:
        if not href or href.startswith(("mailto:", "#", "tel:")):
            continue
        m = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", shown.lower())
        host = (urlparse(href).hostname or "").lower()
        if m and host and registrable_domain(m.group(1)) != registrable_domain(host):
            res.add(4, f"Link text shows {m.group(1)} but goes to {host}")
            res.tactics.add("Impersonation")
        if href not in seen_urls:
            seen_urls.add(href)
            res.extend(analyze_url(href))
        if tls and href.startswith("https://") and host:
            tls_hosts.add(host)
    for host in list(tls_hosts)[:5]:           # cap network requests
        res.extend(check_tls(host))


def analyze_email(raw, tls=False):
    res = Result()
    msg = email.message_from_string(raw, policy=policy.default)
    has_headers = msg.get("From") is not None

    plain, html, attachments = [], [], []
    if has_headers:
        analyze_headers(msg, res)
        for part in msg.walk():
            if part.is_multipart():
                continue
            if part.get_filename():
                attachments.append(part.get_filename())
                continue
            try:
                body = part.get_content()
            except Exception:
                continue
            if part.get_content_type() == "text/plain":
                plain.append(body)
            elif part.get_content_type() == "text/html":
                html.append(body)
    else:
        plain.append(raw)

    plain, html = "\n".join(plain), "\n".join(html)
    subject = str(msg.get("Subject", "")) if has_headers else ""
    scan_text(f"{subject}\n{plain}\n{re.sub(r'<[^>]+>', ' ', html)}", res)

    pairs = []
    if html:
        p = LinkParser()
        p.feed(html)
        pairs = p.links
    pairs += [(u, u) for u in re.findall(r"https?://[^\s<>\"')]+", plain)]
    scan_links(pairs, res, tls)

    for name in attachments:
        low = name.lower()
        if low.endswith(RISKY_EXTENSIONS):
            res.add(3, f"Risky attachment type: {name}")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|bat|vbs)$", low):
            res.add(4, f"Double-extension attachment: {name}")

    # Spear-phishing hint: personalised greeting + credential/urgency wording
    if re.search(r"^\s*(hi|hello|dear)\s+[A-Z][a-z]+", plain, re.M) and res.score >= 4:
        res.flags.add("SPEAR")
    return res


def analyze_sms(text, tls=False):
    res = Result()
    res.flags.add("SMISHING")
    scan_text(text, res)
    urls = re.findall(r"(?:https?://|www\.)[^\s]+|\b[\w-]+\.(?:top|xyz|click|tk|ml|ga|icu)\S*",
                      text, re.I)
    scan_links([(u, u) for u in urls], res, tls)
    if urls and res.score >= 2:
        res.add(1, "Short message combining a link with pressure/payment wording")
    if re.search(r"\b(call|whatsapp)\b.*\+?\d{7,}", text.lower()):
        res.add(1, "Asks you to call or message an unknown number")
    return res


# ------------------------------- Output ----------------------------------

RESPONSE_TIPS = {
    "Containment": [
        "Do not click links, open attachments, or reply.",
        "If you already clicked or entered details: disconnect the device from "
        "the network and log out of affected accounts.",
        "Report to IT/security or your email provider; forward as an attachment.",
        "For BEC/payment requests: stop the payment and phone your bank at once.",
    ],
    "Eradication": [
        "Change passwords from a clean device (unique, via a password manager).",
        "Scan the device for malware; remove unknown apps and browser extensions.",
        "Check mailbox rules, forwarding addresses and connected apps.",
        "Block the sender, domain and URLs at the mail filter or firewall.",
    ],
    "Recovery": [
        "Restore from clean backups if files or settings were altered.",
        "Monitor accounts and statements closely for several weeks.",
        "Warn anyone who may have received the same message.",
        "Document the timeline and keep evidence (headers, screenshots).",
    ],
    "MFA Audit": [
        "Confirm MFA is on for email, banking and cloud accounts.",
        "Prefer authenticator apps, passkeys or security keys over SMS codes.",
        "Review enrolled devices and revoke any you don't recognise.",
        "Never approve MFA prompts you did not start; report them.",
    ],
}

FLAG_LABELS = {
    "BEC": "Business Email Compromise (payment/identity fraud) indicators",
    "SMISHING": "Smishing (SMS phishing) indicators",
    "SPEAR": "Personalised wording: possible spear phishing",
}


def report(res):
    if res.score >= HIGH_AT:
        verdict = "HIGH RISK: likely phishing"
    elif res.score >= MEDIUM_AT:
        verdict = "MEDIUM RISK: suspicious, verify before acting"
    else:
        verdict = "LOW RISK: no strong indicators found"

    print(f"\nVerdict: {verdict}\nScore:   {res.score}")

    if res.flags:
        print("\nAttack type indicators:")
        for f in sorted(res.flags):
            print(f"  - {FLAG_LABELS[f]}")
    if res.tactics:
        print("\nSocial engineering tactics detected:")
        for t in sorted(res.tactics):
            print(f"  - {t}")
    if res.findings:
        print("\nIndicators:")
        for reason, pts in sorted(res.findings.items(), key=lambda x: -x[1]):
            print(f"  [+{pts}] {reason}")

    if res.score >= MEDIUM_AT:
        print("\nRecommended response:")
        for phase, tips in RESPONSE_TIPS.items():
            print(f"  {phase}")
            for tip in tips:
                print(f"    - {tip}")

    print("\nNote: heuristic check only. When in doubt, verify with the sender "
          "through a separate, trusted channel.\n")


def main():
    ap = argparse.ArgumentParser(description="Basic phishing detector")
    ap.add_argument("file", nargs="?", help="email/text file, or '-' for stdin")
    ap.add_argument("--url", help="analyze a single URL")
    ap.add_argument("--sms", help="analyze an SMS/chat message (text in quotes)")
    ap.add_argument("--check-tls", action="store_true",
                    help="validate HTTPS certificates of linked sites "
                         "(makes network requests)")
    a = ap.parse_args()

    if a.url:
        res = Result()
        res.extend(analyze_url(a.url))
        if a.check_tls and a.url.startswith("https://"):
            res.extend(check_tls(urlparse(a.url).hostname))
    elif a.sms:
        res = analyze_sms(a.sms, a.check_tls)
    elif a.file:
        raw = sys.stdin.read() if a.file == "-" else \
            open(a.file, encoding="utf-8", errors="replace").read()
        res = analyze_email(raw, a.check_tls)
    else:
        ap.print_help()
        sys.exit(1)
    report(res)


if __name__ == "__main__":
    main()
