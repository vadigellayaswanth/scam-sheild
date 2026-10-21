"""
app.url_analyzer
~~~~~~~~~~~~~~~~

Accurate, evidence-based, heuristic-driven and SSRF-protected URL analysis engine for Scam Shield.
Specifically designed to inspect suspicious links impersonating Amazon or leading
to phishing, credential harvesting, malware downloads, and payment extortion.

Key Capabilities & Security Guarantees:
1. Accurate URL Parsing & Registered Domain Extraction:
   - Robust normalization, port handling, path/query breakdown.
   - Exact registered domain identification (multi-part ccTLDs like .co.in, .co.uk, .gov.in, .edu.in).
   - Punycode / IDN homograph detection (xn--).
   - Hex / Octal / Decimal obfuscated numerical IP formats (e.g. 2130706433, 0x7f000001, 0177.0.0.1).
   - Misleading subdomains (e.g., amazon.in.attacker.com).
   - Typosquatting and Levenshtein lookalike distance detection with false-positive prevention on benign dictionary words (e.g. 'amazing').
   - Brand impersonation (unauthorized use of 'amazon', 'amzn', 'prime', 'aws').
   - URL shorteners (bit.ly, tinyurl, etc.).
2. Safe Live Probing & SSRF Defenses:
   - Strict scheme enforcement (http/https only).
   - DNS pre-resolution validating that NO resolved IP is localhost, loopback, private RFC 1918,
     link-local (169.254.169.254 cloud metadata), CGNAT (100.64.0.0/10), multicast, or reserved.
   - Anti-DNS-Rebinding protection: connects directly to the resolved and verified IP address with the Host header and SNI.
   - Hop-by-hop redirect following re-validating the resolved IP for EVERY destination hop.
   - Connect timeout (2.5s), read timeout (3.0s), response-size limit (64KB stream limit), zero script execution, zero form submission.
3. Live Threat-Intelligence (Google Safe Browsing API v4):
   - Optional, credential-safe integration via SAFE_BROWSING_API_KEY.
   - Distinguishes verified malicious matches (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION)
     from unverified/heuristic detections.
4. Honest, Evidence-Based Verdicts & Risk Scoring:
   - Verdicts: 'Malicious' (verified threat or high-confidence attack), 'Suspicious' (deceptive indicators),
     'Safe-Looking' (official domain, no threat evidence), or 'Unverified' (probing failed/unreachable or ambiguous).
   - Never claims a URL is 100% safe solely because no threats were found.
   - Explains detected evidence explicitly.
"""

import os
import re
import socket
import ipaddress
import logging
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import httpx
from dotenv import load_dotenv

# Ensure environment variables are loaded
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

logger = logging.getLogger("scam_shield.url_analyzer")

# Regex to safely extract URLs from multiline, multilingual messages (en, hi, te)
URL_EXTRACTION_PATTERN = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>\"\'`{}|\\^\[\]]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|in|org|net|co|xyz|top|info|biz|cc|tv|club|live|shop|store|online|site|app|link|click|buzz|tech|me|io|is|gd|ly|to)[^\s<>\"\'`{}|\\^\[\]]*)",
    re.UNICODE,
)

# Known legitimate Amazon apex/canonical domains
OFFICIAL_AMAZON_DOMAINS = {
    "amazon.in",
    "amazon.com",
    "amzn.to",
    "amzn.in",
    "amazonpay.in",
    "aws.amazon.com",
    "sellercentral.amazon.in",
    "pay.amazon.in",
}

# Known URL shortener domains commonly abused in SMS / WhatsApp phishing
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "tiny.cc",
    "rb.gy",
    "wa.me",
    "t.me",
    "v.gd",
    "shorturl.at",
    "rebrand.ly",
}

# Suspicious / high-abuse TLDs frequently seen in low-cost cyber scam campaigns
HIGH_ABUSE_TLDS = {
    "xyz", "top", "club", "buzz", "click", "work", "cf", "gq", "ml", "tk",
    "ga", "icu", "cam", "fit", "rest", "surf", "monster", "date", "racing",
}

# Multi-part second-level domains for accurate registered domain parsing
TWO_PART_TLDS = {
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "gov.in", "ac.in", "edu.in", "res.in",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "com.sg", "edu.sg", "gov.sg",
}

# Sensitive credential / fraud keywords in URL path or query
SUSPICIOUS_PATH_KEYWORDS = [
    ("kyc", 25, "URL path contains 'kyc' verification keyword"),
    ("pan", 20, "URL references PAN card update/verification"),
    ("aadhaar", 20, "URL references Aadhaar card update"),
    ("otp", 30, "URL references OTP submission or credential entry"),
    ("refund", 20, "URL path claims payment or order refund"),
    ("claim", 15, "URL references prize or gift claiming"),
    ("reward", 15, "URL references reward or lucky draw"),
    ("login", 15, "URL contains external login page reference"),
    ("verify", 15, "URL demands account or credential verification"),
    ("suspend", 25, "URL references account suspension or hold"),
    ("block", 25, "URL references account block"),
    ("amazon-pay", 25, "URL path/subdomain references Amazon Pay"),
    ("update-account", 25, "URL path references urgent account update"),
    ("apk", 40, "URL targets third-party Android APK download"),
]

# Amazon lookalike and typosquatting tokens (e.g. amaz0n, amzon, amzn-security)
TYPOSQUAT_PATTERNS = [
    re.compile(r"amaz0n", re.IGNORECASE),
    re.compile(r"amz0n", re.IGNORECASE),
    re.compile(r"amzn[-_.]", re.IGNORECASE),
    re.compile(r"amazon[-_.](?:update|kyc|verify|support|refund|security|login|order|pay)", re.IGNORECASE),
    re.compile(r"(?:update|kyc|verify|support|refund|security|login|order|pay)[-_.]amazon", re.IGNORECASE),
    re.compile(r"amz[-_.](?:update|kyc|verify|support|refund|pay)", re.IGNORECASE),
]

# Common benign dictionary words close in edit distance to 'amazon' that must NOT trigger false positives
BENIGN_WORDS = {"amazing", "amazed", "amazingly", "amazonas", "amazonian"}


def extract_urls(text: str) -> List[str]:
    """
    Extracts, cleans, and normalizes URLs from raw message text.
    Handles English, Hindi, and Telugu multilingual strings cleanly.
    Strips trailing punctuation (periods, commas, colons, brackets).
    """
    if not isinstance(text, str) or not text.strip():
        return []

    found = URL_EXTRACTION_PATTERN.findall(text)
    clean_urls: List[str] = []
    seen = set()

    for item in found:
        candidate = item.strip()
        candidate = re.sub(r"[.,;:!?)\]}>]+$", "", candidate)
        if not candidate:
            continue

        if not candidate.lower().startswith(("http://", "https://")):
            if "." in candidate and not candidate.startswith("/"):
                candidate = "https://" + candidate
            else:
                continue

        try:
            parsed = urllib.parse.urlparse(candidate)
            if parsed.scheme.lower() not in {"http", "https"}:
                continue
            if not parsed.netloc:
                continue
            if candidate.lower() not in seen:
                seen.add(candidate.lower())
                clean_urls.append(candidate)
        except Exception:
            continue

    return clean_urls


def parse_ip_or_obfuscated(host_str: str) -> Optional[Any]:
    """
    Parses standard IPv4/IPv6, dword (integer), hex, and octal IP address representations.
    Returns an ipaddress object if the host represents an IP, or None if it is a domain name.
    """
    s = (host_str or "").strip().strip("[]").split(":")[0].strip()
    if not s:
        return None

    # 1. Standard IPv4 / IPv6
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        pass

    # 2. Single integer / dword or single hex (e.g. 2130706433, 0x7f000001)
    if re.match(r"^(?:0x[0-9a-fA-F]+|\d+)$", s):
        try:
            val = int(s, 0)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # 3. Dotted octal / hex (e.g. 0177.0.0.1, 0x7f.0.0.1)
    parts = s.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                if p.startswith(("0x", "0X")):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    octets.append(int(p, 8))
                elif p.isdigit():
                    octets.append(int(p, 10))
                else:
                    return None
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(bytes(octets))
        except Exception:
            pass

    return None


def get_registered_domain(hostname: str) -> str:
    """
    Extracts the true registrable domain (e.g. example.co.in from sub.example.co.in,
    or attacker.com from amazon.in.attacker.com).
    """
    host = (hostname or "").lower().strip().split(":")[0].strip("[]")
    if not host:
        return ""

    # If it is an IP address, return host as is
    parsed_ip = parse_ip_or_obfuscated(host)
    if parsed_ip is not None:
        return str(parsed_ip)

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    # Check for two-part ccTLDs (e.g. .co.in, .co.uk)
    suffix_2 = ".".join(parts[-2:])
    if suffix_2 in TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Standard TLD
    return ".".join(parts[-2:])


def calculate_levenshtein(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def is_ip_blocked_for_ssrf(ip_input: Any) -> Tuple[bool, str]:
    """
    Validates whether an IP address belongs to private, loopback, link-local,
    multicast, carrier-grade NAT, reserved, or non-public ranges.

    Returns:
        (is_blocked: bool, reason: str)
    """
    if isinstance(ip_input, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = ip_input
    else:
        ip = parse_ip_or_obfuscated(str(ip_input))
        if ip is None:
            return True, "Invalid IP address syntax"

    if ip.is_loopback:
        return True, "Loopback address (localhost) blocked for SSRF safety"
    if ip.is_link_local:
        return True, "Link-local address (RFC 3927) blocked for SSRF safety"
    if ip.is_private:
        return True, "Private / internal network IP (RFC 1918 / RFC 4193) blocked for SSRF safety"
    if ip.is_multicast:
        return True, "Multicast address blocked for SSRF safety"
    if ip.is_reserved:
        return True, "Reserved IP range blocked for SSRF safety"
    if ip.is_unspecified:
        return True, "Unspecified address (0.0.0.0 / ::) blocked for SSRF safety"
    if not ip.is_global:
        return True, "Non-globally routable address (RFC 6598 CGNAT or special-use) blocked for SSRF safety"

    return False, "Public IP"


def resolve_hostname_safely(hostname: str) -> Tuple[bool, List[str], str]:
    """
    Resolves hostname to IP addresses and verifies that NONE belong to private/reserved ranges.
    Decodes obfuscated IP notation (hex, octal, dword) prior to DNS lookup.

    Returns:
        (is_safe: bool, resolved_ips: list[str], diagnostic_message: str)
    """
    host = hostname.split(":")[0].strip().strip("[]")
    if not host:
        return False, [], "Empty hostname"

    # Check if host is direct or obfuscated IP
    direct_ip = parse_ip_or_obfuscated(host)
    if direct_ip is not None:
        is_blocked, reason = is_ip_blocked_for_ssrf(direct_ip)
        if is_blocked:
            return False, [str(direct_ip)], reason
        return True, [str(direct_ip)], "Valid public IP host"

    # Resolve via DNS
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips: List[str] = []
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        if not resolved_ips:
            return False, [], "DNS lookup returned no records"

        # Verify every resolved address
        for ip_str in resolved_ips:
            is_blocked, reason = is_ip_blocked_for_ssrf(ip_str)
            if is_blocked:
                return False, resolved_ips, f"Hostname resolves to unsafe destination ({ip_str}): {reason}"

        return True, resolved_ips, "Hostname resolved to safe public destination"

    except socket.gaierror as e:
        return False, [], f"DNS resolution failed: {e}"
    except Exception as e:
        return False, [], f"Resolution error: {type(e).__name__}"


def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Safely queries Google Safe Browsing API v4 for threat intelligence if configured.
    Does not leak API key on error.

    Returns:
        {
            "checked": bool,
            "status": "clean" | "malicious" | "error" | "unconfigured",
            "matches": list[str],
            "threat_types": list[str],
            "diagnostic": str
        }
    """
    api_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    if not api_key or api_key == "your_google_safe_browsing_api_key_here":
        return {
            "checked": False,
            "status": "unconfigured",
            "matches": [],
            "threat_types": [],
            "diagnostic": "Google Safe Browsing API key not configured.",
        }

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "scam-shield-defense",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(f"{endpoint}?key={api_key}", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
                    return {
                        "checked": True,
                        "status": "malicious",
                        "matches": matches,
                        "threat_types": threat_types,
                        "diagnostic": f"Verified malicious match in Google Safe Browsing: {', '.join(threat_types)}",
                    }
                return {
                    "checked": True,
                    "status": "clean",
                    "matches": [],
                    "threat_types": [],
                    "diagnostic": "No threat matches found in Google Safe Browsing database.",
                }
            elif resp.status_code in (400, 401, 403):
                return {
                    "checked": False,
                    "status": "error",
                    "matches": [],
                    "threat_types": [],
                    "diagnostic": f"Safe Browsing API authentication error (HTTP {resp.status_code}).",
                }
            else:
                return {
                    "checked": False,
                    "status": "error",
                    "matches": [],
                    "threat_types": [],
                    "diagnostic": f"Safe Browsing API returned HTTP {resp.status_code}.",
                }
    except Exception as exc:
        return {
            "checked": False,
            "status": "error",
            "matches": [],
            "threat_types": [],
            "diagnostic": f"Safe Browsing request failed: {type(exc).__name__}",
        }


def check_live_availability(
    url: str,
    max_redirects: int = 3,
    connect_timeout: float = 2.5,
    read_timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Safely probes whether a URL responds, adhering strictly to SSRF safeguards:
    - Pre-validates hostname IP before initiating request.
    - Mitigates DNS Rebinding by pinning connections directly to the verified safe IP.
    - Manually tracks redirects, re-validating the resolved IP for EVERY hop.
    - Limits read size to 64KB (no full webpage download, no script execution).
    - Returns structured availability results.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "available": "invalid_scheme",
            "status_code": None,
            "final_url": url,
            "redirect_history": [],
            "error_detail": "Only HTTP and HTTPS protocols are permitted.",
        }

    current_url = url
    redirect_history: List[str] = []

    for _ in range(max_redirects + 1):
        cur_parsed = urllib.parse.urlparse(current_url)
        scheme = cur_parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return {
                "available": "blocked_ssrf",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": f"Redirected to disallowed scheme: {scheme}",
            }

        hostname = cur_parsed.hostname or ""
        is_safe, resolved_ips, diag = resolve_hostname_safely(hostname)
        if not is_safe:
            if "DNS resolution failed" in diag:
                return {
                    "available": "unreachable",
                    "status_code": None,
                    "final_url": current_url,
                    "redirect_history": redirect_history,
                    "error_detail": "Domain does not resolve (DNS failure / unreachable).",
                }
            return {
                "available": "blocked_ssrf",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": f"SSRF Protection: {diag}",
            }

        # Safe to connect: pin to verified safe IP to defeat DNS rebinding
        safe_ip = resolved_ips[0]
        port = cur_parsed.port or (443 if scheme == "https" else 80)
        path = cur_parsed.path or "/"
        if cur_parsed.query:
            path += "?" + cur_parsed.query

        ip_host_str = f"[{safe_ip}]" if ":" in safe_ip else safe_ip
        pinned_target = f"{scheme}://{ip_host_str}:{port}{path}"
        headers = {
            "Host": hostname,
            "User-Agent": "ScamShield-SecurityProbe/1.0 (+https://github.com/vadigellayaswanth/scam-sheild)",
        }

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(read_timeout, connect=connect_timeout),
                verify=False,  # Allow self-signed test certs safely for probe verification
            ) as client:
                req = client.build_request(
                    "GET",
                    pinned_target,
                    headers=headers,
                    extensions={"sni_hostname": hostname} if scheme == "https" else {},
                )

                with client.send(req, stream=True) as resp:
                    # Bounded stream read (max 64KB)
                    total_bytes = 0
                    for chunk in resp.iter_bytes(chunk_size=4096):
                        total_bytes += len(chunk)
                        if total_bytes >= 65536:
                            break

                    if resp.is_redirect and "location" in resp.headers:
                        next_url = urllib.parse.urljoin(current_url, resp.headers["location"])
                        redirect_history.append(current_url)
                        current_url = next_url
                        continue
                    else:
                        return {
                            "available": "online" if resp.status_code < 500 else "server_error",
                            "status_code": resp.status_code,
                            "final_url": current_url,
                            "redirect_history": redirect_history,
                            "error_detail": None,
                        }

        except httpx.ConnectTimeout:
            return {
                "available": "unreachable",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": "Connection timed out.",
            }
        except httpx.ReadTimeout:
            return {
                "available": "unreachable",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": "Response read timed out.",
            }
        except httpx.RequestError as exc:
            return {
                "available": "unreachable",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": f"Network error: {type(exc).__name__}",
            }
        except Exception as exc:
            return {
                "available": "unknown",
                "status_code": None,
                "final_url": current_url,
                "redirect_history": redirect_history,
                "error_detail": f"Probe error: {type(exc).__name__}",
            }

    # Exceeded max redirects
    return {
        "available": "suspicious_redirects",
        "status_code": None,
        "final_url": current_url,
        "redirect_history": redirect_history,
        "error_detail": f"Too many redirects (exceeded limit of {max_redirects}).",
    }


def analyze_url_heuristics(
    url: str,
    availability_result: Optional[Dict[str, Any]] = None,
    language: str = "en",
    threat_intel_result: Optional[Dict[str, Any]] = None,
    surrounding_message: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates evidence-based risk metrics for a single URL:
    - Registered domain identification
    - Brand impersonation & Levenshtein lookalike typosquatting
    - Misleading subdomains & punycode IDN homographs
    - URL shortener obfuscation
    - Direct numerical IP addresses
    - Sensitive fraud/credential paths
    - Live redirect destination validation
    - Live threat intelligence (Safe Browsing)
    - Surrounding message context analysis
    - Honest verdicts: 'safe_looking' (or 'low'), 'suspicious' ('medium'), 'high', 'critical' ('malicious'), 'unverified'
    - Confidence level: 'high', 'medium', 'low'
    """
    score = 0
    red_flags: List[str] = []
    category = "Legitimate or Low-Risk Link"
    confidence = "medium"

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    reg_domain = get_registered_domain(host)

    # 1. Check scheme
    if scheme not in {"http", "https"}:
        return {
            "url": url,
            "domain": host,
            "registered_domain": host,
            "risk_score": 90,
            "verdict": "critical",
            "verdict_label": "Malicious",
            "confidence": "high",
            "category": "Disallowed or Suspicious URL Scheme",
            "red_flags": [f"Disallowed protocol: '{parsed.scheme}'. Only HTTP and HTTPS are permitted."],
            "safe_actions": ["Do not open links with non-standard protocols in your browser."],
            "availability": "invalid_scheme",
            "redirect_destination": None,
            "reputation_checked": False,
            "threat_intelligence": {"checked": False, "status": "skipped"},
        }

    # 2. Check Punycode / IDN Homographs
    is_punycode = False
    if "xn--" in host:
        is_punycode = True
        score += 60
        red_flags.append(f"Punycode / IDN homograph detected in domain '{host}' (often used to visually spoof legitimate brand letters)")
        category = "Punycode Homograph Spoofing"

    # 3. Check if host is direct or obfuscated IP address
    is_direct_ip = False
    parsed_ip = parse_ip_or_obfuscated(host)
    if parsed_ip is not None:
        is_direct_ip = True
        score += 50
        red_flags.append(f"Uses raw numerical IP address ({host}) instead of an official registered domain name")
        category = "Direct IP Address Link"

    # 4. Check for Official Amazon Domains
    is_official_amazon = False
    for off_domain in OFFICIAL_AMAZON_DOMAINS:
        if reg_domain == off_domain or host == off_domain or host.endswith("." + off_domain):
            is_official_amazon = True
            break

    if is_official_amazon:
        category = "Official Amazon Domain"
        score = 0
        confidence = "high"

    # 5. Check for URL Shorteners
    is_shortener = False
    for shortener in KNOWN_SHORTENERS:
        if reg_domain == shortener or host == shortener or host.endswith("." + shortener):
            is_shortener = True
            score += 35
            red_flags.append(f"Uses URL shortener ({host}) to obscure the true website destination")
            category = "Masked or Shortened Link"
            break

    # 6. Check for Brand Impersonation, Lookalikes & Misleading Subdomains
    if not is_official_amazon and not is_direct_ip:
        reg_name = reg_domain.split(".")[0] if reg_domain else ""

        # Obvious keyword presence in registered domain
        if "amazon" in reg_domain or "amzn" in reg_domain:
            score += 65
            red_flags.append(f"Suspicious brand impersonation: Registered domain '{reg_domain}' imitates Amazon but is NOT an official domain")
            category = "Brand Impersonation & Typosquatting"

        for pattern in TYPOSQUAT_PATTERNS:
            if pattern.search(host):
                score += 70
                red_flags.append(f"Deceptive lookalike domain detected in host: '{host}'")
                category = "Brand Impersonation & Typosquatting"
                break

        # Levenshtein distance check against "amazon" with false-positive filtering
        if reg_name and reg_name not in {"amazon", "amzn"} and reg_name not in BENIGN_WORDS and len(reg_name) >= 4:
            dist = calculate_levenshtein(reg_name, "amazon")
            if dist == 1:
                score += 65
                red_flags.append(f"Typosquatting alert: Domain name '{reg_name}' is suspiciously close to 'amazon' (edit distance: {dist})")
                category = "Brand Impersonation & Typosquatting"
            elif dist == 2:
                # Check for visual substitutions or Amazon token presence
                has_sub = any(c in reg_name for c in "01-_") or ("amz" in reg_name and "on" in reg_name)
                full_pq = f"{path}?{query}"
                has_kw = any(kw in full_pq for kw, _, _ in SUSPICIOUS_PATH_KEYWORDS)
                if has_sub or has_kw:
                    score += 55
                    red_flags.append(f"Typosquatting alert: Lookalike domain name '{reg_name}' resembles 'amazon'")
                    category = "Brand Impersonation & Typosquatting"

        # Misleading subdomains (e.g., amazon.in.attacker-phish.com)
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain_str = host[:-(len(reg_domain) + 1)] if host.endswith("." + reg_domain) else ".".join(parts[:-2])
            if "amazon" in subdomain_str or "amzn" in subdomain_str:
                score += 60
                red_flags.append(f"Misleading subdomain structure: attempts to mimic Amazon under root domain '{reg_domain}'")
                category = "Misleading Subdomain Phishing"

        # High-Abuse TLDs
        tld = parts[-1] if parts else ""
        if tld in HIGH_ABUSE_TLDS:
            score += 30
            red_flags.append(f"Registered on high-abuse top-level domain (.{tld}) commonly used by throwaway phishing sites")

    # 7. Sensitive Path & Query Keywords
    full_path_query = f"{path}?{query}"
    for kw, kw_score, kw_desc in SUSPICIOUS_PATH_KEYWORDS:
        if kw in full_path_query:
            score += kw_score
            red_flags.append(kw_desc)
            if not is_official_amazon and category in {"Legitimate or Low-Risk Link", "Masked or Shortened Link"}:
                category = "Phishing or Credential Theft Link"

    # 8. Unencrypted HTTP connection warning
    if scheme == "http" and not is_official_amazon:
        if score > 0:
            red_flags.append("Unencrypted connection (HTTP instead of HTTPS); sensitive data sent over this link lacks TLS protection")

    # 9. Surrounding Message Context Analysis
    if surrounding_message and isinstance(surrounding_message, str) and not is_official_amazon:
        msg_lower = surrounding_message.lower()
        threat_markers = [
            ("blocked", "account blocked threat in message"),
            ("suspended", "account suspension threat in message"),
            ("kyc", "urgency regarding KYC verification in message"),
            ("lottery", "cash prize / lottery bait in message"),
            ("gift card", "gift card / voucher demand in message"),
            ("pan card", "PAN card demand in message"),
            ("aadhaar", "Aadhaar credential request in message"),
            ("otp", "OTP request in message"),
            ("urgent", "manufactured urgency in message"),
        ]
        context_matches = [desc for kw, desc in threat_markers if kw in msg_lower]
        if context_matches:
            score += 20
            red_flags.append(f"Suspicious context: Message conveying this link contains {', '.join(context_matches[:2])}")

    # 10. Live Availability & Redirect Destination Findings
    final_destination = None
    availability_status = "unknown"
    if availability_result:
        availability_status = availability_result.get("available", "unknown")
        final_destination = availability_result.get("final_url")
        redirects = availability_result.get("redirect_history", [])

        if availability_status == "blocked_ssrf":
            score += 80
            red_flags.append(f"Security Alert: Destination attempted access to internal/private infrastructure ({availability_result.get('error_detail')})")
            category = "SSRF or Internal Network Probe"
            confidence = "high"

        elif availability_status == "suspicious_redirects":
            score += 45
            red_flags.append("Excessive redirect chain detected (exceeded safe redirect limit)")
            category = "Suspicious Redirect Loop"

        elif redirects and final_destination and final_destination != url:
            final_parsed = urllib.parse.urlparse(final_destination)
            final_host = (final_parsed.hostname or "").lower()
            final_reg = get_registered_domain(final_host)
            if not any(final_reg == off or final_host == off or final_host.endswith("." + off) for off in OFFICIAL_AMAZON_DOMAINS):
                score += 30
                red_flags.append(f"Redirects to unverified external destination: {final_destination}")
                if is_shortener:
                    category = "Shortened Link to External Destination"

    # 11. Live Threat Intelligence (Google Safe Browsing)
    ti_data = {"checked": False, "status": "unconfigured"}
    if threat_intel_result:
        ti_data = threat_intel_result
        if threat_intel_result.get("status") == "malicious":
            score = max(score, 95)
            threat_list = threat_intel_result.get("threat_types", [])
            red_flags.insert(0, f"Verified threat intelligence alert: Flagged as {', '.join(threat_list)} in Google Safe Browsing")
            category = "Confirmed Malicious Phishing/Malware"
            confidence = "high"

    # Final Risk Score (0-100)
    risk_score = min(score, 100)

    # Determine Verdict and Honest Labeling
    if risk_score >= 75:
        verdict = "critical"
        verdict_label = "Malicious"
        confidence = "high"
    elif risk_score >= 45:
        verdict = "high"
        verdict_label = "Suspicious"
        confidence = "high" if (is_shortener or len(red_flags) >= 2) else "medium"
    elif risk_score >= 20:
        verdict = "medium"
        verdict_label = "Suspicious"
        confidence = "medium"
    else:
        if availability_result is not None and availability_status in {"unreachable", "unknown"}:
            verdict = "low"
            verdict_label = "Unverified"
            confidence = "low"
        else:
            verdict = "low"
            verdict_label = "Safe-Looking"
            confidence = "high" if is_official_amazon else "medium"

    # Safe Actions
    safe_actions: List[str] = []
    lang = language.lower().strip() if language in {"en", "hi", "te"} else "en"

    if lang == "hi":
        if verdict in {"critical", "high"}:
            safe_actions = [
                "इस लिंक पर बिल्कुल क्लिक न करें और न ही कोई विवरण दर्ज करें।",
                "किसी भी अज्ञात वेबसाइट पर अपना पासवर्ड, ओटीपी (OTP), या यूपीआई पिन कभी न डालें।",
                "अमेज़न से संबंधित किसी भी अलर्ट की जांच केवल आधिकारिक ऐप या amazon.in पर करें।",
            ]
        elif is_shortener:
            safe_actions = [
                "यह एक छोटा (shortened) लिंक है जो असली वेबसाइट को छुपाता है। इसे खोलने से बचें।",
                "सीधे आधिकारिक अमेज़न ऐप खोलकर ऑर्डर या खाते की जांच करें।",
            ]
        elif verdict_label == "Unverified":
            safe_actions = [
                "वेबसाइट अनुत्तरदायी या पहुंच से बाहर है। इसे किसी विश्वसनीय स्रोत से ही सत्यापित करें।",
                "अज्ञात लिंक पर कोई भी व्यक्तिगत जानकारी साझा न करें।",
            ]
        else:
            safe_actions = [
                "सत्यापित करें कि वेबसाइट का पता आधिकारिक amazon.in से मेल खाता है।",
                "असुरक्षित लिंक पर व्यक्तिगत या वित्तीय जानकारी कभी दर्ज न करें।",
            ]
    elif lang == "te":
        if verdict in {"critical", "high"}:
            safe_actions = [
                "ఈ లింక్‌ను ఎట్టి పరిస్థితుల్లోనూ క్లిక్ చేయవద్దు లేదా ఎలాంటి వివరాలు ఇవ్వవద్దు.",
                "తెలియని వెబ్‌సైట్లలో మీ పాస్‌వర్డ్, ఓటీపీ (OTP) లేదా యూపీఐ పిన్ నమోదు చేయవద్దు.",
                "అమెజాన్ హెచ్చరికలను ఎల్లప్పుడూ అధికారిక యాప్ లేదా amazon.in లో మాత్రమే తనిఖీ చేయండి.",
            ]
        elif is_shortener:
            safe_actions = [
                "ఇది అసలు వెబ్‌సైట్‌ను దాచే షార్ట్ చేసిన లింక్. దీన్ని తెరవవద్దు.",
                "ఖాతా స్థితిని నేరుగా అధికారిక అమెజాన్ యాప్‌లో తనిఖీ చేయండి.",
            ]
        elif verdict_label == "Unverified":
            safe_actions = [
                "వెబ్‌సైట్ స్పందించడం లేదు లేదా చేరుకోలేకపోతోంది. అప్రమత్తంగా ఉండండి.",
                "అపరిచిత లింక్‌లలో వ్యక్తిగత సమాచారం నమోదు చేయవద్దు.",
            ]
        else:
            safe_actions = [
                "వెబ్‌సైట్ చిరునామా అధికారిక amazon.in కు చెందినదో కాదో సరిచూసుకోండి.",
                "అపరిచిత లింక్‌లలో వ్యక్తిగత సమాచారం నమోదు చేయవద్దు.",
            ]
    else:
        if verdict in {"critical", "high"}:
            safe_actions = [
                "Do not click this link or submit any personal credentials, passwords, or OTPs.",
                "Verify your Amazon account or order exclusively through the official Amazon app or at amazon.in.",
                "Report this link and sender as a scam or phishing attempt.",
            ]
        elif is_shortener:
            safe_actions = [
                "Be cautious: shortened links obscure the destination server to avoid detection.",
                "Do not enter passwords or payment credentials if redirected to an unknown page.",
            ]
        elif verdict_label == "Unverified":
            safe_actions = [
                "This domain did not respond or could not be reached. Do not trust unverified communications.",
                "Check account status directly by typing amazon.in in a clean browser window.",
            ]
        else:
            safe_actions = [
                "Ensure any Amazon webpage explicitly uses the official amazon.in or amazon.com domain.",
                "Never enter banking, card, or OTP details on unverified third-party websites.",
            ]

    return {
        "url": url,
        "domain": host,
        "registered_domain": reg_domain,
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "confidence": confidence,
        "category": category,
        "red_flags": red_flags,
        "safe_actions": safe_actions,
        "availability": availability_status,
        "redirect_destination": final_destination,
        "reputation_checked": bool(ti_data.get("checked")),
        "threat_intelligence": ti_data,
    }


def analyze_scam_url(
    url: str,
    check_live: bool = True,
    language: str = "en",
    surrounding_message: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Primary entrypoint for analyzing a suspicious URL.
    Safely executes SSRF-protected availability check (if check_live=True),
    queries threat intelligence (Safe Browsing) if configured,
    and combines findings with registered domain and heuristic scoring.
    """
    clean_urls = extract_urls(url)
    target_url = clean_urls[0] if clean_urls else url.strip()

    avail_result = None
    if check_live:
        avail_result = check_live_availability(target_url)

    ti_result = None
    if check_live:
        ti_result = check_google_safe_browsing(target_url)

    return analyze_url_heuristics(
        url=target_url,
        availability_result=avail_result,
        language=language,
        threat_intel_result=ti_result,
        surrounding_message=surrounding_message,
    )
