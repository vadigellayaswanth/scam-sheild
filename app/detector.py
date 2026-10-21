"""
app.detector
~~~~~~~~~~~~

Rule-based scam and phishing detection engine for Scam Shield.
Specifically geared towards identifying messages impersonating Amazon targeting
users in India across English, Hindi, and Telugu (including native scripts and
common Romanized transliterations).

IMPORTANT LIMITATIONS & DISCLAIMER:
- This detector uses deterministic pattern matching and heuristics.
- A high risk score is an indicator/warning of suspicious signals, NOT definitive legal proof of fraud.
- A low risk score indicates no known high-risk red flags were triggered, but it does NOT guarantee safety.
- Treat every unsolicited communication with vigilance; verify orders and account activity directly via the official Amazon app or website (amazon.in).
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Any

SUPPORTED_LANGUAGES = {"en", "hi", "te"}

# URL Regex and known official Amazon domains
URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
)
SHORTENER_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|cutt\.ly|tiny\.cc|rb\.gy|wa\.me|t\.me)/[a-z0-9_-]+"
)
# Exact registered domains that are genuinely official Amazon properties.
# Subdomains of these are also accepted (e.g. www.amazon.in, sellercentral.amazon.in).
OFFICIAL_AMAZON_DOMAINS = [
    "amazon.in",
    "amazon.com",
    "amzn.to",
    "amzn.in",
]

# Common patterns across categories
# Each tuple: (Rule ID, points, description, list of regex patterns)

CATEGORY_RULES: Dict[str, List[Tuple[str, int, str, List[str]]]] = {
    "Fake customer support asking users to install remote-access software": [
        (
            "REMOTE_APP",
            60,
            "Requests installation of remote screen-sharing or access software",
            [
                r"\b(?:anydesk|teamviewer|quicksupport|any\s*desk|team\s*viewer|rustdesk|zoho\s*assist|airdroid)\b",
                r"(?:download|install|open)\s+.*?\b(?:anydesk|teamviewer|app|apk)\b",
                r"(?:anydesk|teamviewer)\s+.*?\b(?:install|download|kare|cheyandi|dowlod)\b",
            ],
        ),
        (
            "REMOTE_ACCESS_PHRASE",
            30,
            "Mentions remote support or screen sharing to fix account/order issues",
            [
                r"\b(?:screen\s*share|remote\s*access|remote\s*support)\b",
                r"(?:screen\s*share\s*kare|screen\s*share\s*cheyandi)",
            ],
        ),
    ],
    "OTP, PIN, or CVV theft": [
        (
            "OTP_PIN_CVV_THEFT",
            70,
            "Direct request to share confidential security credentials (OTP, PIN, CVV, or card details)",
            [
                r"\b(?:otp|one\s*time\s*password|cvv|mpin|upi\s*pin|atm\s*pin)\b.*?\b(?:share|send|provide|tell|verify|enter|forward|bhejo|ivvandi|cheppandi)\b",
                r"\b(?:share|send|provide|tell|enter|bhejo|ivvandi|cheppandi)\b.*?\b(?:otp|cvv|pin|mpin)\b",
                r"\b(?:otp|cvv|pin)\s*(?:bhejiye|bhejo|bataye|cheppandi|ivvandi|share\s*karo)\b",
                r"(?:ओटीपी|पिन|सीवीवी)\s*(?:शेयर|भेजें|बताएं|साझा)",
                r"(?:ఓటీపీ|పిన్|సివివి)\s*(?:చెప్పండి|పంపండి|షేర్)",
            ],
        ),
    ],
    "Gift card, QR-code, or UPI collect-payment scams": [
        (
            "UPI_COLLECT_QR",
            50,
            "Requests payment via UPI collect request, QR code scan, or gift card purchase",
            [
                r"\b(?:scan\s*(?:the\s*)?qr(?:\s*code)?|scan\s*karke|qr\s*scan\s*cheyandi)\b",
                r"\b(?:upi\s*collect|approve\s*collect\s*request|enter\s*upi\s*pin\s*to\s*receive)\b",
                r"\b(?:pin\s*daalo\s*paise\s*milega|pin\s*kodithe\s*money\s*vasthundi)\b",
                r"\b(?:buy|purchase|send)\s+(?:amazon\s+)?gift\s*card\b",
                r"(?:क्युआर|क्यूआर\s*कोड|यूपीआई)\s*(?:स्कैन|पिन)",
                r"(?:క్యూఆర్\s*కోడ్|యూపీఐ)\s*(?:స్కాన్|పిన్)",
            ],
        ),
    ],
    "Fake account-blocking, KYC, or account-verification messages": [
        (
            "ACCOUNT_SUSPENSION_KYC",
            50,
            "Threatens account suspension, block, deactivation, or demands immediate KYC verification",
            [
                r"\b(?:account|id|khata|profile)\b.*?\b(?:blocked|suspended|deactivated|closed|terminated|hold|locked|block)\b",
                r"\b(?:update|complete|verify)\b.*?\b(?:kyc|pan|aadhaar|account\s*details)\b",
                r"\b(?:kyc)\b.*?\b(?:expired|pending|mandatory|suspend|update|incomplete)\b",
                r"(?:account\s*block\s*(?:hoga|ho\s*gaya|avuthundi|ayindi))",
                r"(?:kyc\s*update\s*(?:kare|kariye|cheyandi))",
                r"(?:खाता|अकाउंट)\s*.*?(?:ब्लॉक|बंद|सस्पेंड)",
                r"(?:ఖాతా|అకౌంట్)\s*.*?(?:బ్లాక్|రద్దు)",
            ],
        ),
    ],
    "Fake refund, order cancellation, or payment failure": [
        (
            "FAKE_REFUND_OR_ORDER",
            40,
            "Claims urgent order cancellation, refund processing, or payment failure requiring external action",
            [
                r"\b(?:order\s*cancelled|order\s*canceled|payment\s*failed|refund\s*(?:approved|processed|pending|initiated|credit))\b",
                r"\b(?:claim|get|receive|process)\b.*?\b(?:refund|cashback)\b",
                r"(?:refund\s*pane\s*ke\s*liye|refund\s*kosam|paise\s*wapas)",
                r"(?:रिफंड|ऑर्डर\s*रद्द|भुगतान\s*विफल)",
                r"(?:రీఫండ్|ఆర్డర్\s*రద్దు|చెల్లింపు\s*విఫలమైంది)",
            ],
        ),
    ],
    "Fake Prime or subscription charge": [
        (
            "FAKE_PRIME_CHARGE",
            40,
            "Unrecognized Amazon Prime membership renewal, unauthorized subscription debit, or cancellation threat",
            [
                r"\b(?:prime\s*(?:membership|subscription|renewal|auto-renew|charge|fee))\b",
                r"\bcharged\s+.*?\b(?:prime|subscription)\b",
                r"\b(?:cancel|dispute)\s+.*?\b(?:prime|subscription)\b",
                r"(?:प्राइम\s*सदस्यता|प्राइम\s*चार्ज)",
                r"(?:ప్రైమ్\s*సభ్యత్వం|ప్రైమ్\s*ఛార్జ్)",
            ],
        ),
    ],
    "Product review or task-based job scams": [
        (
            "TASK_JOB_SCAM",
            45,
            "Offers part-time job, daily income, or payment for writing product reviews or liking products",
            [
                r"\b(?:part[\s-]*time\s*job|work\s*from\s*home|daily\s*income|earn\s*(?:rs\.?|inr)?\s*\d+.*?(?:daily|per\s*day))\b",
                r"\b(?:write\s*reviews?|review\s*products?|amazon\s*rating|task\s*completion)\b",
                r"(?:ghar\s*baithe\s*kamaye|part\s*time\s*kam|rojana\s*kamai)",
                r"(?:ఇంటి\s*వద్దే\s*ఉండి\s*సంపాదించండి|పార్ట్\s*టైమ్\s*జాబ్)",
                r"(?:घर\s*बैठे\s*पैसे\s*कमाएं|पार्ट\s*टाइम\s*जॉब)",
            ],
        ),
    ],
    "Fake prize, lucky draw, or free iPhone offers": [
        (
            "PRIZE_LUCKY_DRAW",
            45,
            "Claims user has won a lottery, lucky draw contest, free gift, or iPhone from Amazon",
            [
                r"\b(?:congratulations|congrats|badhai\s*ho|subhakankshalu)\b.*?\b(?:won|winner|lucky\s*draw|lottery|free\s*iphone|prize)\b",
                r"\b(?:won|winner|lucky\s*draw|lottery)\b.*?\b(?:amazon|iphone|cash\s*prize|gift)\b",
                r"\b(?:claim\s*(?:your\s*)?(?:prize|gift|reward|iphone|car|bonus))\b",
                r"(?:लकी\s*ड्रॉ|इनाम|लॉटरी|मुफ्त\s*उपहार)",
                r"(?:లక్కీ\s*డ్రా|బహుమతి|లాటరీ|ఉచిత\s*బహుమతి)",
            ],
        ),
    ],
    "Fake delivery fee requests": [
        (
            "DELIVERY_FEE_SCAM",
            35,
            "Demands a small parcel release, custom, or redelivery charge for an Amazon package",
            [
                r"\b(?:delivery\s*(?:charge|fee)|redelivery|package\s*on\s*hold|address\s*incomplete)\b.*?\b(?:pay|rs\.?|inr|link)\b",
                r"\b(?:pay|deposit)\b.*?\b(?:delivery|dispatch|courier|parcel)\b",
                r"(?:पार्सल\s*रोका|डिलीवरी\s*चार्ज|पता\s*अपडेट)",
                r"(?:డెలివరీ\s*ఛార్జీ|పార్శిల్\s*ఆగింది)",
            ],
        ),
    ],
    "Fake product recalls": [
        (
            "FAKE_RECALL",
            35,
            "Urgent product safety recall notice prompting compensation or clicking an external link",
            [
                r"\b(?:product\s*recall|safety\s*recall|recalled\s*item|safety\s*hazard)\b.*?\b(?:refund|compensation|click|link|call)\b",
                r"(?:उत्पाद\s*वापसी|रिकॉल)",
                r"(?:ఉత్పత్తి\s*రీకాల్)",
            ],
        ),
    ],
}

# Cross-cutting indicators and pressure tactics
CROSS_CUTTING_INDICATORS: List[Tuple[str, int, str, List[str]]] = [
    (
        "URGENCY_THREATS",
        20,
        "Creates artificial urgency, threats of immediate penalty, police action, or short deadline",
        [
            r"\b(?:urgent|immediately|within\s*\d+\s*(?:mins?|minutes?|hours?)|immediate\s*action|without\s*delay)\b",
            r"\b(?:turant|jaldi|ippude|ventane|samayam\s*ledu)\b",
            r"\b(?:police\s*complaint|legal\s*action|fine\s*imposed|penalty)\b",
            r"(?:तुरंत|जल्दी|24\s*घंटे\s*के\s*भीतर|कानूनी\s*कार्रवाई)",
            r"(?:వెంటనే|ఇప్పుడే|చట్టపరమైన\s*చర్య)",
        ],
    ),
    (
        "REQUEST_PERSONAL_FINANCIAL_INFO",
        20,
        "Prompts entry or submission of sensitive personal, banking, or credential information",
        [
            r"\b(?:bank\s*details|card\s*number|credit\s*card|debit\s*card|password|aadhaar|pan\s*card)\b",
            r"(?:बैंक\s*खाता|पासवर्ड|आधार|पैन)",
            r"(?:బ్యాంక్\s*వివరాలు|పాస్‌వర్డ్|ఆధార్|పాన్)",
        ],
    ),
    (
        "UNOFFICIAL_CONTACT",
        15,
        "Directs user to call personal mobile numbers or contact via WhatsApp/Telegram",
        [
            r"\b(?:whatsapp|telegram|wa\.me|t\.me)\b",
            r"\bcall\s+(?:our\s+support\s+at\s+)?(?:\+91[- ]?)?[6-9]\d{9}\b",
            r"(?:whatsapp\s*kare|whatsapp\s*cheyandi)",
        ],
    ),
]

SAFE_ACTIONS_BY_CATEGORY: Dict[str, List[str]] = {
    "Fake customer support asking users to install remote-access software": [
        "Never install AnyDesk, TeamViewer, or screen-sharing apps requested by callers or SMS.",
        "Amazon customer service will never ask you to install remote access applications.",
        "Hang up immediately and contact Amazon solely through the official Amazon app (Customer Service section).",
    ],
    "OTP, PIN, or CVV theft": [
        "Never share OTPs, CVVs, ATM PINs, or UPI PINs with anyone, even if they claim to be from Amazon.",
        "Amazon representatives never ask for your confidential banking credentials or OTPs.",
        "If you already shared an OTP, immediately freeze your card/bank account using your banking app.",
    ],
    "Gift card, QR-code, or UPI collect-payment scams": [
        "Remember: entering your UPI PIN always sends money, it NEVER receives money.",
        "Do not scan QR codes or approve collect requests sent by unknown contacts.",
        "Amazon never asks customers to buy third-party gift cards or pay via personal UPI QR codes.",
    ],
    "Fake account-blocking, KYC, or account-verification messages": [
        "Do not click links claiming your Amazon account or KYC is suspended.",
        "Open the Amazon app or visit amazon.in directly to check your actual account status.",
        "Amazon does not require third-party APK installations or random SMS links for KYC.",
    ],
    "Fake refund, order cancellation, or payment failure": [
        "Check 'Your Orders' in the official Amazon app or on amazon.in to verify any cancellations or refunds.",
        "Amazon refunds are automatically credited back to your original payment method or Amazon Pay balance without needing you to click SMS links.",
        "Do not follow external links or call numbers provided in the text message.",
    ],
    "Fake Prime or subscription charge": [
        "Go to 'Your Account' -> 'Prime Membership' on amazon.in to verify your active subscriptions and charges.",
        "Do not call unverified customer care numbers listed in SMS or email alerts.",
        "If an unauthorized bank transaction occurred, report it immediately to your bank.",
    ],
    "Product review or task-based job scams": [
        "Be aware that Amazon does not hire reviewers or offer paid daily tasks via WhatsApp or Telegram.",
        "Never deposit money as 'prepaid investment' to unlock task commissions.",
        "Block and report the sender immediately.",
    ],
    "Fake prize, lucky draw, or free iPhone offers": [
        "Amazon does not notify lucky draw winners through random SMS, WhatsApp, or third-party links.",
        "Never pay 'registration fees', 'customs charges', or taxes to claim a purported prize.",
        "Legitimate Amazon contests are exclusively conducted on official Amazon platforms.",
    ],
    "Fake delivery fee requests": [
        "Check your parcel tracking exclusively within the Amazon app under 'Your Orders'.",
        "Amazon delivery partners will not ask for payments via third-party web links to release parcels.",
        "Avoid paying unknown fees to unverified courier links.",
    ],
    "Fake product recalls": [
        "Verify product recalls directly via official communication on the Amazon Message Center at amazon.in.",
        "Do not click external links or provide financial details to claim recall compensation.",
    ],
}

DEFAULT_SAFE_ACTIONS = [
    "Verify any alerts or order issues directly through the official Amazon mobile app or at https://www.amazon.in.",
    "Do not click on unverified links or dial phone numbers sent in unsolicited messages.",
    "Never share OTPs, passwords, or UPI PINs with anyone.",
]

TRANSLATED_SAFE_ACTIONS: Dict[str, Dict[str, List[str]]] = {
    "hi": {
        "default": [
            "किसी भी अलर्ट या ऑर्डर की स्थिति केवल आधिकारिक अमेज़न ऐप या https://www.amazon.in पर जाकर जांचें।",
            "अज्ञात संदेशों में आए लिंक पर क्लिक न करें और दिए गए नंबरों पर कॉल न करें।",
            "अपना ओटीपी (OTP), पासवर्ड या यूपीआई पिन (UPI PIN) कभी किसी के साथ साझा न करें।",
        ],
        "otp": [
            "अपना ओटीपी या पिन कभी किसी को न बताएं। अमेज़न कभी भी आपका ओटीपी या यूपीआई पिन नहीं मांगता।",
            "यदि आपने अनजाने में विवरण साझा कर दिया है, तो तुरंत अपने बैंक खाते या कार्ड को ब्लॉक करें।",
        ],
        "remote": [
            "किसी भी कॉलर या संदेश के कहने पर AnyDesk या TeamViewer जैसे रिमोट एक्सेस ऐप इंस्टॉल न करें।",
            "अमेज़न कभी भी स्क्रीन शेयर करने या रिमोट ऐप डाउनलोड करने को नहीं कहता।",
        ],
    },
    "te": {
        "default": [
            "ఆర్డర్ లేదా ఖాతా వివరాలను అధికారిక అమెజాన్ యాప్ లేదా https://www.amazon.in ద్వారా మాత్రమే తనిఖీ చేయండి.",
            "తెలియని సందేశాలలో ఉన్న లింక్‌లను క్లిక్ చేయవద్దు మరియు అపరిచిత నంబర్లకు కాల్ చేయవద్దు.",
            "మీ ఓటీపీ (OTP), పాస్‌వర్డ్ లేదా యూపీఐ పిన్ (UPI PIN) ఎవరితోనూ పంచుకోవద్దు.",
        ],
        "otp": [
            "మీ ఓటీపీ లేదా పిన్ నంబర్‌ను ఎవరికీ చెప్పవద్దు. అమెజాన్ ఎప్పుడూ ఓటీపీని అడగదు.",
            "ఒకవేళ పొరపాటున వివరాలు ఇచ్చి ఉంటే, వెంటనే మీ బ్యాంకుకు కాల్ చేసి కార్డును బ్లాక్ చేయండి.",
        ],
        "remote": [
            "AnyDesk లేదా TeamViewer వంటి స్క్రీన్ షేరింగ్ యాప్‌లను ఎట్టి పరిస్థితుల్లోనూ ఇన్‌స్టాల్ చేయవద్దు.",
            "అమెజాన్ కస్టమర్ కేర్ ఎప్పుడూ రిమోట్ యాప్స్ డౌన్‌లోడ్ చేయమని కోరదు.",
        ],
    },
}


def _extract_hostname(raw_url: str) -> str:
    """Return the bare hostname (lower-cased, no port) from a raw URL string.

    Handles the common case where the URL regex captures a leading ``www.``
    prefix without a scheme.  Trailing punctuation that slipped past the URL
    regex (e.g. a closing parenthesis or period) is stripped first.
    """
    raw_url = raw_url.strip().rstrip(".,;:)>]'\"").rstrip()
    # Ensure there is a scheme so urlparse works correctly.
    if not re.match(r"(?i)^https?://", raw_url):
        raw_url = "http://" + raw_url
    try:
        hostname = urlparse(raw_url).hostname or ""
    except Exception:
        hostname = ""
    return hostname.lower()


def _is_official_amazon_domain(hostname: str) -> bool:
    """Return True only when *hostname* is an exact official Amazon domain or a
    legitimate subdomain of one.

    Examples
    --------
    >>> _is_official_amazon_domain("amazon.in")           # True
    >>> _is_official_amazon_domain("www.amazon.in")       # True  (subdomain)
    >>> _is_official_amazon_domain("amazon.in.fake.com")  # False (not a subdomain)
    >>> _is_official_amazon_domain("fake-amazon.in")      # False (different domain)
    """
    for official in OFFICIAL_AMAZON_DOMAINS:
        if hostname == official or hostname.endswith("." + official):
            return True
    return False


def _evaluate_links(text: str) -> Tuple[int, List[str]]:
    """Evaluates links present in *text* for URL shorteners and non-official domains.

    Scoring
    -------
    - URL shortener detected                 → +35 points
    - External / unverified link (non-Amazon,
      not already caught as a shortener)     → +15 points  (neutral signal)

    Note: an official Amazon domain in the URL does *not* clear suspicion from
    other triggered rules (e.g. OTP requests or prize draw claims).
    """
    score = 0
    flags = []
    shortener_found = bool(SHORTENER_PATTERN.search(text))

    if shortener_found:
        score += 35
        flags.append("Contains shortened or masking URL (often used to obscure malicious links)")

    # Examine every URL for hostname legitimacy.
    urls = URL_PATTERN.findall(text)
    external_urls_flagged = False
    for raw_url in urls:
        # Skip shortener URLs — already flagged above.
        if SHORTENER_PATTERN.match(raw_url.strip()):
            continue
        hostname = _extract_hostname(raw_url)
        if not hostname:
            continue
        if _is_official_amazon_domain(hostname):
            # Legitimate Amazon URL — no link-score penalty.  Other rules
            # (OTP theft, prize draw, urgency) still apply independently.
            continue
        # Non-Amazon, non-shortener external link — flag once.
        if not external_urls_flagged and not shortener_found:
            score += 15
            flags.append(
                f"Contains an external or unverified link (not an official Amazon domain): {raw_url}"
            )
            external_urls_flagged = True

    return score, flags


def analyze_message(message: str, language: str = "en") -> Dict[str, Any]:
    """
    Analyze an incoming text message for signs of Amazon impersonation scams.

    Parameters
    ----------
    message : str
        The raw text message to analyze. Treated strictly as untrusted data.
    language : str, optional
        Target language code: 'en' (English), 'hi' (Hindi), or 'te' (Telugu). Default is 'en'.

    Returns
    -------
    dict
        {
            "risk_score": int (0 to 100),
            "verdict": "low" | "medium" | "high" | "critical",
            "category": str,
            "red_flags": list[str],
            "safe_actions": list[str],
            "language": str
        }

    Raises
    ------
    ValueError
        If message is empty or whitespace-only, or if language is unsupported.
    """
    # 1. Input validation
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message cannot be empty or whitespace-only.")

    lang_code = language.strip().lower() if isinstance(language, str) else ""
    if lang_code not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"Unsupported language code '{language}'. Supported codes are: {', '.join(sorted(SUPPORTED_LANGUAGES))}."
        )

    # 2. Pattern Matching & Scoring
    total_score = 0
    matched_rules = set()
    red_flags: List[str] = []
    category_scores: Dict[str, int] = {}

    # Category-specific evaluations
    for category_name, rules in CATEGORY_RULES.items():
        for rule_id, points, description, patterns in rules:
            if rule_id in matched_rules:
                continue

            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    matched_rules.add(rule_id)
                    total_score += points
                    red_flags.append(description)
                    category_scores[category_name] = (
                        category_scores.get(category_name, 0) + points
                    )
                    break

    # Cross-cutting indicators
    for rule_id, points, description, patterns in CROSS_CUTTING_INDICATORS:
        if rule_id in matched_rules:
            continue

        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                matched_rules.add(rule_id)
                total_score += points
                red_flags.append(description)
                break

    # Suspicious URLs / Shorteners
    link_score, link_flags = _evaluate_links(message)
    if link_score > 0:
        total_score += link_score
        red_flags.extend(link_flags)

    # Cap score at 100
    risk_score = min(total_score, 100)

    # 3. Determine Verdict based on score ranges:
    # 0–24: low, 25–49: medium, 50–74: high, 75–100: critical
    if risk_score >= 75:
        verdict = "critical"
    elif risk_score >= 50:
        verdict = "high"
    elif risk_score >= 25:
        verdict = "medium"
    else:
        verdict = "low"

    # 4. Determine Primary Category
    if category_scores:
        primary_category = max(category_scores.items(), key=lambda x: x[1])[0]
    elif risk_score > 0:
        primary_category = "General Suspicious Communication"
    else:
        primary_category = "No Scam Detected"

    # 5. Populate Safe Actions tailored to category and language
    safe_actions: List[str] = []
    if lang_code == "hi":
        if "OTP_PIN_CVV_THEFT" in matched_rules:
            safe_actions = TRANSLATED_SAFE_ACTIONS["hi"]["otp"]
        elif "REMOTE_APP" in matched_rules or "REMOTE_ACCESS_PHRASE" in matched_rules:
            safe_actions = TRANSLATED_SAFE_ACTIONS["hi"]["remote"]
        else:
            safe_actions = TRANSLATED_SAFE_ACTIONS["hi"]["default"]
    elif lang_code == "te":
        if "OTP_PIN_CVV_THEFT" in matched_rules:
            safe_actions = TRANSLATED_SAFE_ACTIONS["te"]["otp"]
        elif "REMOTE_APP" in matched_rules or "REMOTE_ACCESS_PHRASE" in matched_rules:
            safe_actions = TRANSLATED_SAFE_ACTIONS["te"]["remote"]
        else:
            safe_actions = TRANSLATED_SAFE_ACTIONS["te"]["default"]
    else:
        # Default English
        safe_actions = SAFE_ACTIONS_BY_CATEGORY.get(
            primary_category, DEFAULT_SAFE_ACTIONS
        )

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "category": primary_category,
        "red_flags": red_flags,
        "safe_actions": safe_actions,
        "language": lang_code,
    }
