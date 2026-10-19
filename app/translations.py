"""
app.translations
~~~~~~~~~~~~~~~~

Provides consistent, offline multilingual translations for Scam Shield scam warnings
and defensive safety recommendations across English (en), Hindi (hi), and Telugu (te).
Keeps common technical and banking terms (such as OTP, PIN, CVV, UPI) clear and recognizable.
"""

from typing import Dict

SUPPORTED_LANGUAGES = {"en", "hi", "te"}

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        # Risk verdicts
        "low": "Low Risk: No prominent scam indicators were detected in this message.",
        "medium": "Medium Risk: This message contains potentially suspicious elements. Proceed with caution.",
        "high": "High Risk: Strong warning signals detected. This message likely impersonates Amazon.",
        "critical": "Critical Risk: High probability of a dangerous scam or credential theft attempt.",
        # Aliases for backwards compatibility
        "verdict_low": "Low Risk: No prominent scam indicators were detected in this message.",
        "verdict_medium": "Medium Risk: This message contains potentially suspicious elements. Proceed with caution.",
        "verdict_high": "High Risk: Strong warning signals detected. This message likely impersonates Amazon.",
        "verdict_critical": "Critical Risk: High probability of a dangerous scam or credential theft attempt.",
        # Safety recommendations
        "general_safety_advice": "Always stay vigilant with unsolicited messages claiming urgent action regarding orders or account status.",
        "never_share_credentials": "Never share your OTP, PIN, or CVV with anyone. Legitimate Amazon representatives will never ask for them.",
        "avoid_suspicious_links": "Avoid clicking on suspicious links or shortened URLs sent via SMS, email, or messaging apps.",
        "verify_official_channels": "Verify all messages, orders, and account alerts exclusively through the official Amazon mobile app or website (amazon.in).",
        "never_install_remote_apps": "Never install remote-access apps (such as AnyDesk or TeamViewer) at a stranger's or caller's request.",
        "report_suspicious_messages": "Report suspicious messages, phishing emails, or fraud attempts directly to Amazon customer support and cyber crime authorities.",
        "contact_bank_official": "If you have shared financial or banking details, immediately contact your bank through its official channels to freeze your account or block cards.",
    },
    "hi": {
        # Risk verdicts
        "low": "कम जोखिम: इस संदेश में कोई स्पष्ट धोखाधड़ी के संकेत नहीं मिले हैं।",
        "medium": "मध्यम जोखिम: इस संदेश में कुछ संदिग्ध तत्व पाए गए हैं। सावधानी बरतें।",
        "high": "उच्च जोखिम: मजबूत चेतावनी संकेत मिले हैं। यह संदेश संभवतः अमेज़न का रूप धारण कर धोखाधड़ी का प्रयास है।",
        "critical": "गंभीर जोखिम: यह एक खतरनाक धोखाधड़ी या आपकी गोपनीय जानकारी चुराने का गंभीर प्रयास हो सकता है।",
        # Aliases for backwards compatibility
        "verdict_low": "कम जोखिम: इस संदेश में कोई स्पष्ट धोखाधड़ी के संकेत नहीं मिले हैं।",
        "verdict_medium": "मध्यम जोखिम: इस संदेश में कुछ संदिग्ध तत्व पाए गए हैं। सावधानी बरतें।",
        "verdict_high": "उच्च जोखिम: मजबूत चेतावनी संकेत मिले हैं। यह संदेश संभवतः अमेज़न का रूप धारण कर धोखाधड़ी का प्रयास है।",
        "verdict_critical": "गंभीर जोखिम: यह एक खतरनाक धोखाधड़ी या आपकी गोपनीय जानकारी चुराने का गंभीर प्रयास हो सकता है।",
        # Safety recommendations
        "general_safety_advice": "ऑर्डर या खाते की स्थिति को लेकर तुरंत कार्रवाई का दावा करने वाले किसी भी अनजान संदेश से हमेशा सावधान रहें।",
        "never_share_credentials": "अपना OTP, PIN या CVV कभी किसी के साथ साझा न करें। अमेज़न के असली प्रतिनिधि इन्हें कभी नहीं मांगते।",
        "avoid_suspicious_links": "संदेशों या सोशल मीडिया में आए किसी भी संदिग्ध लिंक या छोटे किए गए URL (shortened URLs) पर क्लिक न करें।",
        "verify_official_channels": "किसी भी संदेश, ऑर्डर या खाते के अलर्ट की पुष्टि केवल आधिकारिक अमेज़न ऐप या वेबसाइट (amazon.in) पर जाकर करें।",
        "never_install_remote_apps": "किसी भी अनजान व्यक्ति या कॉलर के कहने पर AnyDesk या TeamViewer जैसे रिमोट एक्सेस ऐप कभी इंस्टॉल न करें।",
        "report_suspicious_messages": "संदिग्ध संदेशों और धोखाधड़ी के प्रयासों की सूचना तुरंत अमेज़न ग्राहक सेवा और साइबर क्राइम सेल को दें।",
        "contact_bank_official": "यदि आपने कोई वित्तीय या बैंकिंग विवरण साझा कर दिया है, तो तुरंत अपने बैंक के आधिकारिक नंबर पर संपर्क करके अपने खाते या कार्ड को ब्लॉक कराएं।",
    },
    "te": {
        # Risk verdicts
        "low": "తక్కువ ప్రమాదం: ఈ సందేశంలో ఎటువంటి స్పష్టమైన మోసపూరిత సంకేతాలు కనిపించలేదు.",
        "medium": "మధ్యస్థ ప్రమాదం: ఈ సందేశంలో అనుమానాస్పద అంశాలు ఉన్నాయి. జాగ్రత్త వహించండి.",
        "high": "అధిక ప్రమాదం: బలమైన హెచ్చరిక సంకేతాలు గుర్తించబడ్డాయి. ఇది అమెజాన్ పేరుతో జరుగుతున్న మోసం కావచ్చు.",
        "critical": "తీవ్ర ప్రమాదం: ఇది ప్రమాదకరమైన మోసం లేదా మీ వ్యక్తిగత వివరాలను దొంగిలించే ప్రయత్నం అయ్యే అవకాశం ఉంది.",
        # Aliases for backwards compatibility
        "verdict_low": "తక్కువ ప్రమాదం: ఈ సందేశంలో ఎటువంటి స్పష్టమైన మోసపూరిత సంకేతాలు కనిపించలేదు.",
        "verdict_medium": "మధ్యస్థ ప్రమాదం: ఈ సందేశంలో అనుమానాస్పద అంశాలు ఉన్నాయి. జాగ్రత్త వహించండి.",
        "verdict_high": "అధిక ప్రమాదం: బలమైన హెచ్చరిక సంకేతాలు గుర్తించబడ్డాయి. ఇది అమెజాన్ పేరుతో జరుగుతున్న మోసం కావచ్చు.",
        "verdict_critical": "తీవ్ర ప్రమాదం: ఇది ప్రమాదకరమైన మోసం లేదా మీ వ్యక్తిగత వివరాలను దొంగిలించే ప్రయత్నం అయ్యే అవకాశం ఉంది.",
        # Safety recommendations
        "general_safety_advice": "ఆర్డర్లు లేదా ఖాతా స్థితికి సంబంధించి అత్యవసర చర్యలు కోరే అపరిచిత సందేశాల పట్ల ఎల్లప్పుడూ అప్రమత్తంగా ఉండండి.",
        "never_share_credentials": "మీ OTP, PIN లేదా CVV నంబర్లను ఎవరితోనూ పంచుకోవద్దు. నిజమైన అమెజాన్ ప్రతినిధులు వీటిని ఎప్పటికీ అడగరు.",
        "avoid_suspicious_links": "ఎస్ఎంఎస్ (SMS) లేదా మెసేజింగ్ యాప్‌లలో వచ్చే అనుమానాస్పద లింక్‌లు లేదా షార్ట్ లింక్‌లపై క్లిక్ చేయవద్దు.",
        "verify_official_channels": "ఏదైనా సందేశం లేదా ఆర్డర్ వివరాలను అధికారిక అమెజాన్ మొబైల్ యాప్ లేదా వెబ్‌సైట్ (amazon.in) ద్వారా మాత్రమే ధృవీకరించుకోండి.",
        "never_install_remote_apps": "ఎవరైనా అపరిచితులు లేదా కాలర్స్ చెప్పినప్పుడు AnyDesk లేదా TeamViewer వంటి రిమోట్ యాక్సెస్ యాప్‌లను ఎట్టి పరిస్థితుల్లోనూ ఇన్‌స్టాల్ చేయవద్దు.",
        "report_suspicious_messages": "అనుమానాస్పద సందేశాలు మరియు మోసపూరిత ప్రయత్నాల గురించి వెంటనే అమెజాన్ కస్టమర్ సపోర్ట్ మరియు సైబర్ క్రైమ్ విభాగానికి ఫిర్యాదు చేయండి.",
        "contact_bank_official": "ఒకవేళ మీరు బ్యాంకింగ్ లేదా ఆర్థిక వివరాలను పంచుకుంటే, వెంటనే మీ బ్యాంకును వారి అధికారిక మార్గాల ద్వారా సంప్రదించి ఖాతా లేదా కార్డులను బ్లాక్ చేయండి.",
    },
}


def get_translation(key: str, language: str = "en") -> str:
    """
    Retrieve translated text for a specified key and language.

    Parameters
    ----------
    key : str
        The translation key to look up (e.g. 'high', 'never_share_credentials').
    language : str, optional
        Language code: 'en' (English), 'hi' (Hindi), or 'te' (Telugu). Default is 'en'.

    Returns
    -------
    str
        The translated string in the requested language, or in English as fallback.

    Raises
    ------
    ValueError
        If the requested language is not supported.
    KeyError
        If the key does not exist in the requested language and cannot be found in English fallback.
    """
    if not isinstance(language, str):
        raise ValueError(f"Invalid language type: expected str, got {type(language).__name__}")

    lang_code = language.strip().lower()
    if lang_code not in SUPPORTED_LANGUAGES:
        raise ValueError(
            f"Unsupported language code '{language}'. Supported codes are: {', '.join(sorted(SUPPORTED_LANGUAGES))}."
        )

    # 1. Check if the key exists in the requested language
    lang_dict = TRANSLATIONS.get(lang_code, {})
    if key in lang_dict:
        return lang_dict[key]

    # 2. Fall back to English
    en_dict = TRANSLATIONS.get("en", {})
    if key in en_dict:
        return en_dict[key]

    # 3. Missing in both requested language and English fallback
    raise KeyError(f"Translation key '{key}' not found.")
