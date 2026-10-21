"""
app.assistant
~~~~~~~~~~~~~

Interactive, conversational AI Voice Assistant engine for Scam Shield.
Acts as a friendly conversational companion that answers everyday questions,
supports English, Hindi, and Telugu, and automatically detects, inspects,
and explains suspicious links and scam messages.

Key Capabilities:
- Warm, empathetic conversational demeanor.
- Conversational session context memory.
- Automatic scam link detection and analysis.
- Multi-language synthesis (English, Hindi, Telugu).
- Generates both full rich markdown reply and a concise `speech_text` for Text-to-Speech.
- Reliable fallback when Gemini AI is busy, offline, or unconfigured.
"""

import re
import os
import json
import logging
from typing import List, Dict, Any, Optional, Tuple

from app.ai_analyzer import get_gemini_client, get_model_name
from app.url_analyzer import extract_urls, analyze_scam_url
from app.detector import analyze_message

logger = logging.getLogger("scam_shield.assistant")

ASSISTANT_SYSTEM_PROMPT = """You are the 'Scam Shield Voice Assistant', a friendly, warm, and helpful AI companion that also protects users in India from cyber scams, phishing, and fraudulent messages impersonating Amazon in English, Hindi, and Telugu.

CORE PERSONALITY & TONE:
1. Be warm, empathetic, and engaging. When greeted ("Hi", "Hello", "Hey"), respond warmly with a friendly greeting like "Hey! 😊 How are you doing today?".
2. If the user is bored, offer fun ideas (like a quick cybersecurity quiz, interesting tech trivia, or a friendly chat).
3. If the user expresses sadness or frustration, respond with genuine warmth and empathy.
4. You are an AI assistant: never pretend to be a human, and do not invent physical human experiences you do not have.
5. Explain technical security concepts in simple, plain, easy-to-understand language.
6. Support the user's preferred language seamlessly (English, Hindi, or Telugu). If the user writes in Hindi or Telugu, respond in that language or appropriate transliteration.

AUTOMATIC LINK & SCAM ANALYSIS RESPONSIBILITIES:
- If security analysis data for links or scam messages is provided to you in the prompt context, synthesize the findings naturally into your response.
- Highlight specific red flags clearly (e.g. shortened links, brand lookalikes, OTP solicitation, fake KYC).
- For suspicious links, explicitly advise the user NEVER to enter passwords, OTPs, or payment details.
- For inconclusive results, clearly explain that safety cannot be guaranteed and advise caution.
- Keep responses conversational, helpful, and reassuring.
"""


def _generate_fallback_response(
    user_message: str,
    language: str,
    url_results: List[Dict[str, Any]],
    scam_result: Optional[Dict[str, Any]],
) -> Tuple[str, str]:
    """
    Intelligent, empathetic offline fallback response when Gemini AI is unavailable or rate-limited.
    Returns: (rich_markdown_reply, concise_speech_text)
    """
    msg_lower = user_message.strip().lower()
    lang = language.lower() if language in {"en", "hi", "te"} else "en"

    # 1. URL Analysis Found
    if url_results:
        top_url = url_results[0]
        score = top_url["risk_score"]
        verdict = top_url["verdict"].upper()
        domain = top_url["domain"]

        if lang == "hi":
            if score >= 50:
                text = f"मैंने इस लिंक ({domain}) की जांच की है। 🚨 **सावधान!** यह लिंक उच्च जोखिम ({verdict}, जोखिम स्कोर: {score}/100) दिखाता है। इस पर अपना पासवर्ड, बैंक विवरण या OTP कभी दर्ज न करें।"
                speech = f"सावधान! मैंने लिंक की जांच की है। यह उच्च जोखिम दिखाता है। इस पर कोई भी गोपनीय विवरण दर्ज न करें।"
            else:
                text = f"मैंने लिंक ({domain}) की जांच की। इसका जोखिम स्तर कम प्रतीत होता है ({verdict}), लेकिन किसी भी अनजान वेबसाइट पर लेन-देन करते समय हमेशा सतर्क रहें।"
                speech = f"मैंने लिंक की जांच कर ली है। जोखिम स्तर कम है, लेकिन हमेशा सतर्क रहें।"
        elif lang == "te":
            if score >= 50:
                text = f"నేను ఈ లింక్ ({domain}) ను పరిశీలించాను. 🚨 **హెచ్చరిక!** ఇది ప్రమాదకరంగా కనిపిస్తోంది ({verdict}, రిస్క్ స్కోర్: {score}/100). మీ ఓటీపీ లేదా బ్యాంక్ వివరాలను ఎట్టి పరిస్థితుల్లోనూ పంచుకోవద్దు."
                speech = f"హెచ్చరిక! ఈ లింక్ అధిక ప్రమాదకరంగా ఉంది. మీ వివరాలను ఎవరికీ ఇవ్వవద్దు."
            else:
                text = f"నేను లింక్ ({domain}) పరిశీలించాను. ప్రస్తుతం తక్కువ ప్రమాదం ({verdict}) అనిపిస్తోంది, అయినా అపరిచిత లింక్స్‌తో జాగ్రత్తగా ఉండండి."
                speech = f"లింక్ తనిఖీ పూర్తయింది. తక్కువ ప్రమాదం అని తేలింది, అయినా జాగ్రత్తగా ఉండండి."
        else:
            if score >= 50:
                text = f"I checked the link for you! 🚨 **Warning:** The link `{domain}` shows high risk signals (**{verdict}**, Risk Score: **{score}/100**).\n\n"
                if top_url.get("red_flags"):
                    text += "**Red Flags Detected:**\n" + "\n".join(f"- {f}" for f in top_url["red_flags"][:3]) + "\n\n"
                text += "**Advice:** Please do not enter your password, OTP, or card details on this website."
                speech = f"Warning! I analyzed the link for {domain}. It shows high risk scam signals. Do not enter any passwords or OTPs."
            else:
                text = f"I analyzed the link `{domain}` for you. The risk score is low (**{score}/100**), but always make sure to verify official Amazon orders directly through the Amazon app."
                speech = f"I checked the link for {domain}. It appears low risk, but always verify orders inside the official Amazon app."
        return text, speech

    # 2. Greetings
    if re.search(r"\b(hi|hello|hey|namaste|vanakkam|namaskaram|greetings)\b", msg_lower):
        if lang == "hi":
            return "नमस्ते! 😊 मैं स्कैम शील्ड वॉइस असिस्टेंट हूँ। आप आज कैसे हैं? क्या आपको किसी संदिग्ध संदेश या लिंक की जांच करनी है?", "नमस्ते! आप आज कैसे हैं? मैं आपकी कैसे मदद कर सकता हूँ?"
        elif lang == "te":
            return "హలో! నమస్కారం! 😊 నేను స్కామ్ షీల్డ్ వాయిస్ అసిస్టెంట్‌ని. మీరు ఎలా ఉన్నారు? ఏదైనా అనుమానాస్పద మెసేజ్ లేదా లింక్ తనిఖీ చేయాలా?", "హలో! నమస్కారం! మీరు ఎలా ఉన్నారు? నేను మీకు ఎలా సహాయపడగలను?"
        else:
            return "Hey! 😊 How are you doing today? I'm your Scam Shield assistant—feel free to chat, ask questions, or share any suspicious messages or links you want me to inspect!", "Hey! How are you doing today? Let me know how I can help!"

    # 3. Emotions (bored, sad, frustrated)
    if "bored" in msg_lower or "boring" in msg_lower:
        if lang == "hi":
            return "बोर हो रहे हैं? 😊 क्या आप साइबर सुरक्षा के बारे में कुछ नया जानना चाहते हैं, कोई त्वरित प्रश्नोत्तरी खेलना चाहते हैं या बस थोड़ी बातचीत करना चाहते हैं?", "बोर हो रहे हैं? चलिए कुछ दिलचस्प बात करते हैं या कुछ नया सीखते हैं!"
        elif lang == "te":
            return "బోరింగ్‌గా ఉందా? 😊 కొద్దిసేపు సరదాగా మాట్లాడుకుందామా, లేదా సైబర్ సెక్యూరిటీ గురించి ఏదైనా ఆసక్తికరమైన విషయం నేర్చుకుందామా?", "బోరింగ్‌గా ఉందా? రండి ఏదైనా ఆసక్తికరమైన విషయం గురించి మాట్లాడుకుందాం!"
        else:
            return "Feeling bored? 😊 Want to chat for a bit, test your scam-detection instincts with a quick challenge, or learn some cool tech security trivia?", "Feeling bored? Want to chat for a bit or try a quick scam-detection challenge?"

    if any(w in msg_lower for w in ["sad", "unhappy", "upset", "depressed", "frustrated"]):
        if lang == "hi":
            return "मुझे सुनकर दुख हुआ। कभी-कभी दिन कठिन हो सकते हैं। मैं यहाँ आपके साथ हूँ, अगर आप किसी चीज़ के बारे में बात करना चाहते हैं।", "मुझे सुनकर दुख हुआ। मैं यहाँ आपकी मदद के लिए उपस्थित हूँ।"
        elif lang == "te":
            return "మీరు బాధపడుతున్నారని విని చింతిస్తున్నాను. కొన్నిసార్లు రోజులు కష్టంగా ఉండవచ్చు. నేను మీకు తోడుగా ఉన్నాను.", "మీరు బాధపడుతున్నారని తెలిసి చింతిస్తున్నాను. నేను మీకు సహాయం చేయడానికి ఇక్కడే ఉన్నాను."
        else:
            return "I'm really sorry you're feeling down. Days can get overwhelming sometimes. I'm right here with you if you'd like to talk or take your mind off things.", "I'm really sorry you're feeling down. I'm right here with you if you want to chat."

    # 4. Scam check questions
    if any(w in msg_lower for w in ["check", "scam", "suspicious", "fake", "phishing", "fraud", "is this real"]):
        return (
            "Of course! Share the message text or paste the link right here, and I will thoroughly inspect it for scam red flags, lookalike domains, and social engineering tricks.",
            "Of course! Share the message or link, and I will check it for scam warning signs right away.",
        )

    # 5. General inquiries
    if lang == "hi":
        return f"मैं समझ गया: \"{user_message}\"। मैं आपकी सुरक्षा और सहायता के लिए यहाँ हूँ। क्या आप चाहते हैं कि मैं किसी लिंक, संदेश या अमेज़न अलर्ट की जांच करूँ?", "मैं समझ गया। क्या आप चाहते हैं कि मैं किसी लिंक या संदेश की जांच करूँ?"
    elif lang == "te":
        return f"నాకు అర్థమైంది: \"{user_message}\". నేను మీకు సహాయం చేయడానికి సిద్ధంగా ఉన్నాను. ఏదైనా మెసేజ్ లేదా లింక్ తనిఖీ చేయాలా?", "నాకు అర్థమైంది. ఏదైనా సందేశం లేదా లింక్ తనిఖీ చేయాలా?"
    else:
        return (
            f"I hear you! You asked about: \"{user_message}\". I'm here to chat, answer questions, or inspect any suspicious message or link you've received. Let me know what you'd like to explore next!",
            f"I hear you! Let me know if you would like me to inspect any suspicious message or link.",
        )


def chat_with_assistant(
    message: str,
    language: str = "en",
    history: Optional[List[Dict[str, str]]] = None,
    auto_analyze_links: bool = True,
) -> Dict[str, Any]:
    """
    Core handler for conversational Voice Assistant interactions.

    Parameters:
    - message: Raw user message (typed or spoken).
    - language: 'en', 'hi', or 'te'.
    - history: Optional list of previous turns [{"role": "user"|"assistant", "content": "..."}].
    - auto_analyze_links: Automatically extracts and inspects all URLs present.

    Returns structured assistant response dictionary.
    """
    lang = language.lower().strip() if language in {"en", "hi", "te"} else "en"
    clean_msg = message.strip() if isinstance(message, str) else ""

    # 1. Automatic URL Detection and Inspection
    extracted_urls = extract_urls(clean_msg) if auto_analyze_links else []
    url_results: List[Dict[str, Any]] = []

    for u in extracted_urls:
        try:
            # Run live SSRF-protected check, threat intel, and contextual heuristics
            res = analyze_scam_url(url=u, check_live=True, language=lang, surrounding_message=clean_msg)
            url_results.append(res)
        except Exception as e:
            logger.warning("Error analyzing URL %s: %s", u, e)

    # 2. Run Scam Message Heuristics if text looks like a potential scam notice
    scam_result = None
    if len(clean_msg) > 15:
        try:
            scam_result = analyze_message(clean_msg, language=lang)
        except Exception:
            scam_result = None

    # Calculate overall risk score across message and detected URLs
    max_risk_score = 0
    if scam_result:
        max_risk_score = max(max_risk_score, scam_result.get("risk_score", 0))
    for u_res in url_results:
        max_risk_score = max(max_risk_score, u_res.get("risk_score", 0))

    if max_risk_score >= 75:
        overall_verdict = "critical"
    elif max_risk_score >= 50:
        overall_verdict = "high"
    elif max_risk_score >= 25:
        overall_verdict = "medium"
    else:
        overall_verdict = "low"

    # 3. Attempt Gemini Conversational AI with XML and context isolation
    client, _ = get_gemini_client()
    reply_text = None
    speech_text = None

    if client:
        try:
            from google.genai import types

            # Build contextual system instruction with security data if available
            context_snippet = ""
            if url_results:
                context_snippet += "\n[SECURITY ENGINE URL SCAN RESULTS]:\n"
                for idx, ur in enumerate(url_results, 1):
                    context_snippet += (
                        f"URL #{idx}: {ur['url']}\n"
                        f"Domain: {ur['domain']}\n"
                        f"Risk Score: {ur['risk_score']}/100 ({ur['verdict'].upper()})\n"
                        f"Category: {ur['category']}\n"
                        f"Availability: {ur['availability']}\n"
                        f"Red Flags: {', '.join(ur.get('red_flags', []))}\n"
                        f"Safe Actions: {', '.join(ur.get('safe_actions', []))}\n"
                    )

            if scam_result and scam_result.get("risk_score", 0) > 20:
                context_snippet += (
                    f"\n[SECURITY ENGINE MESSAGE SCAN RESULT]:\n"
                    f"Message Risk: {scam_result['risk_score']}/100 ({scam_result['verdict'].upper()})\n"
                    f"Category: {scam_result['category']}\n"
                    f"Red Flags: {', '.join(scam_result.get('red_flags', []))}\n"
                )

            # Format conversation history
            conv_prompt = ""
            if history:
                conv_prompt += "Previous conversation context:\n"
                for turn in history[-4:]:  # Keep recent 4 turns
                    role = "User" if turn.get("role") == "user" else "Assistant"
                    conv_prompt += f"{role}: {turn.get('content', '')}\n"
                conv_prompt += "\n"

            conv_prompt += f"User message to respond to:\n<user_message>\n{clean_msg}\n</user_message>\n"
            conv_prompt += f"Selected language: {lang}\n"
            if context_snippet:
                conv_prompt += f"{context_snippet}\n"

            conv_prompt += (
                "Please provide your response strictly as JSON with two fields:\n"
                "1. 'reply': Markdown formatted, warm, natural response addressing the user.\n"
                "2. 'speech_text': Short, natural conversational spoken summary (1-3 sentences) suitable for Text-to-Speech playback."
            )

            config = types.GenerateContentConfig(
                system_instruction=ASSISTANT_SYSTEM_PROMPT,
                temperature=0.7,
                response_mime_type="application/json",
            )

            response = client.models.generate_content(
                model=get_model_name(),
                contents=conv_prompt,
                config=config,
            )

            if response and response.text:
                parsed = json.loads(response.text)
                if isinstance(parsed, dict) and "reply" in parsed:
                    reply_text = str(parsed["reply"]).strip()
                    speech_text = str(parsed.get("speech_text", "")).strip() or reply_text

        except Exception as exc:
            logger.info("Gemini conversational generation unavailable (%s). Falling back gracefully.", exc)

    # 4. Fallback if Gemini failed or is unavailable
    if not reply_text:
        reply_text, speech_text = _generate_fallback_response(
            user_message=clean_msg,
            language=lang,
            url_results=url_results,
            scam_result=scam_result,
        )

    # Clean speech text from markdown symbols so speech synthesis sounds natural
    clean_speech = re.sub(r"[*_#`~\[\]<>]", "", speech_text or reply_text)
    clean_speech = re.sub(r"https?://\S+", "this link", clean_speech)

    return {
        "reply": reply_text,
        "speech_text": clean_speech,
        "language": lang,
        "urls_detected": url_results,
        "scam_message_analysis": scam_result,
        "overall_risk_score": max_risk_score,
        "overall_verdict": overall_verdict,
    }
