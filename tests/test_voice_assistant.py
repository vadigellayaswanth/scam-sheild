"""
tests.test_voice_assistant
~~~~~~~~~~~~~~~~~~~~~~~~~~

Unit test suite for the Scam Shield Voice Assistant & Automatic Link Detection:
- Conversational greetings ("Hi", "Hello", "Hey")
- Empathetic responses for boredom, sadness, and everyday questions
- Automatic URL detection and security analysis from conversational messages
- Spoken text generation (clean text for browser speech synthesis)
- Multi-language support (English, Hindi, Telugu)
- FastAPI /chat and /analyze-url endpoint tests
- MCP server analyze_scam_url tool invocation
"""

import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from app.assistant import chat_with_assistant, _generate_fallback_response
from app.mcp_server import analyze_scam_url_mcp, analyze_scam_message
from app.main import app


class TestVoiceAssistantConversation(unittest.TestCase):
    """Tests for conversational assistant engine."""

    def test_friendly_greeting_english(self):
        res = chat_with_assistant("Hi there!", language="en")
        self.assertTrue(any(w in res["reply"].lower() for w in ["hey", "hello", "hi", "how are you"]))
        self.assertTrue(len(res["speech_text"]) > 0)
        self.assertEqual(res["language"], "en")

    def test_friendly_greeting_hindi(self):
        res = chat_with_assistant("Hello", language="hi")
        self.assertTrue("नमस्ते" in res["reply"] or "मदद" in res["reply"])
        self.assertEqual(res["language"], "hi")

    def test_friendly_greeting_telugu(self):
        res = chat_with_assistant("Hey", language="te")
        self.assertTrue("హలో" in res["reply"] or "నమస్కారం" in res["reply"])
        self.assertEqual(res["language"], "te")

    def test_boredom_empathy(self):
        res = chat_with_assistant("I'm bored today.", language="en")
        self.assertTrue(any(w in res["reply"].lower() for w in ["bored", "chat", "challenge", "fun", "learn", "trivia"]))

    def test_scam_inquiry_intent(self):
        res = chat_with_assistant("Can you check a suspicious message for me?", language="en")
        self.assertTrue(any(w in res["reply"].lower() for w in ["share", "message", "check", "inspect", "help", "sure"]))

    def test_automatic_url_detection_and_analysis(self):
        # User asks assistant about a phishing link
        msg = "Hey, is this link safe? http://amaz0n-security-update.in/kyc-verify"
        res = chat_with_assistant(msg, language="en", auto_analyze_links=True)

        self.assertEqual(len(res["urls_detected"]), 1)
        url_info = res["urls_detected"][0]
        self.assertEqual(url_info["domain"], "amaz0n-security-update.in")
        self.assertGreaterEqual(url_info["risk_score"], 75)
        self.assertEqual(url_info["verdict"], "critical")
        self.assertGreaterEqual(res["overall_risk_score"], 75)
        self.assertEqual(res["overall_verdict"], "critical")
        # Explanation should mention the domain or warn about risk
        self.assertTrue(
            "amaz0n-security-update.in" in res["reply"].lower()
            or "lookalike" in res["reply"].lower()
            or "fake" in res["reply"].lower()
        )
        self.assertTrue(
            any(w in res["speech_text"].lower() for w in ["warning", "not safe", "scam", "do not click", "dangerous", "risk", "details"])
        )

    def test_speech_text_is_clean_of_markdown(self):
        msg = "Hi! Check http://bit.ly/test-link"
        res = chat_with_assistant(msg, language="en")
        # Speech text should not contain markdown asterisks or raw http links
        self.assertNotIn("**", res["speech_text"])
        self.assertNotIn("http://", res["speech_text"])


class TestMCPServerTools(unittest.TestCase):
    """Tests for MCP server tools: analyze_scam_message and analyze_scam_url."""

    def test_analyze_scam_url_tool_success(self):
        res = analyze_scam_url_mcp(
            url="https://amazon.in/dp/B08N5WRWNW",
            check_live=False,
            language="en",
        )
        self.assertEqual(res["domain"], "amazon.in")
        self.assertEqual(res["verdict"], "low")
        self.assertEqual(res["risk_score"], 0)

    def test_analyze_scam_url_tool_empty_validation(self):
        res = analyze_scam_url_mcp(url="")
        self.assertIn("error", res)
        self.assertEqual(res["verdict"], "unknown")

    def test_existing_analyze_scam_message_still_works(self):
        res = analyze_scam_message(
            message="Amazon alert: Your account is blocked. Call customer support immediately.",
            language="en",
        )
        self.assertIn("risk_score", res)
        self.assertIn("verdict", res)
        self.assertGreaterEqual(res["risk_score"], 50)


class TestFastAPINewEndpoints(unittest.TestCase):
    """Tests for FastAPI /chat and /analyze-url endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_post_chat_greeting(self):
        resp = self.client.post("/chat", json={"message": "Hello!", "language": "en"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("reply", data)
        self.assertIn("speech_text", data)
        self.assertEqual(data["language"], "en")

    def test_post_chat_with_link(self):
        resp = self.client.post(
            "/chat",
            json={
                "message": "Hey is this link safe: http://amaz0n-verify.xyz/login",
                "language": "en",
                "auto_analyze_links": True,
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["urls_detected"]), 1)
        self.assertEqual(data["overall_verdict"], "critical")

    def test_post_analyze_url_endpoint(self):
        resp = self.client.post(
            "/analyze-url",
            json={"url": "https://amazon.in/help", "check_live": False, "language": "en"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["domain"], "amazon.in")
        self.assertEqual(data["verdict"], "low")

    def test_empty_message_validation(self):
        resp = self.client.post("/chat", json={"message": "   ", "language": "en"})
        self.assertEqual(resp.status_code, 422)
