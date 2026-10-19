"""
app.mcp_server
~~~~~~~~~~~~~~

Model Context Protocol (MCP) server for Scam Shield.
Exposes the `analyze_scam_message` tool over Streamable HTTP transport
using the official Python MCP SDK (mcp 2.x).

Compatible with MCP specification version 2025-11-25 / 2026-07-28+.
Runs independently on port 8001 by default, preserving the existing FastAPI application on port 8000.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field

# Ensure scam-shield project root is always in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp.server.mcpserver import MCPServer
from app.detector import analyze_message, SUPPORTED_LANGUAGES
from app.translations import get_translation
from app.ai_analyzer import analyze_with_ai

logger = logging.getLogger("scam_shield.mcp_server")

# Initialize the MCP Server with metadata
mcp_server = MCPServer(
    name="scam-shield-mcp",
    title="Scam Shield Security Server",
    description="Multilingual scam analysis tool protecting consumers from fraudulent messages impersonating Amazon.",
    version="1.0.0",
)


class ScamAnalysisResult(BaseModel):
    """Structured response model for analyze_scam_message."""
    risk_score: int = Field(..., description="Overall evaluated scam risk score from 0 to 100.")
    verdict: str = Field(..., description="Risk verdict assessment ('low', 'medium', 'high', 'critical').")
    category: str = Field(..., description="Identified scam category or 'No Scam Detected'.")
    red_flags: List[str] = Field(..., description="List of suspicious red flags detected in the message.")
    safe_actions: List[str] = Field(..., description="Actionable protective advice for the user.")
    language: str = Field(..., description="Language code used for detection ('en', 'hi', or 'te').")
    localized_verdict: Optional[str] = Field(None, description="Verdict translated to user's selected language.")
    localized_safety_advice: Optional[str] = Field(None, description="General safety guidance in selected language.")
    ai_explanation: Optional[str] = Field(None, description="Contextual analysis from Google Gemini or safe diagnostic.")
    analysis_mode: str = Field(..., description="Detection mode: 'ai_enhanced' or 'rule_based'.")


@mcp_server.tool(
    name="analyze_scam_message",
    description="Analyze a suspicious SMS, WhatsApp, or email message for Amazon impersonation, phishing links, and social engineering indicators across English, Hindi, and Telugu.",
)
def analyze_scam_message(
    message: str,
    language: Literal["en", "hi", "te"] = "en",
) -> Dict[str, Any]:
    """
    Evaluates an untrusted message for fraudulent Amazon impersonation signals.

    Parameters
    ----------
    message : str
        The raw text of the incoming message to inspect.
    language : str, optional
        Target language code for detection and guidance ('en', 'hi', 'te'). Defaults to 'en'.

    Returns
    -------
    dict
        Structured scam assessment including risk score, verdict, red flags, safe actions, and AI explanation.
    """
    # 1. Input Validation
    if not isinstance(message, str) or not message.strip():
        return {
            "error": "Invalid input: 'message' must be a non-empty string.",
            "risk_score": 0,
            "verdict": "unknown",
            "category": "Error",
            "red_flags": [],
            "safe_actions": [],
            "language": language if language in SUPPORTED_LANGUAGES else "en",
            "analysis_mode": "error",
            "ai_explanation": "Validation failed: message cannot be empty or whitespace-only.",
        }

    lang = str(language).lower().strip() if language else "en"
    if lang not in SUPPORTED_LANGUAGES:
        return {
            "error": f"Invalid language '{language}'. Supported languages: {sorted(list(SUPPORTED_LANGUAGES))}.",
            "risk_score": 0,
            "verdict": "unknown",
            "category": "Error",
            "red_flags": [],
            "safe_actions": [],
            "language": "en",
            "analysis_mode": "error",
            "ai_explanation": f"Unsupported language requested. Please use one of: {sorted(list(SUPPORTED_LANGUAGES))}.",
        }

    # 2. Rule-based evaluation
    try:
        rule_result = analyze_message(message=message.strip(), language=lang)
    except Exception as exc:
        logger.error("Rule-based detection error: %s", exc)
        return {
            "error": "Internal analysis error occurred.",
            "risk_score": 0,
            "verdict": "unknown",
            "category": "Error",
            "red_flags": [],
            "safe_actions": [],
            "language": lang,
            "analysis_mode": "error",
            "ai_explanation": "Error occurred during message evaluation.",
        }

    # 3. Augment with AI analysis (Gemini) when available
    ai_result, ai_diagnostic = analyze_with_ai(message=message.strip(), language=lang)

    if ai_result:
        analysis_mode = "ai_enhanced"
        final_risk_score = max(rule_result["risk_score"], ai_result["risk_score"])
        ai_explanation = ai_result.get("ai_explanation")

        if rule_result["category"] != "No Scam Detected" and rule_result["category"] != "General Suspicious Communication":
            final_category = rule_result["category"]
        else:
            final_category = ai_result.get("category", rule_result["category"])

        if final_risk_score >= 75:
            final_verdict = "critical"
        elif final_risk_score >= 50:
            final_verdict = "high"
        elif final_risk_score >= 25:
            final_verdict = "medium"
        else:
            final_verdict = "low"

        combined_red_flags: List[str] = list(rule_result["red_flags"])
        for flag in ai_result.get("red_flags", []):
            if flag and flag not in combined_red_flags:
                combined_red_flags.append(flag)

        combined_safe_actions: List[str] = list(rule_result["safe_actions"])
        for action in ai_result.get("safe_actions", []):
            if action and action not in combined_safe_actions:
                combined_safe_actions.append(action)

        final_red_flags = combined_red_flags
        final_safe_actions = combined_safe_actions
    else:
        # Fallback to pure rule-based detector with safe diagnostic explanation
        analysis_mode = "rule_based"
        final_risk_score = rule_result["risk_score"]
        final_verdict = rule_result["verdict"]
        final_category = rule_result["category"]
        final_red_flags = rule_result["red_flags"]
        final_safe_actions = rule_result["safe_actions"]
        ai_explanation = ai_diagnostic or "AI analysis unavailable; evaluated using rule-based detector."

    # 4. Localized translations
    try:
        localized_verdict = get_translation(key=final_verdict, language=lang)
    except (KeyError, ValueError):
        localized_verdict = None

    try:
        localized_safety_advice = get_translation(key="general_safety_advice", language=lang)
    except (KeyError, ValueError):
        localized_safety_advice = None

    return {
        "risk_score": final_risk_score,
        "verdict": final_verdict,
        "category": final_category,
        "red_flags": final_red_flags,
        "safe_actions": final_safe_actions,
        "language": rule_result["language"],
        "localized_verdict": localized_verdict,
        "localized_safety_advice": localized_safety_advice,
        "ai_explanation": ai_explanation,
        "analysis_mode": analysis_mode,
    }


def run_server(host: str = "127.0.0.1", port: int = 8001, path: str = "/mcp"):
    """
    Starts the Scam Shield MCP server using Streamable HTTP transport.
    Endpoint will be available at http://{host}:{port}{path} (default: http://127.0.0.1:8001/mcp).
    """
    print(f"Starting Scam Shield MCP Server (Streamable HTTP) on http://{host}:{port}{path}")
    mcp_server.run(
        transport="streamable-http",
        host=host,
        port=port,
        streamable_http_path=path,
    )


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8001
    path = "/mcp"

    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])

    run_server(host=host, port=port, path=path)
