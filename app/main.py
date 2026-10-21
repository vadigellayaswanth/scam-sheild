"""
app.main
~~~~~~~~

FastAPI application for the Scam Shield project.
Provides HTTP API endpoints to check service health and analyze messages
for suspicious Amazon impersonation signals across English, Hindi, and Telugu.
"""

import os
import json
import logging
from typing import List, Literal, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.detector import analyze_message, SUPPORTED_LANGUAGES
from app.translations import get_translation
from app.ai_analyzer import analyze_with_ai
from app.url_analyzer import analyze_scam_url, extract_urls
from app.assistant import chat_with_assistant

app = FastAPI(
    title="Scam Shield API",
    description="Multilingual scam-detection API for identifying Amazon impersonation scams in India.",
    version="0.1.0",
)

# CORS configuration for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


class HealthResponse(BaseModel):
    status: str
    service: str


class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        description="The incoming text message to evaluate for scam indicators.",
        examples=["Amazon: Your account is blocked due to pending KYC. Update at bit.ly/amz-kyc"],
    )
    language: Literal["en", "hi", "te"] = Field(
        default="en",
        description="Language code for detection and localized guidance ('en', 'hi', or 'te').",
        examples=["en"],
    )

    @field_validator("message")
    @classmethod
    def validate_message_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Message cannot be empty or whitespace-only.")
        return value


class AnalyzeResponse(BaseModel):
    risk_score: int
    verdict: str
    category: str
    red_flags: List[str]
    safe_actions: List[str]
    language: str
    localized_verdict: Optional[str] = None
    localized_safety_advice: Optional[str] = None
    ai_explanation: Optional[str] = None
    analysis_mode: str = "rule_based"  # 'ai_enhanced' or 'rule_based'


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Verify that the Scam Shield API service is online and healthy.",
    tags=["Health"],
)
def get_health() -> HealthResponse:
    """Return the health status of the Scam Shield service."""
    return HealthResponse(status="ok", service="Scam Shield")


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze Message",
    description="Analyze an incoming message for Amazon scam/phishing patterns and return risk metrics with localized guidance.",
    tags=["Analysis"],
)
def post_analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Evaluate message for Amazon impersonation indicators.
    Executes rule-based baseline and safely augments with Gemini AI analysis
    when available, ensuring the final risk score is never lower than the rule score.
    """
    try:
        rule_result = analyze_message(
            message=request.message, language=request.language
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the message.",
        )

    # Attempt AI analysis gracefully
    ai_result, ai_diagnostic = analyze_with_ai(message=request.message, language=request.language)

    if ai_result:
        analysis_mode = "ai_enhanced"
        # Ensure final score is never lower than rule-based score
        final_risk_score = max(rule_result["risk_score"], ai_result["risk_score"])
        ai_explanation = ai_result.get("ai_explanation")

        # Category priority: if rule matched a specific category, retain it, otherwise use AI category
        if rule_result["category"] != "No Scam Detected" and rule_result["category"] != "General Suspicious Communication":
            final_category = rule_result["category"]
        else:
            final_category = ai_result.get("category", rule_result["category"])

        # Determine verdict based on final score
        if final_risk_score >= 75:
            final_verdict = "critical"
        elif final_risk_score >= 50:
            final_verdict = "high"
        elif final_risk_score >= 25:
            final_verdict = "medium"
        else:
            final_verdict = "low"

        # Combine red flags and safe actions cleanly without duplicates
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

    # Localized verdict and general safety advice
    localized_verdict: Optional[str] = None
    localized_safety_advice: Optional[str] = None

    try:
        localized_verdict = get_translation(
            key=final_verdict, language=request.language
        )
    except (KeyError, ValueError):
        localized_verdict = None

    try:
        localized_safety_advice = get_translation(
            key="general_safety_advice", language=request.language
        )
    except (KeyError, ValueError):
        localized_safety_advice = None

    return AnalyzeResponse(
        risk_score=final_risk_score,
        verdict=final_verdict,
        category=final_category,
        red_flags=final_red_flags,
        safe_actions=final_safe_actions,
        language=rule_result["language"],
        localized_verdict=localized_verdict,
        localized_safety_advice=localized_safety_advice,
        ai_explanation=ai_explanation,
        analysis_mode=analysis_mode,
    )


class MCPDemoResponse(AnalyzeResponse):
    invoked_via_mcp: bool = True
    mcp_tool_name: str = "analyze_scam_message"
    mcp_endpoint: str = "http://127.0.0.1:8001/mcp"


@app.post(
    "/mcp-demo",
    response_model=MCPDemoResponse,
    summary="Alexa+ MCP Bridge Demo",
    description="Connects to the Scam Shield MCP server via the official Python MCP SDK over Streamable HTTP and invokes the analyze_scam_message tool.",
    tags=["MCP Demo"],
)
async def post_mcp_demo(request: AnalyzeRequest) -> MCPDemoResponse:
    """
    Simulated Alexa+ bridge that genuinely calls the MCP tool `analyze_scam_message`
    running on the Scam Shield MCP server via Streamable HTTP transport.
    """
    mcp_host = os.getenv("MCP_HOST", "127.0.0.1")
    mcp_port = os.getenv("MCP_PORT", os.getenv("PORT", "8001"))
    mcp_path = os.getenv("MCP_PATH", "/mcp")
    if not mcp_path.startswith("/"):
        mcp_path = f"/{mcp_path}"
    mcp_url = os.getenv("MCP_SERVER_URL", f"http://{mcp_host}:{mcp_port}{mcp_path}")

    try:
        async with streamable_http_client(mcp_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                call_result = await session.call_tool(
                    name="analyze_scam_message",
                    arguments={"message": request.message, "language": request.language},
                )
    except Exception as exc:
        logging.getLogger("scam_shield.mcp_client").error("MCP call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to communicate with Scam Shield MCP server at {mcp_url}: {str(exc)}",
        )

    # Extract parsed result from tool output
    if not call_result.content:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="MCP tool returned empty content.",
        )

    raw_text = call_result.content[0].text
    try:
        parsed_result = json.loads(raw_text)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not parse MCP tool response: {str(exc)}",
        )

    return MCPDemoResponse(
        risk_score=parsed_result["risk_score"],
        verdict=parsed_result["verdict"],
        category=parsed_result["category"],
        red_flags=parsed_result.get("red_flags", []),
        safe_actions=parsed_result.get("safe_actions", []),
        language=parsed_result.get("language", request.language),
        localized_verdict=parsed_result.get("localized_verdict"),
        localized_safety_advice=parsed_result.get("localized_safety_advice"),
        ai_explanation=parsed_result.get("ai_explanation"),
        analysis_mode=parsed_result.get("analysis_mode", "rule_based"),
        invoked_via_mcp=True,
        mcp_tool_name="analyze_scam_message",
        mcp_endpoint=mcp_url,
    )


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., description="Message from the user to the Voice Assistant")
    language: Literal["en", "hi", "te"] = Field(default="en")
    history: Optional[List[ChatMessage]] = Field(default=None)
    auto_analyze_links: bool = Field(default=True)

    @field_validator("message")
    @classmethod
    def validate_message_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Message cannot be empty or whitespace-only.")
        return value


class ChatResponse(BaseModel):
    reply: str
    speech_text: str
    language: str
    urls_detected: List[dict]
    scam_message_analysis: Optional[dict] = None
    overall_risk_score: int
    overall_verdict: str


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., description="Web link to inspect")
    check_live: bool = Field(default=True)
    language: Literal["en", "hi", "te"] = Field(default="en")

    @field_validator("url")
    @classmethod
    def validate_url_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("URL cannot be empty or whitespace-only.")
        return value


@app.post(
    "/chat",
    response_model=ChatResponse,
    summary="Voice Assistant Conversational Endpoint",
    description="Conversational endpoint for the voice assistant. Answers general questions, greets warmly, and automatically analyzes URLs and scam signals.",
    tags=["Voice Assistant"],
)
def post_chat(request: ChatRequest) -> ChatResponse:
    """
    Chat endpoint for the Scam Shield Voice Assistant.
    Provides empathetic conversational companion responses, answers questions,
    and automatically extracts and analyzes any URLs or scam messages.
    """
    try:
        history_dicts = (
            [{"role": h.role, "content": h.content} for h in request.history]
            if request.history
            else None
        )
        result = chat_with_assistant(
            message=request.message,
            language=request.language,
            history=history_dicts,
            auto_analyze_links=request.auto_analyze_links,
        )
        return ChatResponse(
            reply=result["reply"],
            speech_text=result["speech_text"],
            language=result["language"],
            urls_detected=result["urls_detected"],
            scam_message_analysis=result["scam_message_analysis"],
            overall_risk_score=result["overall_risk_score"],
            overall_verdict=result["overall_verdict"],
        )
    except Exception as exc:
        logging.getLogger("scam_shield.chat").error("Chat error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while communicating with the assistant: {str(exc)}",
        )


@app.post(
    "/analyze-url",
    summary="Analyze Scam URL",
    description="Inspect a single URL for lookalikes, shorteners, SSRF safety, and phishing markers.",
    tags=["URL Analysis"],
)
def post_analyze_url(request: AnalyzeUrlRequest) -> dict:
    """
    Dedicated endpoint to evaluate a link for scam signals and SSRF safety.
    """
    try:
        return analyze_scam_url(
            url=request.url,
            check_live=request.check_live,
            language=request.language,
        )
    except Exception as exc:
        logging.getLogger("scam_shield.url_analyzer").error("URL analysis error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while evaluating the URL: {str(exc)}",
        )


