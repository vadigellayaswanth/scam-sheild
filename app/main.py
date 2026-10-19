"""
app.main
~~~~~~~~

FastAPI application for the Scam Shield project.
Provides HTTP API endpoints to check service health and analyze messages
for suspicious Amazon impersonation signals across English, Hindi, and Telugu.
"""

from typing import List, Literal, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from app.detector import analyze_message, SUPPORTED_LANGUAGES
from app.translations import get_translation
from app.ai_analyzer import analyze_with_ai

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
