"""
FastAPI backend for password validation services.
This API exposes three endpoints:
- GET /health: simple readiness check
- POST /validate: returns policy validation results
- POST /strength: returns password strength score and feedback
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from password_validator import PasswordValidator


app = FastAPI(
    title="Password Validation API",
    description="OWASP-aligned API for password validation and strength scoring.",
    version="1.0.0",
)


COMMON_PASSWORDS_PATH = Path(__file__).parent / "common_passwords.txt"
# Single shared validator instance for all incoming requests.
validator = PasswordValidator(str(COMMON_PASSWORDS_PATH))


class ValidationRequest(BaseModel):
    """Input payload for validation/strength endpoints."""
    password: str = Field(..., min_length=1, description="Password to validate")
    username: Optional[str] = Field(None, description="Optional username for similarity checks")


class ValidationResponse(BaseModel):
    """Validation response model returned by POST /validate."""
    is_valid: bool
    issues: List[str]


class StrengthResponse(BaseModel):
    """Strength response model returned by POST /strength."""
    strength: str
    score: float
    feedback: List[str]


@app.get("/health")
def health() -> Dict[str, str]:
    """Health endpoint used by frontend/service checks."""
    return {"status": "ok"}


@app.post("/validate", response_model=ValidationResponse)
def validate_password_endpoint(payload: ValidationRequest) -> ValidationResponse:
    """Validate password against all configured policy rules."""
    is_valid, issues = validator.validate(payload.password, username=payload.username)
    return ValidationResponse(is_valid=is_valid, issues=issues)


@app.post("/strength", response_model=StrengthResponse)
def password_strength_endpoint(payload: ValidationRequest) -> StrengthResponse:
    """Compute strength label/score and improvement feedback."""
    result: Dict[str, Any] = validator.get_password_strength(payload.password)
    return StrengthResponse(
        strength=result["strength"],
        score=float(result["score"]),
        feedback=result["feedback"],
    )
