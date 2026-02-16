"""
Streamlit frontend for the practical password validation application.

This UI consumes the FastAPI backend:
- POST /validate for policy checks
- POST /strength for strength scoring
"""

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, request

import streamlit as st


def get_strength_label(score: float) -> str:
    """Map numeric score (0-100) into a readable strength label."""
    if score >= 80:
        return "Very Strong"
    if score >= 60:
        return "Strong"
    if score >= 40:
        return "Medium"
    return "Weak"


def render_strength(score: float) -> None:
    """Render Streamlit progress bar + text label for password strength."""
    normalized = max(0.0, min(1.0, score / 100.0))
    st.progress(normalized)
    label = get_strength_label(score)
    st.caption(f"{label} ({score:.1f}/100)")


def post_json(
    api_base_url: str, endpoint: str, payload: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Send JSON payload to backend endpoint and return:
    - parsed response dict on success
    - error string on failure
    """
    url = f"{api_base_url.rstrip('/')}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")
            return json.loads(body), None
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        return None, f"HTTP {exc.code}: {details}"
    except error.URLError as exc:
        return None, f"Connection error: {exc.reason}"
    except Exception as exc:
        return None, f"Unexpected error: {exc}"


def check_health(api_base_url: str) -> bool:
    """Call backend health endpoint and return True when API is ready."""
    url = f"{api_base_url.rstrip('/')}/health"
    try:
        with request.urlopen(url, timeout=3) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body.get("status") == "ok"
    except Exception:
        return False


def main() -> None:
    """Main Streamlit application entry point."""
    st.set_page_config(
        page_title="Password Security Validator",
        page_icon="🔐",
        layout="centered",
    )

    st.title("🔐 Password Security Validator")
    st.caption("OWASP-aligned password validation with instant feedback")

    # Sidebar contains backend connection info and static password policy rules.
    with st.sidebar:
        st.subheader("API")
        api_base_url = st.text_input("Backend URL", value="http://127.0.0.1:8000")
        if check_health(api_base_url):
            st.success("Backend connected")
        else:
            st.warning("Backend not reachable")

        st.subheader("Password Rules")
        st.markdown(
            """
            - 8 to 128 characters
            - At least 1 lowercase letter
            - At least 1 uppercase letter
            - At least 1 number
            - At least 1 special character
            - No long repeated sequences
            - No sequential patterns like `abc` or `123`
            """
        )

    username = st.text_input("Username (optional)", placeholder="e.g. johnsmith")

    # Toggle to help users inspect input while preserving default hidden mode.
    show_password = st.checkbox("Show password", value=False)
    password_type = "default" if show_password else "password"
    password = st.text_input("Password", type=password_type, placeholder="Enter password")

    # No API call until user starts typing a password.
    if not password:
        st.info("Enter a password to see validation and strength analysis.")
        return

    payload = {
        "password": password,
        "username": username or None,
    }

    # Call both backend endpoints used by the UI.
    validate_response, validate_error = post_json(api_base_url, "/validate", payload)
    strength_response, strength_error = post_json(api_base_url, "/strength", payload)

    # Centralized API error display so users know exactly what to fix.
    if validate_error or strength_error:
        st.error("Unable to fetch validation results from backend API.")
        if validate_error:
            st.caption(f"Validate error: {validate_error}")
        if strength_error:
            st.caption(f"Strength error: {strength_error}")
        st.info("Start the API first: python -m uvicorn api:app --reload")
        return

    # Defensive parsing with safe defaults.
    is_valid = bool(validate_response.get("is_valid", False))
    issues: List[str] = validate_response.get("issues", [])
    score = float(strength_response.get("score", 0.0))
    feedback: List[str] = strength_response.get("feedback", [])

    st.subheader("Strength")
    render_strength(score)

    st.subheader("Validation Result")
    if is_valid:
        st.success("Password meets all configured security requirements.")
    else:
        st.error("Password does not meet one or more security requirements.")
        for issue in issues:
            st.markdown(f"- {issue}")

    if feedback:
        st.subheader("Suggestions")
        for suggestion in feedback:
            st.markdown(f"- {suggestion}")


if __name__ == "__main__":
    main()
