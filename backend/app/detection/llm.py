from __future__ import annotations

from typing import List, Optional

from openai import OpenAI

from ..config import get_settings
from ..schemas import DetectionSignal, EmailInput


SYSTEM_PROMPT = (
    "You are a security analyst specialized in phishing email detection. "
    "Given the email subject, sender, body, and attachments metadata, "
    "analyze for phishing characteristics including brand impersonation, urgency, credential harvesting, and links/attachments risks. "
    "Return a short, decisive assessment and do not hedge excessively."
)


def analyze_with_llm(email: EmailInput) -> tuple[int, str, List[DetectionSignal]]:
    settings = get_settings()
    if not settings.llm_enabled:
        return 0, "", []

    client = OpenAI(api_key=settings.openai_api_key)

    parts = []
    parts.append(f"Subject: {email.subject}")
    parts.append(f"Sender: {email.sender_email}")
    if email.sender_display_name:
        parts.append(f"Sender Name: {email.sender_display_name}")
    if email.body_text:
        parts.append(f"Body (text):\n{email.body_text}")
    if email.body_html:
        parts.append(f"Body (html):\n{email.body_html}")
    if email.attachments:
        att_lines = [f"- {a.filename} ({a.mime_type or 'unknown'}, {a.size_bytes or '?'} bytes)" for a in email.attachments]
        parts.append("Attachments:\n" + "\n".join(att_lines))

    user_content = "\n\n".join(parts)

    try:
        response = client.chat.completions.create(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
                {"role": "system", "content": (
                    "Return JSON with keys: risk ('low'|'medium'|'high'), "
                    "rationale (string <= 300 chars), and indicators (array of short bullet strings)."
                )},
            ],
            temperature=0.2,
        )
    except Exception as e:
        # Fail open: heuristics still apply; LLM adds no score
        return 0, "", [
            DetectionSignal(
                id="llm.error",
                title="LLM analysis unavailable",
                description=(str(e)[:200] or "LLM call failed."),
                severity="low",
                score_delta=0,
            )
        ]

    content = response.choices[0].message.content or ""

    # Simple robust parsing without importing json for resilience to minor formatting issues
    import json
    risk = "low"
    rationale = ""
    indicators: List[str] = []
    try:
        parsed = json.loads(content)
        risk = parsed.get("risk", risk)
        rationale = parsed.get("rationale", rationale)
        indicators = parsed.get("indicators", [])
    except Exception:
        rationale = content[:300]

    score_delta = 0
    severity_map = {"low": ("low", 0), "medium": ("medium", 10), "high": ("high", 25)}
    sev, delta = severity_map.get(str(risk).lower(), ("low", 0))
    score_delta += delta

    llm_signals = [
        DetectionSignal(
            id="llm.summary",
            title="LLM phishing assessment",
            description=rationale or "LLM gave no rationale.",
            severity=sev,
            score_delta=delta,
        )
    ]

    for idx, ind in enumerate(indicators[:5]):
        llm_signals.append(DetectionSignal(
            id=f"llm.indicator.{idx+1}",
            title=f"LLM indicator #{idx+1}",
            description=str(ind)[:200],
            severity=sev,
            score_delta=0,
        ))

    return score_delta, rationale, llm_signals
