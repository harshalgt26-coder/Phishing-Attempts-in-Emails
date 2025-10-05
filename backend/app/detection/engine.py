from __future__ import annotations

from typing import List

from ..schemas import EmailInput, DetectionResult
from .heuristics import score_sender_domain, score_subject_and_body, score_attachments
from .llm import analyze_with_llm


def clamp(value: int, min_value: int = 0, max_value: int = 100) -> int:
    return max(min_value, min(max_value, value))


def score_to_verdict(score: int) -> tuple[str, str]:
    # Map score to verdict and confidence
    if score >= 75:
        return "phishing", "high"
    if score >= 50:
        return "suspicious", "medium"
    return "safe", "low"


def recommend_actions(verdict: str, confidence: str) -> List[str]:
    if verdict == "phishing" and confidence == "high":
        return [
            "This is likely a phishing attempt. Report and block the sender.",
            "Do not click links or open attachments.",
            "Verify via known official channels only.",
        ]
    if verdict == "suspicious":
        return [
            "Exercise caution. Verify sender identity.",
            "Do not provide credentials or payment.",
        ]
    return [
        "No strong phishing indicators detected.",
        "Stay vigilant and report unexpected emails.",
    ]


def run_detection(email: EmailInput) -> DetectionResult:
    total_score = 0
    signals: List = []

    # Heuristics
    h1 = score_sender_domain(email.sender_email)
    total_score += h1.score_delta
    signals.extend(h1.signals)

    h2 = score_subject_and_body(email.subject, email.body_text, email.body_html)
    total_score += h2.score_delta
    signals.extend(h2.signals)

    h3 = score_attachments([a.model_dump() for a in email.attachments])
    total_score += h3.score_delta
    signals.extend(h3.signals)

    # LLM analysis
    llm_delta, llm_summary, llm_signals = analyze_with_llm(email)
    total_score += llm_delta
    signals.extend(llm_signals)

    # Normalize and finalize verdict
    total_score = clamp(total_score, 0, 100)
    verdict, confidence = score_to_verdict(total_score)
    recommendations = recommend_actions(verdict, confidence)

    return DetectionResult(
        verdict=verdict,
        score=total_score,
        confidence=confidence,
        signals=signals,
        recommendations=recommendations,
        llm_summary=llm_summary or None,
    )
