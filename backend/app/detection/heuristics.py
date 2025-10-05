from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

import tldextract
from bs4 import BeautifulSoup
from rapidfuzz import fuzz

from ..schemas import DetectionSignal, EmailInput


TRUSTED_DOMAINS = {
    # Add more as needed
    "google.com",
    "gmail.com",
    "apple.com",
    "microsoft.com",
    "paypal.com",
    "amazon.com",
    "linkedin.com",
    "facebook.com",
    "twitter.com",
    "x.com",
}

BRAND_KEYWORDS = [
    "microsoft", "office365", "outlook", "onedrive",
    "google", "gmail", "gdrive", "workspace",
    "apple", "icloud", "itunes",
    "paypal", "bank", "chase", "boa", "wells fargo",
    "amazon", "prime",
]

URGENT_LANGUAGE = [
    "urgent", "immediately", "suspended", "verify now", "confirm your account",
    "password reset", "unauthorized", "unusual activity", "click below", "last warning",
]

SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "icu", "click", "country", "gq", "tk", "ml", "cf", "work", "mobi"
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jar", ".bat", ".cmd", ".vbs", ".lnk", ".iso", ".img", ".hta", ".ps1",
}


@dataclass
class HeuristicResult:
    score_delta: int
    signals: List[DetectionSignal]


EMAIL_REGEX = re.compile(r"(?P<name>[^<]*)<(?P<email>[^>]+)>")


def extract_domain(email: str) -> Optional[str]:
    match = EMAIL_REGEX.search(email) if "<" in email else None
    raw_email = match.group("email") if match else email
    parts = tldextract.extract(raw_email.split("@")[-1])
    if not parts.domain:
        return None
    domain = f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain
    return domain.lower()


def score_sender_domain(sender_email: str) -> HeuristicResult:
    domain = extract_domain(sender_email or "")
    signals: List[DetectionSignal] = []
    score = 0

    if not domain:
        signals.append(DetectionSignal(
            id="sender.no_domain",
            title="Sender domain not detected",
            description="Could not parse sender domain from the From header.",
            severity="medium",
            score_delta=5,
        ))
        score += 5
        return HeuristicResult(score, signals)

    # Suspicious TLDs
    extracted = tldextract.extract(domain)
    if extracted.suffix and any(tld in extracted.suffix.split('.') for tld in SUSPICIOUS_TLDS):
        signals.append(DetectionSignal(
            id="sender.suspicious_tld",
            title=f"Suspicious top-level domain: .{extracted.suffix}",
            description="Sender domain uses a commonly abused TLD for phishing.",
            severity="high",
            score_delta=20,
        ))
        score += 20

    # Lookalike domain to trusted brands (homoglyph cheap check via similarity)
    for brand in TRUSTED_DOMAINS:
        brand_root = brand.split('.')[0]
        similarity = fuzz.partial_ratio(extracted.domain.lower(), brand_root)
        if similarity >= 85 and brand_root != extracted.domain.lower():
            signals.append(DetectionSignal(
                id="sender.lookalike_domain",
                title=f"Lookalike domain to {brand}",
                description=f"Sender domain '{domain}' resembles trusted brand '{brand}'.",
                severity="high",
                score_delta=25,
            ))
            score += 25
            break

    return HeuristicResult(score, signals)


def score_subject_and_body(subject: str, body_text: Optional[str], body_html: Optional[str]) -> HeuristicResult:
    content = " ".join(filter(None, [subject or "", body_text or ""]))
    # Extract text from HTML too
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "lxml")
            content += " " + (soup.get_text(" ") or "")
        except Exception:
            pass

    content_lower = content.lower()
    score = 0
    signals: List[DetectionSignal] = []

    # Urgency and scare tactics
    for phrase in URGENT_LANGUAGE:
        if phrase in content_lower:
            signals.append(DetectionSignal(
                id="content.urgency",
                title="Urgent or threatening language",
                description=f"Found phrase indicative of urgency: '{phrase}'.",
                severity="medium",
                score_delta=10,
            ))
            score += 10
            break

    # Brand impersonation keywords
    for brand_kw in BRAND_KEYWORDS:
        if brand_kw in content_lower:
            signals.append(DetectionSignal(
                id="content.brand_impersonation",
                title="Brand impersonation indicators",
                description=f"Found brand keyword: '{brand_kw}'.",
                severity="medium",
                score_delta=10,
            ))
            score += 10
            break

    # Credential harvesting hints
    if re.search(r"verify\s+(your\s+)?(account|identity|password)", content_lower):
        signals.append(DetectionSignal(
            id="content.credential_harvest",
            title="Credential verification request",
            description="Content requests verifying account or password.",
            severity="high",
            score_delta=20,
        ))
        score += 20

    # Payment / invoice pressure
    if re.search(r"(invoice|payment|wire|gift\s*card)", content_lower):
        signals.append(DetectionSignal(
            id="content.payment_pressure",
            title="Payment or invoice pressure",
            description="Mentions of urgent payment, invoices, or wire requests.",
            severity="medium",
            score_delta=10,
        ))
        score += 10

    return HeuristicResult(score, signals)


def score_attachments(attachments: List[dict]) -> HeuristicResult:
    score = 0
    signals: List[DetectionSignal] = []

    for att in attachments or []:
        filename = (att.get("filename") or "").lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if filename.endswith(ext):
                signals.append(DetectionSignal(
                    id="attachment.dangerous_ext",
                    title=f"Dangerous attachment: {ext}",
                    description=f"Attachment '{filename}' has risky extension {ext}.",
                    severity="high",
                    score_delta=25,
                ))
                score += 25
                break

        # Large compressed archives can be suspicious, but false positives common
        if filename.endswith((".zip", ".rar", ".7z")):
            signals.append(DetectionSignal(
                id="attachment.archive",
                title="Compressed archive attachment",
                description="Compressed archives can conceal malicious content.",
                severity="medium",
                score_delta=10,
            ))
            score += 10

    return HeuristicResult(score, signals)
