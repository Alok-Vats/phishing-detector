"""Feature extraction utilities for phishing email analysis."""

from __future__ import annotations

import re
from urllib.parse import urlparse


SUSPICIOUS_EMAIL_KEYWORDS = (
    "verify", "urgent", "password", "reset", "account", "bank", "suspend", 
    "login", "click", "limited time", "credential", "payment", "invoice"
)

URL_PATTERN = re.compile(r"https?://[^\s)>\]]+")


def extract_email_features(sender: str, subject: str, body: str) -> dict:
    """Extract deterministic features for rule-based email phishing detection."""
    normalized_sender = sender.strip().lower()
    normalized_subject = subject.strip().lower()
    normalized_body = body.strip().lower()
    combined_text = f"{normalized_subject} {normalized_body}"
    discovered_urls = URL_PATTERN.findall(body)
    
    sender_domain = _extract_sender_domain(normalized_sender)
    
    external_domains = set()
    for u in discovered_urls:
        try:
            h = urlparse(u).hostname
            if h and h != sender_domain:
                external_domains.add(h)
        except Exception:
            pass

    return {
        "sender_domain": sender_domain,
        "subject_length": len(subject.strip()),
        "body_length": len(body.strip()),
        "url_count": len(discovered_urls),
        "external_domain_count": len(external_domains),
        "contains_html_link": int("<a " in body.lower() or "<html" in body.lower()),
        "contains_urgent_language": int(
            any(keyword in combined_text for keyword in ("urgent", "immediately", "action required", "act now", "important"))
        ),
        "contains_suspicious_keyword": int(
            any(keyword in combined_text for keyword in SUSPICIOUS_EMAIL_KEYWORDS)
        ),
        "contains_reply_to_mismatch_hint": int("reply-to" in body.lower() or "return-path" in body.lower()),
        "contains_attachment_hint": int(
            any(token in combined_text for token in ("attachment", ".zip", ".exe", ".html", "attached", ".pdf"))
        ),
        "external_sender": int(not normalized_sender.endswith((".edu", ".org", ".com", ".gov"))),
        "display_name_mismatch_hint": int(_has_display_name_mismatch(normalized_sender)),
    }


def _extract_sender_domain(sender: str) -> str:
    """Return the sender domain for a plain email address or mailbox string."""
    if "@" not in sender:
        return ""
    mailbox = sender.split()[-1].strip("<>")
    return mailbox.split("@", maxsplit=1)[-1]


def _has_display_name_mismatch(sender: str) -> bool:
    """Return True when the sender field includes both a display name and mailbox."""
    return "<" in sender and ">" in sender and "@" in sender


def extract_urls_from_email(body: str) -> list[str]:
    """Return HTTP(S) URLs present in the email body."""
    return [url for url in URL_PATTERN.findall(body) if urlparse(url).scheme in {"http", "https"}]
