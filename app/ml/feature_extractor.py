"""Feature extraction utilities for URL phishing analysis."""

from __future__ import annotations

import ipaddress
import math
from urllib.parse import parse_qsl

from app.utils.url_parser import parse_url


SUSPICIOUS_KEYWORDS = ("login", "verify", "secure", "update", "account", "bank", "signin", "auth", "confirm", "service", "support")
SUSPICIOUS_TLDS = (".tk", ".xyz", ".top", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc", ".su")


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for lexical features."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def extract_features(url: str) -> dict:
    """Extract deterministic URL features for rules and future ML models."""
    parsed = parse_url(url)
    lexical_target = f"{parsed.hostname}{parsed.path}".lower()
    
    url_len = len(parsed.normalized)
    dot_count = parsed.hostname.count(".")
    hyphen_count = parsed.hostname.count("-")
    
    special_chars = "@?&=_%-"
    special_character_count = sum(url.count(c) for c in special_chars)
    digit_count = sum(c.isdigit() for c in url)
    
    special_char_ratio = special_character_count / url_len if url_len > 0 else 0.0
    digit_ratio = digit_count / url_len if url_len > 0 else 0.0
    
    query_params = parse_qsl(parsed.query, keep_blank_values=True)

    return {
        "url_length": url_len,
        "domain_length": len(parsed.hostname),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "subdomain_count": max(dot_count - 1, 0),
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "special_character_count": special_character_count,
        "special_char_ratio": special_char_ratio,
        "digit_ratio": digit_ratio,
        "query_parameter_count": len(query_params),
        "uses_https": int(parsed.scheme == "https"),
        "contains_ip_address": int(_contains_ip_address(parsed.hostname)),
        "contains_at_symbol": int("@" in url),
        "contains_suspicious_keyword": int(any(k in lexical_target for k in SUSPICIOUS_KEYWORDS)),
        "entropy": calculate_entropy(url),
        "is_suspicious_tld": int(any(parsed.hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        "obfuscation_count": url.count("%")
    }


def _contains_ip_address(hostname: str) -> bool:
    """Return True when the hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True
