"""Hybrid Risk Engine combining multiple detection signals safely."""

from __future__ import annotations
import datetime

def compute_hybrid_score(
    url_ml_result: dict | None = None,
    email_ml_result: dict | None = None,
    url_rules_score: int = 0,
    email_rules_score: int = 0,
    whitelist_match: bool = False,
    blacklist_match: bool = False,
    threat_intel_results: list | None = None,
    website_analysis_result: dict | None = None,
) -> dict:
    """Combine signals into a final 0-100 score with structured explanation."""
    
    signals = []
    indicators = []
    reputation_sources = []
    xai_explanations = []
    
    # 1. Base ML predictions
    ml_scores = []
    
    if url_ml_result:
        p = url_ml_result.get("prediction")
        c = url_ml_result.get("confidence", 0.5)
        url_s = c * 100 if p == "phishing" else (1 - c) * 100
        ml_scores.append(url_s)
        signals.append(f"URL ML predicted {p} ({c:.2f} confidence)")
        indicators.append("url_ml_" + p)
        if "xai" in url_ml_result:
            xai_explanations.extend(url_ml_result["xai"])
        
    if email_ml_result:
        p = email_ml_result.get("prediction")
        c = email_ml_result.get("confidence", 0.5)
        email_s = c * 100 if p == "phishing" else (1 - c) * 100
        ml_scores.append(email_s)
        signals.append(f"Email ML predicted {p} ({c:.2f} confidence)")
        indicators.append("email_ml_" + p)
        if "xai" in email_ml_result:
            xai_explanations.extend(email_ml_result["xai"])

    if ml_scores:
        # Skew high if any ML is highly confident it's phishing
        base_ml_score = max(ml_scores) if max(ml_scores) > 75 else sum(ml_scores) / len(ml_scores)
    else:
        base_ml_score = 20 # 0 = perfectly safe, 100 = definitely phishing
        
    score = base_ml_score
    
    # 2. Rule modifiers
    if url_rules_score > 0:
        score += min(25, url_rules_score * 10)
        signals.append(f"URL heuristics triggered ({url_rules_score} flags)")
        indicators.append("url_heuristics_flag")
        
    if email_rules_score > 0:
        score += min(25, email_rules_score * 8)
        signals.append(f"Email heuristics triggered ({email_rules_score} flags)")
        indicators.append("email_heuristics_flag")
        
    # 3. External Reputation
    ti_malicious = 0
    ti_safe = 0
    if threat_intel_results:
        for result in threat_intel_results:
            reputation_sources.append({
                "provider": result.provider_name,
                "is_malicious": result.is_malicious,
                "confidence": result.confidence
            })
            if result.is_malicious:
                ti_malicious += 1
                signals.append(f"External reputation ({result.provider_name}) marked as malicious.")
                indicators.append(f"ti_{result.provider_name.lower()}_malicious")
            elif result.is_safe:
                ti_safe += 1
                
    # 4. Handle specific conflicts
    if ti_malicious > 0 and ti_safe > 0:
        signals.append("Conflict: External reputation providers disagree.")
        
    if ti_malicious > 0 and base_ml_score < 50:
        signals.append("Conflict: ML predicts legitimate but external reputation is malicious.")
        score = max(score, 85) # Trust external reputation over ML
    elif ti_malicious > 0:
        score += ti_malicious * 30

    if base_ml_score >= 75 and not threat_intel_results:
        signals.append("Notice: ML predicts malicious but external reputation is unavailable.")

    # 5. Local Lists (Overrides)
    if whitelist_match:
        if ti_malicious > 0:
            signals.append("Conflict: Local whitelist match but external reputation is malicious. Forcing manual review.")
            score = 50
            indicators.append("whitelist_conflict")
        else:
            score = 0
            signals.append("Matched local whitelist.")
            indicators.append("whitelist_hit")
    elif blacklist_match:
        score = 100
        signals.append("Matched local blacklist.")
        indicators.append("blacklist_hit")

    # 6. Website Analysis Signals (if provided)
    if website_analysis_result and "error" not in website_analysis_result:
        web_flags = 0
        
        if website_analysis_result.get("has_password_field"):
            signals.append("Website contains a password field.")
            indicators.append("web_password_field")
            
        if website_analysis_result.get("suspicious_form_destinations_count", 0) > 0:
            signals.append("Website contains a form submitting to an external/mismatched domain.")
            indicators.append("web_suspicious_form_action")
            web_flags += 2
            
        if website_analysis_result.get("external_iframes_count", 0) > 0:
            signals.append("Website embeds external iframes.")
            indicators.append("web_external_iframes")
            web_flags += 1
            
        if website_analysis_result.get("external_links_ratio", 0) > 0.8:
            signals.append("Website has a highly suspicious ratio of external links (>80%).")
            indicators.append("web_excessive_external_links")
            web_flags += 1

        if web_flags > 0:
            score += min(20, web_flags * 10)
    elif website_analysis_result and "error" in website_analysis_result:
        signals.append(f"Website analysis skipped: {website_analysis_result['error']}")

    score = max(0, min(100, int(round(score))))
    
    if score >= 75:
        classification = "phishing"
    elif score >= 50:
        classification = "suspicious"
    else:
        classification = "legitimate"
        
    explanation = f"Calculated hybrid risk score of {score}/100 based on " + ", ".join(indicators)
    if whitelist_match and ti_malicious == 0: explanation = "Overridden by whitelist."
    if blacklist_match: explanation = "Overridden by blacklist."

    return {
        "classification": classification,
        "prediction": classification, # For backward compatibility with UI/Tests
        "risk_score": score,
        "confidence": abs(score - 50) / 50.0,
        "contributing_signals": signals,
        "reputation_sources": reputation_sources,
        "xai_explanations": xai_explanations,
        "indicators": indicators,
        "explanation": explanation,
        "model_versions": {
            "url_ml": "v2",
            "email_ml": "v1",
            "engine": "1.1"
        },
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
    }
