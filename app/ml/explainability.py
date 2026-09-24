"""Explainability utilities for ML models (XAI)."""

from __future__ import annotations

def explain_url_rf_prediction(features: dict, feature_names: list, model) -> list[dict]:
    """Provide local explanation for URL Random Forest prediction."""
    if not hasattr(model, 'feature_importances_'):
        return []
        
    importances = model.feature_importances_
    reasons_map = {
        "url_length": "unusual URL length",
        "domain_length": "unusual domain length",
        "contains_ip_address": "IP hostname instead of domain",
        "subdomain_count": "excessive subdomains",
        "contains_suspicious_keyword": "suspicious tokens in URL",
        "special_character_count": "high number of special characters",
        "entropy": "high entropy/randomness in URL structure",
        "obfuscation_count": "encoding/obfuscation detected",
        "is_suspicious_tld": "suspicious TLD",
    }
    
    explanations = []
    for i, fname in enumerate(feature_names):
        importance = importances[i]
        val = features.get(fname, 0)
        
        # Filter for meaningful contributions
        if importance > 0.01:
            if fname in ["contains_ip_address", "contains_suspicious_keyword", "is_suspicious_tld", "uses_https"]:
                # For uses_https, it's suspicious if it's 0 (HTTP)
                if fname == "uses_https" and val == 0:
                    explanations.append({"feature": fname, "reason": "lack of HTTPS encryption", "importance": float(importance)})
                elif fname != "uses_https" and val == 1:
                    explanations.append({"feature": fname, "reason": reasons_map.get(fname, fname), "importance": float(importance)})
            elif fname in ["subdomain_count", "obfuscation_count"]:
                if val > 1:
                    explanations.append({"feature": fname, "reason": reasons_map.get(fname, fname), "importance": float(importance)})
            elif fname == "entropy":
                if val > 4.0:
                    explanations.append({"feature": fname, "reason": reasons_map.get(fname, fname), "importance": float(importance)})
            elif fname == "url_length":
                if val > 75:
                    explanations.append({"feature": fname, "reason": reasons_map.get(fname, fname), "importance": float(importance)})
            elif fname == "special_char_ratio" or fname == "digit_ratio":
                if val > 0.15:
                    reason = "unusual special character ratio" if "special" in fname else "unusual digit ratio"
                    explanations.append({"feature": fname, "reason": reason, "importance": float(importance)})

    explanations.sort(key=lambda x: x["importance"], reverse=True)
    return explanations[:3]


def explain_email_svm_prediction(text: str, vectorizer, model, heuristic_features: dict = None) -> list[dict]:
    """Provide local explanation for Email Linear SVM prediction."""
    explanations = []
    
    # 1. Deterministic heuristic signals
    reasons_map = {
        "contains_urgent_language": "urgency indicators detected",
        "contains_suspicious_keyword": "credential/payment/suspicious language detected",
        "display_name_mismatch_hint": "sender display name mismatch",
        "contains_reply_to_mismatch_hint": "reply-to mismatch hint",
        "contains_attachment_hint": "suspicious attachment hint",
        "external_sender": "sender is from an external/suspicious origin",
        "contains_html_link": "suspicious HTML characteristics",
        "external_domain_count": "embedded external domains",
    }
    
    if heuristic_features:
        for fname, val in heuristic_features.items():
            if val >= 1 and fname in reasons_map:
                explanations.append({"feature": fname, "reason": reasons_map[fname], "importance": 1.0})
                
    # 2. LinearSVC coefficients analysis
    if hasattr(model, 'coef_'):
        try:
            X_vec = vectorizer.transform([text])
            feature_names = vectorizer.get_feature_names_out()
            # If multiple classes, use the positive class coefficients
            coefs = model.coef_[0] if len(model.coef_.shape) > 1 else model.coef_
            if len(model.coef_.shape) == 1:
                coefs = model.coef_
            elif len(model.coef_.shape) == 2 and model.coef_.shape[0] == 1:
                coefs = model.coef_[0]
            
            cx = X_vec.tocoo()
            contributions = []
            for i, v in zip(cx.col, cx.data):
                c = coefs[i] * v
                if c > 0: # positive contribution towards phishing class
                    contributions.append((feature_names[i], float(c)))
                    
            contributions.sort(key=lambda x: x[1], reverse=True)
            
            for fname, c in contributions[:3]:
                explanations.append({
                    "feature": f"keyword_{fname}",
                    "reason": f"suspicious language ('{fname}')",
                    "importance": round(c, 4)
                })
        except Exception:
            pass
            
    explanations.sort(key=lambda x: x["importance"], reverse=True)
    return explanations[:5]
