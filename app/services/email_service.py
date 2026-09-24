"""Email phishing detection service integrated with hybrid risk engine."""

from __future__ import annotations

from app.ml.email_feature_extractor import extract_email_features, extract_urls_from_email
from app.ml.model_loader import load_email_model_and_vectorizer
from app.services.hybrid_risk_engine import compute_hybrid_score
from app.services.prediction_service import _predict_with_model_v2
from app.ml.explainability import explain_email_svm_prediction
import pandas as pd


def analyze_email_content(sender: str, subject: str, body: str) -> dict:
    """Analyze email content combining NLP, rules, and URL analysis via Hybrid Engine."""
    features = extract_email_features(sender, subject, body)
    linked_urls = extract_urls_from_email(body)
    
    # 1. Email Rules
    email_rules_score = _calculate_risk_score(features)
    
    # 2. Email ML
    email_ml_result = _predict_email_ml(sender, subject, body, features)
    
    # 3. Embedded URL ML (taking the worst case if multiple URLs)
    url_ml_result = None
    url_rules_score = 0
    if linked_urls:
        for url in linked_urls:
            # We can use prediction_service's v2 ML 
            u_ml = _predict_with_model_v2(url)
            if u_ml and u_ml.get("prediction") == "phishing":
                url_ml_result = u_ml
                break
            if u_ml and not url_ml_result:
                url_ml_result = u_ml
        # Add a simple heuristic bump if URLs are present
        url_rules_score = len(linked_urls)
    
    # 4. Compute Hybrid Score
    hybrid_result = compute_hybrid_score(
        url_ml_result=url_ml_result,
        email_ml_result=email_ml_result,
        url_rules_score=url_rules_score,
        email_rules_score=email_rules_score,
        whitelist_match=False, # Could add sender domain whitelist here later
        blacklist_match=False,
    )

    # Wrap in expected response format
    hybrid_result["input_type"] = "email"
    hybrid_result["sender"] = sender.strip()
    hybrid_result["subject"] = subject.strip()
    hybrid_result["details"] = {
        "normalized_sender": sender.strip().lower(),
        "subject": subject.strip(),
        "body_preview": body.strip()[:180],
        "linked_urls": linked_urls,
        "features": features,
    }
    # Keep compatibility fields
    hybrid_result["reasons"] = hybrid_result["contributing_signals"]
    hybrid_result["model_source"] = "hybrid_engine"
    hybrid_result["matched_list"] = None
    hybrid_result["matched_entry"] = None
    
    return hybrid_result


def _predict_email_ml(sender: str, subject: str, body: str, heuristic_features: dict) -> dict | None:
    """Run NLP inference on email text."""
    try:
        loaded = load_email_model_and_vectorizer()
        if not loaded:
            return None
        model_bundle, vectorizer = loaded
    except Exception:
        return None
        
    text = f"{sender} {subject} {body}".lower()
    
    try:
        X_vec = vectorizer.transform([text])
        model = model_bundle["model"]
        pred_val = model.predict(X_vec)[0]
        
        if pred_val == 1 or pred_val == "1":
            prediction = "phishing"
        else:
            prediction = "legitimate"
            
        confidence = 0.85
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_vec)[0]
            if pred_val == 1 or pred_val == "1":
                confidence = float(probs[1]) if len(probs) > 1 else 0.85
            else:
                confidence = float(probs[0]) if len(probs) > 1 else 0.85
        elif hasattr(model, "decision_function"):
            score = model.decision_function(X_vec)[0]
            import math
            prob = 1.0 / (1.0 + math.exp(-score))
            confidence = prob if prediction == "phishing" else 1 - prob
                
        model = model_bundle["model"]
        explanations = explain_email_svm_prediction(text, vectorizer, model, heuristic_features)
        return {"prediction": prediction, "confidence": confidence, "xai": explanations}
    except Exception:
        return None


def _calculate_risk_score(features: dict) -> int:
    """Aggregate rule triggers into a simple phishing risk score."""
    return int(
        features.get("contains_urgent_language", 0)
        + features.get("contains_suspicious_keyword", 0)
        + features.get("contains_attachment_hint", 0)
        + features.get("contains_html_link", 0)
        + features.get("contains_reply_to_mismatch_hint", 0)
        + features.get("display_name_mismatch_hint", 0)
        + (2 if features.get("url_count", 0) >= 2 else 0)
        + (2 if features.get("external_domain_count", 0) > 0 else 0)
    )
