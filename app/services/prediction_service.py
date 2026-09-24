"""High-level orchestration for URL analysis requests."""

from __future__ import annotations

import pandas as pd
from pathlib import Path
from flask import current_app

from app.ml.feature_extractor import extract_features
from app.ml.model_loader import load_model
from app.services.blacklist_service import get_blacklist_match
from app.services.url_service import inspect_url
from app.services.whitelist_service import get_whitelist_match
from app.services.hybrid_risk_engine import compute_hybrid_score
from app.services.threat_intel import check_url_reputation
from app.services.website_analysis import fetch_and_analyze
from app.ml.explainability import explain_url_rf_prediction


def analyze_url(url: str) -> dict:
    """Return an analysis result using list matches, ML inference, or heuristics."""
    details = inspect_url(url)
    whitelist_match = get_whitelist_match(url)
    blacklist_match = get_blacklist_match(url)
    
    url_rules_score = 0
    if details["reasons"]:
        url_rules_score = len(details["reasons"])

    url_ml_result = _predict_with_model_v2(url)
    if not url_ml_result:
        # Fallback to v1 if v2 fails
        url_ml_result = _predict_with_model(url)
        
    threat_intel_results = check_url_reputation(url)
    
    # Try fetching website for static HTML signals
    website_analysis_result = fetch_and_analyze(url)
        
    hybrid_result = compute_hybrid_score(
        url_ml_result=url_ml_result,
        email_ml_result=None,
        url_rules_score=url_rules_score,
        email_rules_score=0,
        whitelist_match=bool(whitelist_match),
        blacklist_match=bool(blacklist_match),
        threat_intel_results=threat_intel_results,
        website_analysis_result=website_analysis_result,
    )
    
    # Wrap in expected response format
    hybrid_result["input_type"] = "url"
    hybrid_result["url"] = url
    hybrid_result["details"] = details
    hybrid_result["reasons"] = hybrid_result["contributing_signals"]
    if whitelist_match:
        hybrid_result["model_source"] = "whitelist"
        hybrid_result["matched_list"] = "whitelist"
        hybrid_result["matched_entry"] = whitelist_match
    elif blacklist_match:
        hybrid_result["model_source"] = "blacklist"
        hybrid_result["matched_list"] = "blacklist"
        hybrid_result["matched_entry"] = blacklist_match
    else:
        hybrid_result["model_source"] = "hybrid_engine"
        hybrid_result["matched_list"] = None
        hybrid_result["matched_entry"] = None

    return hybrid_result


def _predict_with_model(url: str) -> dict | None:
    """Run inference using the saved model artifact when available."""
    try:
        model_bundle = load_model()
    except (OSError, ValueError):
        return None

    if model_bundle is None:
        return None

    features = extract_features(url)
    feature_row = pd.DataFrame([features]).reindex(columns=model_bundle["feature_names"], fill_value=0)
    model = model_bundle["model"]

    prediction = str(model.predict(feature_row)[0])
    probability_lookup = {}
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(feature_row)[0]
        probability_lookup = {
            label: float(probability)
            for label, probability in zip(model.classes_, probabilities, strict=False)
        }

    confidence = probability_lookup.get(prediction, 0.5)
    explanations = explain_url_rf_prediction(features, model_bundle["feature_names"], model)
    return {"prediction": prediction, "confidence": confidence, "xai": explanations}


def _predict_with_model_v2(url: str) -> dict | None:
    """Run inference using the v2 model artifact when available."""
    try:
        # Try to resolve path safely
        base_path = current_app.config.get("MODEL_PATH", "models/phishing_url_model.pkl")
        v2_path = str(Path(base_path).parent / "phishing_url_model_v2.pkl")
        model_bundle = load_model(v2_path)
    except Exception:
        # If outside app context, fallback
        base_dir = Path(__file__).resolve().parent.parent.parent
        v2_path = str(base_dir / "models" / "phishing_url_model_v2.pkl")
        model_bundle = load_model(v2_path)

    if model_bundle is None:
        return None

    features = extract_features(url)
    feature_row = pd.DataFrame([features]).reindex(columns=model_bundle["feature_names"], fill_value=0)
    model = model_bundle["model"]

    prediction = str(model.predict(feature_row)[0])
    probability_lookup = {}
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(feature_row)[0]
        probability_lookup = {
            label: float(probability)
            for label, probability in zip(model.classes_, probabilities, strict=False)
        }

    confidence = probability_lookup.get(prediction, 0.5)
    explanations = explain_url_rf_prediction(features, model_bundle["feature_names"], model)
    return {"prediction": prediction, "confidence": confidence, "xai": explanations}
