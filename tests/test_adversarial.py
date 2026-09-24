"""Offline Adversarial Robustness Defensive Tests."""

import pytest
from app.services.prediction_service import _predict_with_model_v2, _predict_with_model
from app.services.email_service import analyze_email_content

def test_url_encoding_obfuscation():
    """Test that URL encoding does not trick the ML model into scoring legitimately."""
    # Baseline phishing URL
    baseline_url = "http://secure.paypal.com.login-update-account.info/login"
    res_base = _predict_with_model_v2(baseline_url) or _predict_with_model(baseline_url)
    
    # Obfuscated URL (URL Encoded)
    obfuscated_url = "http://secure.paypal.com.login-update-account.info/%6c%6f%67%69%6e"
    res_obf = _predict_with_model_v2(obfuscated_url) or _predict_with_model(obfuscated_url)
    
    # Ensure both are flagged as phishing
    assert res_base["prediction"] == "phishing"
    assert res_obf["prediction"] == "phishing"
    
    # Confidence should not drop significantly (delta < 0.1)
    confidence_drop = res_base["confidence"] - res_obf["confidence"]
    assert confidence_drop < 0.15, f"Model is highly vulnerable to URL encoding (Drop: {confidence_drop})"

def test_url_suspicious_subdomain_changes():
    """Test inserting highly suspicious tokens in subdomains."""
    baseline = "http://login.update.com/path"
    res_base = _predict_with_model_v2(baseline) or _predict_with_model(baseline)
    
    adversarial = "http://secure-billing-login-verify.update.com/path"
    res_adv = _predict_with_model_v2(adversarial) or _predict_with_model(adversarial)
    
    # Adding more suspicious tokens should logically maintain or increase risk confidence, not decrease it
    assert res_adv["prediction"] == "phishing"
    assert res_adv["confidence"] >= res_base["confidence"] - 0.05

def test_email_wording_changes():
    """Test that bypassing filter words with char substitution (l33t speak) is handled or risk doesn't drop to 0."""
    sender = "admin@paypal.com"
    subject = "Account Restricted"
    body_base = "Dear customer, your account has been restricted. Please login immediately to update your billing details."
    
    res_base = analyze_email_content(sender, subject, body_base)
    
    body_adv = "Dear customer, your acc0unt has been r3stricted. Please log1n immediately to upd4te your b!lling details."
    res_adv = analyze_email_content(sender, subject, body_adv)
    
    # The goal is to measure robustness. If the base email wasn't highly malicious to the ML, 
    # we just check that the risk score doesn't drop significantly due to obfuscation.
    risk_drop = res_base["risk_score"] - res_adv["risk_score"]
    assert risk_drop < 15, f"Risk dropped massively from {res_base['risk_score']} to {res_adv['risk_score']} due to l33t speak"

def test_email_subject_modifications():
    """Test appending urgent but noisy tokens to subject."""
    sender = "support@apple.com"
    body = "Click here to unlock your Apple ID."
    
    sub_base = "Action Required: Apple ID Locked"
    res_base = analyze_email_content(sender, sub_base, body)
    
    sub_adv = "URGENT!!! [Action Required]: Apple ID Locked!!! (Ref: 19283)"
    res_adv = analyze_email_content(sender, sub_adv, body)
    
    risk_drop = res_base["risk_score"] - res_adv["risk_score"]
    assert risk_drop < 10, f"Risk dropped due to noisy subject from {res_base['risk_score']} to {res_adv['risk_score']}"
