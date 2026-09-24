import pytest
from app.services.hybrid_risk_engine import compute_hybrid_score
from app.services.threat_intel.base import ThreatIntelResult

def test_hybrid_engine_normal_legitimate():
    result = compute_hybrid_score(
        url_ml_result={"prediction": "legitimate", "confidence": 0.9},
        threat_intel_results=[]
    )
    assert result["classification"] == "legitimate"
    assert result["risk_score"] == 10

def test_hybrid_engine_normal_malicious():
    result = compute_hybrid_score(
        url_ml_result={"prediction": "phishing", "confidence": 0.95},
        threat_intel_results=[]
    )
    assert result["classification"] == "phishing"
    assert result["risk_score"] == 95
    assert "Notice: ML predicts malicious but external reputation is unavailable." in result["contributing_signals"]

def test_hybrid_engine_conflict_whitelist_malicious_ti():
    ti_mock = ThreatIntelResult("MockVT", True, False, False, 1.0, [], {})
    result = compute_hybrid_score(
        url_ml_result={"prediction": "legitimate", "confidence": 0.9},
        whitelist_match=True,
        threat_intel_results=[ti_mock]
    )
    assert result["classification"] == "suspicious"
    assert result["risk_score"] == 50
    assert any("Conflict: Local whitelist match" in s for s in result["contributing_signals"])

def test_hybrid_engine_conflict_ml_legitimate_ti_malicious():
    ti_mock = ThreatIntelResult("MockVT", True, False, False, 1.0, [], {})
    result = compute_hybrid_score(
        url_ml_result={"prediction": "legitimate", "confidence": 0.9},
        threat_intel_results=[ti_mock]
    )
    # ML says legitimate (score 10) but TI says malicious -> should elevate to >= 85
    assert result["classification"] == "phishing"
    assert result["risk_score"] >= 85
    assert any("Conflict: ML predicts legitimate but external reputation is malicious" in s for s in result["contributing_signals"])

def test_hybrid_engine_conflict_ti_disagree():
    ti_mock1 = ThreatIntelResult("MockVT", True, False, False, 1.0, [], {})
    ti_mock2 = ThreatIntelResult("MockSafe", False, False, True, 1.0, [], {})
    
    result = compute_hybrid_score(
        url_ml_result={"prediction": "legitimate", "confidence": 0.9},
        threat_intel_results=[ti_mock1, ti_mock2]
    )
    
    assert any("Conflict: External reputation providers disagree" in s for s in result["contributing_signals"])
    assert result["classification"] == "phishing" # The malicious hit still overrides

def test_hybrid_engine_blacklist_always_100():
    ti_mock2 = ThreatIntelResult("MockSafe", False, False, True, 1.0, [], {})
    result = compute_hybrid_score(
        url_ml_result={"prediction": "legitimate", "confidence": 0.9},
        blacklist_match=True,
        threat_intel_results=[ti_mock2]
    )
    assert result["classification"] == "phishing"
    assert result["risk_score"] == 100
