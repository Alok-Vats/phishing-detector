import pytest
from unittest.mock import MagicMock
from app.ml.explainability import explain_url_rf_prediction, explain_email_svm_prediction
import numpy as np

def test_explain_url_rf_prediction():
    mock_model = MagicMock()
    # Mock global feature importances for URL
    mock_model.feature_importances_ = [0.05, 0.20, 0.01, 0.30]
    feature_names = ["url_length", "contains_ip_address", "uses_https", "entropy"]
    
    # Instance features where IP address is present, length is short, and entropy is high
    features = {
        "url_length": 50,
        "contains_ip_address": 1,
        "uses_https": 1,
        "entropy": 4.5
    }
    
    explanations = explain_url_rf_prediction(features, feature_names, mock_model)
    
    # 0.30 entropy > 0.20 IP
    assert len(explanations) == 2
    assert explanations[0]["feature"] == "entropy"
    assert explanations[0]["reason"] == "high entropy/randomness in URL structure"
    assert explanations[1]["feature"] == "contains_ip_address"
    assert explanations[1]["reason"] == "IP hostname instead of domain"

def test_explain_email_svm_prediction_heuristics():
    heuristic_features = {
        "contains_urgent_language": 1,
        "contains_html_link": 1
    }
    mock_model = MagicMock()
    mock_model.coef_ = np.array([[0.0]])
    mock_vectorizer = MagicMock()
    mock_vectorizer.transform.return_value = MagicMock()
    
    explanations = explain_email_svm_prediction("test", mock_vectorizer, mock_model, heuristic_features)
    assert len(explanations) >= 2
    reasons = [e["reason"] for e in explanations]
    assert "urgency indicators detected" in reasons
    assert "suspicious HTML characteristics" in reasons

def test_explain_email_svm_prediction_coefficients():
    mock_vectorizer = MagicMock()
    mock_vectorizer.get_feature_names_out.return_value = ["good", "urgent", "login"]
    
    # Sparse matrix mock
    from scipy.sparse import csr_matrix
    mock_vectorizer.transform.return_value = csr_matrix([[1, 1, 1]])
    
    mock_model = MagicMock()
    # LinearSVC usually has shape (1, n_features) for binary classification
    mock_model.coef_ = np.array([[-1.5, 2.0, 3.5]])
    
    explanations = explain_email_svm_prediction("good urgent login", mock_vectorizer, mock_model)
    
    # "good" has negative coefficient, should not appear
    # "login" has 3.5, "urgent" has 2.0
    assert len(explanations) == 2
    assert explanations[0]["feature"] == "keyword_login"
    assert explanations[0]["reason"] == "suspicious language ('login')"
    assert explanations[0]["importance"] == 3.5
    assert explanations[1]["feature"] == "keyword_urgent"
    assert explanations[1]["importance"] == 2.0
