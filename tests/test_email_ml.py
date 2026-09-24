import pytest
from app.ml.train_email_model import preprocess_data
from app.services.email_service import analyze_email_content
import pandas as pd
from app.ml.model_loader import load_email_model_and_vectorizer
import os
from app import create_app

def test_dataset_preprocessing_missing_fields():
    # Test handling of missing fields
    data = pd.DataFrame([
        {"sender": "bad@guy.com", "subject": None, "body": None, "label": 1},
        {"sender": None, "subject": "Hello", "body": "World", "label": 0}
    ])
    processed = preprocess_data(data)
    assert processed["subject"].iloc[0] == ""
    assert processed["body"].iloc[0] == ""
    assert processed["sender"].iloc[1] == ""
    assert "bad@guy.com  " in processed["text"].iloc[0] or "bad@guy.com" in processed["text"].iloc[0]
    assert "hello world" in processed["text"].iloc[1]

def test_dataset_preprocessing_duplicate_removal():
    data = pd.DataFrame([
        {"sender": "a", "subject": "b", "body": "c", "label": 0},
        {"sender": "a", "subject": "b", "body": "c", "label": 0}
    ])
    processed = preprocess_data(data)
    assert len(processed) == 1

def test_email_model_loading():
    app = create_app("testing")
    with app.app_context():
        # Depending on test environment, models might not exist. If they do, they should load.
        loaded = load_email_model_and_vectorizer()
        if loaded is not None:
            model, vectorizer = loaded
            assert "model" in model
            assert "labels" in model
            assert hasattr(vectorizer, "transform")

def test_email_prediction_with_ml():
    app = create_app("testing")
    with app.app_context():
        # Empty/malformed input
        res1 = analyze_email_content("", "", "")
        assert res1["input_type"] == "email"
        
        # Typical phishing
        res2 = analyze_email_content("bad@evil.com", "Urgent Update", "Click here now to verify your account http://fake.com")
        assert res2["prediction"] in ["phishing", "suspicious", "legitimate"]
        
        # The hybrid logic ensures we get model_source either as hybrid_engine
        assert res2["model_source"] == "hybrid_engine"
