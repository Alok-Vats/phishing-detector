import pytest
import json
from app import create_app
from app.auth import create_user
from app.db.database import get_db, execute_query
from unittest.mock import patch

@pytest.fixture
def client():
    app = create_app("testing")
    with app.app_context():
        # Ensure DB is fresh
        execute_query("DELETE FROM users")
        execute_query("DELETE FROM scan_history")
        
        # Seed test user
        token = create_user("apiuser", "pass", "Analyst")
        app.config["TEST_TOKEN"] = token
        
    return app.test_client()

def get_headers(client):
    return {"Authorization": f"Bearer {client.application.config['TEST_TOKEN']}", "Content-Type": "application/json"}

def test_api_auth_missing(client):
    res = client.post("/api/v1/analyze/url", json={"url": "http://test.com"})
    assert res.status_code == 401
    assert "Unauthorized" in res.json["error"]

def test_api_analyze_url_success(client):
    with patch("app.api.analyze_url") as mock_analyze:
        mock_analyze.return_value = {
            "prediction": "legitimate",
            "confidence": 0.99,
            "input_type": "url",
            "url": "http://google.com"
        }
        res = client.post("/api/v1/analyze/url", headers=get_headers(client), json={"url": "http://google.com"})
        
        assert res.status_code == 200
        assert res.json["status"] == "success"
        assert res.json["data"]["prediction"] == "legitimate"

def test_api_analyze_url_invalid(client):
    res = client.post("/api/v1/analyze/url", headers=get_headers(client), json={"url": "not_a_url"})
    assert res.status_code == 400
    assert "Validation Error" in res.json["error"]

def test_api_analyze_email_success(client):
    with patch("app.api.analyze_email_content") as mock_analyze:
        mock_analyze.return_value = {
            "prediction": "phishing",
            "confidence": 0.85,
            "input_type": "email"
        }
        res = client.post("/api/v1/analyze/email", headers=get_headers(client), json={
            "sender": "bad@evil.com",
            "subject": "Urgent",
            "body": "Click here"
        })
        
        assert res.status_code == 200
        assert res.json["status"] == "success"
        assert res.json["data"]["prediction"] == "phishing"

def test_api_history_authorization(client):
    # Create normal user
    with client.application.app_context():
        normal_token = create_user("normal", "pass", "User")
        
    res = client.get("/api/v1/history", headers={"Authorization": f"Bearer {normal_token}"})
    assert res.status_code == 403 # Forbidden for normal user

    # Analyst token
    res2 = client.get("/api/v1/history", headers=get_headers(client))
    assert res2.status_code == 200

def test_api_get_scan_not_found(client):
    res = client.get("/api/v1/scan/9999", headers=get_headers(client))
    assert res.status_code == 404

def test_api_payload_too_large(client):
    large_payload = {"url": "http://x.com/" + "a" * (10 * 1024 * 1024 + 10)}
    res = client.post("/api/v1/analyze/url", headers=get_headers(client), json=large_payload)
    assert res.status_code == 413

def test_api_provider_failure_graceful(client):
    from unittest.mock import patch
    with patch("app.api.analyze_url", side_effect=Exception("Database Timeout")):
        res = client.post("/api/v1/analyze/url", headers=get_headers(client), json={"url": "http://google.com"})
        
        assert res.status_code == 500
        assert res.json["error"] == "Internal Server Error"
        assert "An unexpected error occurred" in res.json["message"]
