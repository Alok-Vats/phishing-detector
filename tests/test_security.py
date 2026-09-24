"""Security regression tests."""

import pytest
from app import create_app
from app.ml.model_loader import load_model, load_email_model_and_vectorizer

@pytest.fixture
def client():
    app = create_app("testing")
    return app.test_client()

def test_security_headers_present(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert "Content-Security-Policy" in res.headers
    assert "X-Frame-Options" in res.headers
    assert "Strict-Transport-Security" in res.headers
    assert res.headers["X-Frame-Options"] == "SAMEORIGIN"

def test_payload_size_limit(client):
    app = create_app("testing")
    with app.test_client() as c:
        # Send an oversized payload > 10MB
        large_payload = b"a" * (11 * 1024 * 1024)
        res = c.post("/api/v1/analyze/url", data=large_payload, headers={"Content-Type": "application/json"})
        assert res.status_code == 413 # Payload Too Large

def test_path_traversal_model_loader():
    # Attempt to load a model outside the models directory
    app = create_app("testing")
    with app.app_context():
        with pytest.raises(ValueError, match="Unsafe model path detected."):
            load_model("../../../etc/passwd")
            
        with pytest.raises(ValueError, match="Unsafe model path detected."):
            load_email_model_and_vectorizer("../../../etc/passwd", "../../../etc/passwd")

def test_csrf_protection():
    app = create_app("testing")
    app.testing = False
    
    with app.test_client() as c:
        # Missing CSRF
        res_missing = c.post("/admin/login", data={"username": "admin", "password": "pw"})
        assert res_missing.status_code == 400
        
        # Invalid CSRF
        res_invalid = c.post("/admin/login", data={"username": "admin", "password": "pw", "csrf_token": "bad_token"})
        assert res_invalid.status_code == 400
        
        # Valid CSRF + Normal authenticated request
        c.get("/admin/login")
        from flask import session
        with c.session_transaction() as sess:
            valid_token = sess["csrf_token"]
            
        res_valid = c.post("/admin/login", data={"username": "admin", "password": "pw", "csrf_token": valid_token})
        assert res_valid.status_code == 200
        assert b"Invalid credentials" in res_valid.data

def test_model_integrity_verification(tmp_path):
    from app.ml.model_loader import verify_integrity
    from pathlib import Path
    import json
    import hashlib
    
    base_dir = tmp_path / "models"
    base_dir.mkdir()
    
    model_path = base_dir / "test_model.pkl"
    model_path.write_bytes(b"trusted content")
    
    h = hashlib.sha256(b"trusted content").hexdigest()
    
    trusted_file = base_dir / "trusted_hashes.json"
    trusted_file.write_text(json.dumps({"test_model.pkl": h}))
    
    # 1. Valid trusted model
    verify_integrity(model_path, base_dir) # Should not raise
    
    # 2. Modified model (Incorrect hash)
    model_path.write_bytes(b"tampered content")
    with pytest.raises(ValueError, match="integrity verification failed"):
        verify_integrity(model_path, base_dir)
        
    # 3. Missing manifest entry
    trusted_file.write_text(json.dumps({"other.pkl": "123"}))
    with pytest.raises(ValueError, match="not explicitly trusted"):
        verify_integrity(model_path, base_dir)
        
    # 4. Missing manifest entirely
    trusted_file.unlink()
    with pytest.raises(ValueError, match="manifest not found"):
        verify_integrity(model_path, base_dir)

