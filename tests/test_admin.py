import pytest
from app import create_app
from app.db.database import execute_query, fetch_one
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app = create_app("testing")
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        execute_query("DELETE FROM users")
        execute_query("DELETE FROM scan_history")
        
        # Insert admin user
        hash = generate_password_hash("adminpass")
        execute_query("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'Admin')", (hash,))
        
        # Insert test data
        execute_query("INSERT INTO scan_history (input_type, input_value, normalized_value, prediction, confidence, model_source, reasons, features) VALUES ('url', 'http://test.com', 'test.com', 'phishing', 0.9, 'test_model', '[]', '{}')")
        
    return app.test_client()

def test_admin_dashboard_unauthorized(client):
    res = client.get("/admin/dashboard")
    assert res.status_code == 302 # Redirect to login

def test_admin_login(client):
    res = client.post("/admin/login", data={"username": "admin", "password": "adminpass"}, follow_redirects=True)
    assert res.status_code == 200
    assert b"Dashboard" in res.data
    assert b"Phishing Detections" in res.data

def test_admin_dashboard_metrics(client):
    client.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    res = client.get("/admin/dashboard")
    assert res.status_code == 200
    assert b"Total Scans" in res.data

def test_admin_history_filters(client):
    client.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    res = client.get("/admin/history?type=url&classification=phishing")
    assert res.status_code == 200
    assert b"test.com" in res.data

def test_admin_users_access(client):
    client.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    res = client.get("/admin/users")
    assert res.status_code == 200
    assert b"Manage Users" in res.data
    
    # Try to create user
    res2 = client.post("/admin/users", data={"action": "create", "username": "new_analyst", "password": "pw", "role": "Analyst"}, follow_redirects=True)
    assert res2.status_code == 200
    
    with client.application.app_context():
        user = fetch_one("SELECT * FROM users WHERE username = 'new_analyst'")
        assert user is not None
        assert user["role"] == "Analyst"
