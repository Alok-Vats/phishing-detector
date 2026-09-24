import pytest
from app import create_app
from app.db.database import execute_query
from werkzeug.security import generate_password_hash
import json
import csv
import io

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
        
    return app.test_client()

def test_export_unauthorized(client):
    res = client.get("/admin/history/export?format=json")
    assert res.status_code == 302 # redirect to login

def test_export_empty_dataset(client):
    client.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    res = client.get("/admin/history/export?format=json")
    assert res.status_code == 200
    data = json.loads(res.data)
    assert len(data["data"]) == 0

def test_export_csv_and_json(client):
    client.post("/admin/login", data={"username": "admin", "password": "adminpass"})
    
    # Add a scan
    with client.application.app_context():
        execute_query("INSERT INTO scan_history (input_type, input_value, normalized_value, prediction, confidence, model_source, reasons, features) VALUES ('url', 'http://test.com', 'test.com', 'phishing', 0.9, 'test_model', '[]', '{}')")
    
    # JSON Export
    res_json = client.get("/admin/history/export?format=json")
    assert res_json.status_code == 200
    data = json.loads(res_json.data)
    assert len(data["data"]) == 1
    assert data["data"][0]["normalized_value"] == "test.com"
    
    # CSV Export
    res_csv = client.get("/admin/history/export?format=csv")
    assert res_csv.status_code == 200
    assert res_csv.mimetype == "text/csv"
    assert b"test.com" in res_csv.data
    assert b"90.0%" in res_csv.data
    
    # Test filters applying to export
    res_filter = client.get("/admin/history/export?format=json&classification=legitimate")
    data_filter = json.loads(res_filter.data)
    assert len(data_filter["data"]) == 0
