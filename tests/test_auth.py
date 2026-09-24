import pytest
from app.auth import create_user, verify_api_token
from app.db.database import get_db, execute_query
from app import create_app

@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        # Clean users table
        execute_query("DELETE FROM users")
    return app

def test_create_user(app):
    with app.app_context():
        token = create_user("testuser", "password123", "User")
        assert token is not None
        assert len(token) > 20
        
        # Verify user
        user = verify_api_token(token)
        assert user is not None
        assert user["username"] == "testuser"
        assert user["role"] == "User"

def test_verify_invalid_token(app):
    with app.app_context():
        user = verify_api_token("invalid_token")
        assert user is None

def test_create_duplicate_user(app):
    with app.app_context():
        t1 = create_user("testuser", "pwd")
        assert t1 is not None
        t2 = create_user("testuser", "pwd2")
        assert t2 is None # constraint failed
