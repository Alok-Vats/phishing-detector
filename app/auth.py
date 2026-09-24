"""Authentication and Authorization."""

from __future__ import annotations

import functools
import secrets
from flask import request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

from app.db.database import get_db, fetch_one, execute_query


def create_user(username: str, password: str, role: str = "User") -> str | None:
    """Create a new user and return their API token."""
    db = get_db()
    password_hash = generate_password_hash(password)
    api_token = secrets.token_urlsafe(32)
    try:
        execute_query(
            "INSERT INTO users (username, password_hash, role, api_token) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, api_token)
        )
        return api_token
    except Exception:
        return None


def verify_api_token(token: str) -> dict | None:
    """Verify API token and return user details."""
    user = fetch_one("SELECT id, username, role FROM users WHERE api_token = ?", (token,))
    if user:
        return dict(user)
    return None


def require_auth(f):
    """Decorator to require authentication via API token."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized", "message": "Missing or invalid Authorization header"}), 401
            
        token = auth_header.split(" ")[1]
        user = verify_api_token(token)
        if not user:
            return jsonify({"error": "Unauthorized", "message": "Invalid API token"}), 401
            
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_role(roles: list[str]):
    """Decorator to require a specific role."""
    def decorator(f):
        @functools.wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            if g.current_user["role"] not in roles:
                return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
