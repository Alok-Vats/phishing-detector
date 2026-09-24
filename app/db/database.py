"""SQLite database utilities for the Flask app."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

from flask import current_app, g

def is_postgres():
    return bool(os.getenv("DATABASE_URL"))


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS blacklist_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_type TEXT NOT NULL,
    input_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    prediction TEXT NOT NULL,
    confidence REAL NOT NULL,
    matched_list TEXT,
    model_source TEXT NOT NULL,
    reasons TEXT NOT NULL,
    features TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'User',
    api_token TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    user_id INTEGER,
    is_correct BOOLEAN NOT NULL,
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scan_history(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


def get_db():
    """Return a request-scoped database connection."""
    if "db" not in g:
        if is_postgres():
            if psycopg2 is None:
                raise RuntimeError("psycopg2 is required for PostgreSQL but not installed.")
            g.db = psycopg2.connect(os.getenv("DATABASE_URL"))
        else:
            db_path = Path(current_app.config["DATABASE_PATH"])
            db_path.parent.mkdir(parents=True, exist_ok=True)
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error=None) -> None:
    """Close the current request's database connection if one exists."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create the initial database schema."""
    db = get_db()
    schema = SCHEMA_SQL
    
    if is_postgres():
        # Quick rewrite for Postgres syntax
        schema = schema.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        cursor = db.cursor()
        cursor.execute(schema)
        
        try:
            cursor.execute("ALTER TABLE scan_history ADD COLUMN model_versions TEXT;")
        except psycopg2.Error:
            db.rollback()
        
        try:
            cursor.execute("ALTER TABLE scan_history ADD COLUMN threat_intel_results TEXT;")
        except psycopg2.Error:
            db.rollback()
            
        db.commit()
        cursor.close()
    else:
        db.executescript(schema)
        try:
            db.execute("ALTER TABLE scan_history ADD COLUMN model_versions TEXT;")
        except sqlite3.OperationalError:
            pass
            
        try:
            db.execute("ALTER TABLE scan_history ADD COLUMN threat_intel_results TEXT;")
        except sqlite3.OperationalError:
            pass
        db.commit()


def init_app(app) -> None:
    """Initialize database state during application startup."""
    with app.app_context():
        init_db()


def fetch_one(query: str, params: tuple = ()):
    """Fetch a single row from the database."""
    db = get_db()
    if is_postgres():
        query = query.replace("?", "%s")
        cursor = db.cursor(cursor_factory=DictCursor)
        cursor.execute(query, params)
        row = cursor.fetchone()
        cursor.close()
        return row
    else:
        cursor = db.execute(query, params)
        row = cursor.fetchone()
        cursor.close()
        return row


def fetch_all(query: str, params: tuple = ()):
    """Fetch all rows for a read query."""
    db = get_db()
    if is_postgres():
        query = query.replace("?", "%s")
        cursor = db.cursor(cursor_factory=DictCursor)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return rows
    else:
        cursor = db.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return rows


def execute_query(query: str, params: tuple = ()) -> None:
    """Execute a write query and commit it immediately."""
    db = get_db()
    if is_postgres():
        query = query.replace("?", "%s")
        cursor = db.cursor()
        cursor.execute(query, params)
        db.commit()
        cursor.close()
    else:
        db.execute(query, params)
        db.commit()
