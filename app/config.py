"""Application configuration classes."""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration shared by all environments."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH", str(BASE_DIR / "instance" / "phishing_detector.sqlite3")
    )
    MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "phishing_url_model.pkl"))
    METRICS_PATH = os.getenv(
        "METRICS_PATH", str(BASE_DIR / "models" / "phishing_url_model_metrics.json")
    )
    DEBUG = False
    TESTING = False
    
    # Security configs
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit globally
    
    # Threat Intelligence Config
    THREAT_INTEL_TIMEOUT_SECONDS = int(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", 3))
    THREAT_INTEL_URLHAUS_ENABLED = os.getenv("THREAT_INTEL_URLHAUS_ENABLED", "True").lower() == "true"
    THREAT_INTEL_VIRUSTOTAL_ENABLED = os.getenv("THREAT_INTEL_VIRUSTOTAL_ENABLED", "True").lower() == "true"
    THREAT_INTEL_VIRUSTOTAL_API_KEY = os.getenv("THREAT_INTEL_VIRUSTOTAL_API_KEY", "")


class DevelopmentConfig(Config):
    """Configuration for local development."""

    DEBUG = True


class TestingConfig(Config):
    """Configuration for automated tests."""

    TESTING = True
    DATABASE_PATH = os.getenv("TEST_DATABASE_PATH", str(BASE_DIR / "instance" / "test.sqlite3"))


class ProductionConfig(Config):
    """Configuration for production-like deployments."""

    pass


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(config_name: str | None = None) -> type[Config]:
    """Return the configuration class matching the requested environment."""
    selected_name = config_name or os.getenv("FLASK_ENV", "development")
    return CONFIG_MAP.get(selected_name, DevelopmentConfig)
