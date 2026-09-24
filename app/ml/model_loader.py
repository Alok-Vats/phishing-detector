"""Utilities for loading a trained phishing URL model safely."""

from __future__ import annotations

from pathlib import Path

import hashlib
import json
import joblib
from flask import current_app


def verify_integrity(filepath: Path, base_models_dir: Path) -> None:
    """Verify SHA-256 hash of the artifact against the trusted manifest."""
    trusted_file = base_models_dir / "trusted_hashes.json"
    if not trusted_file.exists():
        raise ValueError("Trusted hashes manifest not found. Integrity verification impossible.")
    
    with open(trusted_file, "r") as f:
        trusted = json.load(f)
        
    basename = filepath.name
    if basename not in trusted:
        raise ValueError("Model artifact is not explicitly trusted in the manifest.")
        
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
            
    if h.hexdigest() != trusted[basename]:
        raise ValueError("Model artifact integrity verification failed (hash mismatch).")

def load_model(model_path: str | None = None) -> dict | None:
    """Load a saved model bundle and return None when no artifact exists."""
    base_models_dir = Path(__file__).resolve().parent.parent.parent / "models"
    resolved_path = Path(model_path or current_app.config["MODEL_PATH"]).resolve()
    
    # Path traversal protection
    if not str(resolved_path).startswith(str(base_models_dir)):
        raise ValueError("Unsafe model path detected.")
        
    if not resolved_path.exists():
        return None

    # Cryptographic integrity check
    verify_integrity(resolved_path, base_models_dir)

    model_bundle = joblib.load(resolved_path)
    if not isinstance(model_bundle, dict):
        raise ValueError("Model artifact format is invalid.")

    required_keys = {"model", "feature_names", "labels"}
    missing = required_keys - set(model_bundle.keys())
    if missing:
        missing_keys = ", ".join(sorted(missing))
        raise ValueError(f"Model artifact is missing keys: {missing_keys}")

    return model_bundle

def load_email_model_and_vectorizer(model_path: str | None = None, vectorizer_path: str | None = None) -> tuple | None:
    """Load the email NLP model and TF-IDF vectorizer."""
    base_models_dir = Path(__file__).resolve().parent.parent.parent / "models"
    resolved_model_path = Path(model_path or current_app.config.get("EMAIL_MODEL_PATH", Path("models/phishing_email_model.pkl"))).resolve()
    resolved_vect_path = Path(vectorizer_path or current_app.config.get("EMAIL_VECTORIZER_PATH", Path("models/phishing_email_vectorizer.pkl"))).resolve()
    
    # Path traversal protection
    if not str(resolved_model_path).startswith(str(base_models_dir)) or not str(resolved_vect_path).startswith(str(base_models_dir)):
        raise ValueError("Unsafe model path detected.")
    
    if not resolved_model_path.exists() or not resolved_vect_path.exists():
        return None

    # Cryptographic integrity check for both artifacts
    verify_integrity(resolved_model_path, base_models_dir)
    verify_integrity(resolved_vect_path, base_models_dir)

    try:
        model_bundle = joblib.load(resolved_model_path)
        vectorizer = joblib.load(resolved_vect_path)
        return model_bundle, vectorizer
    except Exception:
        return None
