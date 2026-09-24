"""REST API routes v1."""

from __future__ import annotations

import json
from flask import Blueprint, jsonify, request, current_app

from app.auth import require_auth, require_role
from app.services.prediction_service import analyze_url
from app.services.email_service import analyze_email_content
from app.services.history_service import get_scan_history, save_scan_result
from app.utils.validators import validate_url_input, validate_email_input
from app.db.database import fetch_one

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Request size limits
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

@api_bp.before_request
def check_payload_size():
    if request.content_length and request.content_length > MAX_CONTENT_LENGTH:
        return jsonify({"error": "Payload Too Large"}), 413


@api_bp.post("/analyze/url")
@require_auth
def api_analyze_url():
    """Analyze a URL."""
    if not request.is_json:
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400
        
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    
    errors = validate_url_input(url)
    if errors:
        return jsonify({"error": "Validation Error", "details": errors}), 400
        
    try:
        result = analyze_url(url)
        save_scan_result(result)
        return jsonify({"status": "success", "data": result}), 200
    except Exception as e:
        # Secure logging should go to a logger in production
        current_app.logger.error(f"URL analysis error: {e}")
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500


@api_bp.post("/analyze/email")
@require_auth
def api_analyze_email():
    """Analyze an email."""
    if not request.is_json:
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400
        
    payload = request.get_json(silent=True) or {}
    sender = str(payload.get("sender", "")).strip()
    subject = str(payload.get("subject", "")).strip()
    body = str(payload.get("body", "")).strip()
    
    errors = validate_email_input(sender, subject, body)
    if errors:
        return jsonify({"error": "Validation Error", "details": errors}), 400
        
    try:
        result = analyze_email_content(sender, subject, body)
        save_scan_result(result)
        return jsonify({"status": "success", "data": result}), 200
    except Exception as e:
        current_app.logger.error(f"Email analysis error: {e}")
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500


@api_bp.get("/scan/<int:scan_id>")
@require_auth
def api_get_scan(scan_id):
    """Retrieve a specific scan by ID."""
    row = fetch_one("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
    if not row:
        return jsonify({"error": "Not Found", "message": "Scan not found"}), 404
        
    data = dict(row)
    # Parse JSON fields
    for field in ["reasons", "features", "model_versions", "threat_intel_results"]:
        if data.get(field):
            try:
                data[field] = json.loads(data[field])
            except:
                pass
                
    return jsonify({"status": "success", "data": data}), 200


@api_bp.get("/history")
@require_role(["Admin", "Analyst"])
def api_get_history():
    """Retrieve scan history. Requires Admin or Analyst role."""
    limit = min(int(request.args.get("limit", 50)), 100)
    records = get_scan_history(limit=limit)
    return jsonify({"status": "success", "data": records}), 200
