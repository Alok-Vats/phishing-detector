"""Flask routes for the initial user-facing pages."""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

from app.services.email_service import analyze_email_content
from app.services.history_service import get_scan_history, save_scan_result
from app.services.prediction_service import analyze_url
from app.utils.validators import validate_email_input, validate_url_input


from flask import Blueprint, request, jsonify, render_template, current_app, session

main_bp = Blueprint("main", __name__)

@main_bp.before_request
def check_csrf():
    if current_app.testing:
        return
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            from flask import abort
            abort(400, "CSRF token missing or invalid.")


def _prefers_json_response() -> bool:
    """Return True when the request explicitly prefers JSON output."""
    return request.is_json or request.accept_mimetypes.best == "application/json"


@main_bp.get("/")
def index():
    """Render the landing page with URL and email analysis forms."""
    return render_template("index.html")


@main_bp.post("/analyze")
def analyze():
    """Handle UI form submissions and JSON requests for URL analysis."""
    payload_url = request.form.get("url", "").strip()

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        payload_url = str(payload.get("url", "")).strip()

    errors = validate_url_input(payload_url)
    if errors:
        if _prefers_json_response():
            return jsonify({"status": "error", "errors": errors}), 400

        return render_template("index.html", errors=errors, submitted_url=payload_url), 400

    result = analyze_url(payload_url)
    save_scan_result(result)
    if _prefers_json_response():
        return jsonify({"status": "success", "data": result}), 200

    return render_template("result.html", result=result)


@main_bp.get("/history")
def history():
    """Render a page showing recent saved scans."""
    records = get_scan_history()

    if _prefers_json_response():
        return jsonify({"status": "success", "data": records}), 200

    return render_template("history.html", records=records)


@main_bp.post("/analyze-email")
def analyze_email():
    """Handle UI form submissions and JSON requests for email analysis."""
    payload = request.get_json(silent=True) if request.is_json else None
    sender = str((payload or {}).get("sender", request.form.get("sender", ""))).strip()
    subject = str((payload or {}).get("subject", request.form.get("subject", ""))).strip()
    body = str((payload or {}).get("body", request.form.get("body", ""))).strip()

    errors = validate_email_input(sender, subject, body)
    if errors:
        if _prefers_json_response():
            return jsonify({"status": "error", "errors": errors}), 400

        return (
            render_template(
                "index.html",
                email_errors=errors,
                submitted_sender=sender,
                submitted_subject=subject,
                submitted_body=body,
            ),
            400,
        )

    result = analyze_email_content(sender, subject, body)
    save_scan_result(result)
    if _prefers_json_response():
        return jsonify({"status": "success", "data": result}), 200

    return render_template("result.html", result=result)


@main_bp.get("/health")
def health_check():
    """Expose a lightweight health endpoint for local verification."""
    return jsonify({"status": "ok"}), 200
