"""Admin UI Blueprint."""

from __future__ import annotations

import functools
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
from werkzeug.security import check_password_hash

from app.db.database import fetch_one, fetch_all, execute_query
from app.services.history_service import get_scan_history, get_scan_by_id
from app.services.dashboard_service import get_dashboard_metrics
from app.auth import create_user

from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify, current_app

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.before_request
def check_csrf():
    if current_app.testing:
        return
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        token = request.form.get("csrf_token")
        if not token or token != session.get("csrf_token"):
            from flask import abort
            abort(400, "CSRF token missing or invalid.")


def login_required(role=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("admin.login", next=request.url))
            if role and session.get("user_role") != role:
                flash("Insufficient privileges.", "error")
                return redirect(url_for("admin.dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["user_role"] = user["role"]
            next_url = request.args.get("next") or url_for("admin.dashboard")
            return redirect(next_url)
        flash("Invalid credentials.", "error")
    
    # Auto-create an admin if none exists for testing
    admin = fetch_one("SELECT id FROM users WHERE role = 'Admin'")
    if not admin:
        create_user("admin", "admin123", "Admin")
        flash("Created default admin user: admin / admin123", "info")
        
    return render_template("admin/login.html")


@admin_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


@admin_bp.route("/dashboard")
@login_required()
def dashboard():
    metrics = get_dashboard_metrics()
    return render_template("admin/dashboard.html", metrics=metrics)


@admin_bp.route("/history")
@login_required()
def history_view():
    search = request.args.get("q", "")
    input_type = request.args.get("type", "")
    classification = request.args.get("classification", "")
    page = int(request.args.get("page", 1))
    limit = 20
    offset = (page - 1) * limit
    
    records = get_scan_history(
        limit=limit,
        offset=offset,
        search=search,
        input_type=input_type,
        classification=classification
    )
    
    return render_template(
        "admin/history.html", 
        records=records, 
        page=page, 
        q=search, 
        type=input_type, 
        classification=classification
    )


@admin_bp.route("/history/export")
@login_required()
def export_history():
    import csv, io
    from flask import Response
    import json
    
    fmt = request.args.get("format", "csv")
    
    # Apply identical filters as view (ignoring pagination for export)
    search = request.args.get("q", "")
    input_type = request.args.get("type", "")
    classification = request.args.get("classification", "")
    
    records = get_scan_history(limit=1000, offset=0, search=search, input_type=input_type, classification=classification)
    
    if fmt == "json":
        return jsonify({"status": "success", "data": records})
    
    # Default to CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Date", "Type", "Target", "Classification", "Confidence", "Engine"])
    
    for r in records:
        writer.writerow([
            r.get("id", ""),
            r.get("created_at", ""),
            r.get("input_type", ""),
            r.get("normalized_value", ""),
            r.get("prediction", ""),
            f"{r.get('confidence', 0)*100:.1f}%",
            r.get("model_source", "")
        ])
        
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=scan_history.csv"}
    )


@admin_bp.route("/scan/<int:scan_id>")
@login_required()
def scan_detail(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Not found", 404
    return render_template("admin/scan_detail.html", scan=scan)


@admin_bp.route("/users", methods=["GET", "POST"])
@login_required(role="Admin")
def manage_users():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            create_user(
                request.form.get("username"),
                request.form.get("password"),
                request.form.get("role", "User")
            )
            flash("User created successfully.", "success")
        elif action == "delete":
            user_id = request.form.get("user_id")
            execute_query("DELETE FROM users WHERE id = ?", (user_id,))
            flash("User deleted.", "success")
            
        return redirect(url_for("admin.manage_users"))
        
    users = fetch_all("SELECT id, username, role, created_at FROM users")
    return render_template("admin/users.html", users=users)
