"""Application factory for the phishing detection project."""

import secrets
from flask import Flask, session, request, abort

from app.config import get_config
from app.db.database import close_db, init_app as init_db_app
from app.routes import main_bp
from app.api import api_bp
from app.admin import admin_bp


import os

def create_app(config_name: str | None = None) -> Flask:
    """Create and configure the Flask application instance."""
    basedir = os.path.abspath(os.path.dirname(__file__))

    # 25-09-26
    # Commenting out and checking for vercel
    # app = Flask(
    #     __name__, 
    #     instance_relative_config=True,
    #     template_folder=os.path.join(basedir, 'templates'),
    #     static_folder=os.path.join(basedir, 'static')
    # )

    # Vercel fix
    # Therefore, use FLASK_INSTANCE_PATH when it is provided.
    #
    # On Vercel, set:
    # FLASK_INSTANCE_PATH=/tmp/phish-shield-instance
    #
    # Locally, if FLASK_INSTANCE_PATH is not set, Flask will use its normal instance directory.
    instance_path = os.environ.get("FLASK_INSTANCE_PATH")

    app = Flask(
        __name__,
        instance_path=instance_path,
        instance_relative_config=True,
        template_folder=os.path.join(basedir, 'templates'),
        static_folder=os.path.join(basedir, 'static')
    )

    app.config.from_object(get_config(config_name))

    # 25-09-26
    # Vercel Fix
    # Ensure Flask's instance directory exists for the SQLite database file.
    #app.instance_path and __import__("os").makedirs(app.instance_path, exist_ok=True)

    # Create the instance directory in the writable /tmp location when running on Vercel.
    os.makedirs(app.instance_path, exist_ok=True)
    
    init_db_app(app)
    app.teardown_appcontext(close_db)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)

    @app.before_request
    def ensure_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)

    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=session.get("csrf_token", ""))

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    register_error_handlers(app)
    return app


def register_error_handlers(app: Flask) -> None:
    """Attach shared application-level error handlers."""

    @app.errorhandler(404)
    def not_found(_error):
        return (
            {"error": "The requested resource was not found."}
            if _wants_json()
            else (app.jinja_env.get_template("error.html").render(message="Page not found."), 404)
        )

    @app.errorhandler(500)
    def internal_error(_error):
        return (
            {"error": "An unexpected server error occurred."}
            if _wants_json()
            else (
                app.jinja_env.get_template("error.html").render(
                    message="An unexpected server error occurred."
                ),
                500,
            )
        )


def _wants_json() -> bool:
    """Return True when the current request prefers JSON over HTML."""
    from flask import request

    return request.accept_mimetypes.best == "application/json"
