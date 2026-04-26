"""
WebSec Lab — Aplicación Flask
Sistema de demostración de seguridad web (Unidad 5)
"""
import os
import secrets
from datetime import timedelta
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from .extensions import db
from .models import User

load_dotenv()

# ── Extensiones globales ──────────────────────────────────────
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ── Configuración ─────────────────────────────────────────
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///websec.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Sesión segura
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=int(os.getenv("PERMANENT_SESSION_LIFETIME", 900)))

    # CSP Header configuración
    app.config["FERNET_KEY"] = os.getenv("FERNET_KEY", "")
    app.config["MFA_ISSUER"] = os.getenv("MFA_ISSUER", "WebSecLab")

    # ── Inicializar extensiones ───────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Debes iniciar sesión para acceder."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Cabeceras de seguridad (CSP, HSTS, etc.) ─────────────
    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ── Registrar Blueprints ──────────────────────────────────
    from .routes.auth import auth_bp
    from .routes.dashboard import dash_bp
    from .routes.demos import demo_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dash_bp, url_prefix="/")
    app.register_blueprint(demo_bp, url_prefix="/demo")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    # ── Crear tablas y datos iniciales ────────────────────────
    with app.app_context():
        db.create_all()
        _seed_initial_data()

    return app


def _seed_initial_data():
    """Crea usuarios y roles de demostración si no existen."""
    from .models import User, Role, AuditLog
    from .modules.security import hash_password

    if User.query.count() > 0:
        return

    # Crear roles
    roles_data = [
        {"name": "admin",     "description": "Administrador del sistema — acceso total"},
        {"name": "analyst",   "description": "Analista de seguridad — lectura de auditoría"},
        {"name": "user",      "description": "Usuario estándar — acceso mínimo"},
    ]
    roles = {}
    for rd in roles_data:
        r = Role(name=rd["name"], description=rd["description"])
        db.session.add(r)
        roles[rd["name"]] = r
    db.session.flush()

    # Crear usuarios demo
    users_data = [
        {"username": "admin",   "email": "admin@websec.lab",   "role": "admin",    "password": "Admin123!"},
        {"username": "analyst", "email": "analyst@websec.lab", "role": "analyst",  "password": "Analyst123!"},
        {"username": "demo",    "email": "demo@websec.lab",    "role": "user",     "password": "Demo1234!"},
    ]
    for ud in users_data:
        u = User(
            username=ud["username"],
            email=ud["email"],
            password_hash=hash_password(ud["password"]),
            role_id=roles[ud["role"]].id,
            mfa_enabled=False,
        )
        db.session.add(u)

    db.session.commit()
    print("[WebSec] Datos iniciales creados. Usuarios: admin / analyst / demo")
