"""
Rutas de Autenticación — WebSec Lab
Login con MFA, registro, logout, configuración de 2FA
"""
from datetime import datetime, timezone, timedelta

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, session, jsonify)
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ..extensions import db
from ..models import User, Role
from ..modules.security import (
    verify_password, hash_password, check_password_strength,
    generate_mfa_secret, get_totp_uri, generate_qr_code, verify_totp,
    get_current_totp
)
from ..modules.audit import log_event
from .. import limiter

auth_bp = Blueprint("auth", __name__)

MAX_FAILED = 5          # Intentos antes de bloqueo
LOCKOUT_MINUTES = 15    # Minutos de bloqueo


# ─────────────────────────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dash.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        # Validación de usuario
        if not user or not user.is_active:
            log_event("LOGIN_FAILED", status="failure", details=f"Usuario '{username}' no encontrado")
            flash("Credenciales incorrectas.", "danger")
            return render_template("auth/login.html")

        # Verificar bloqueo
        if user.is_locked():
            remaining = (user.locked_until - datetime.now(timezone.utc)).seconds // 60
            log_event("LOGIN_BLOCKED", status="warning",
                      details=f"Cuenta bloqueada por {remaining} min más", user_id=user.id)
            flash(f"Cuenta bloqueada. Intenta en {remaining} minutos.", "danger")
            return render_template("auth/login.html")

        # Verificar contraseña
        if not verify_password(password, user.password_hash):
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                log_event("ACCOUNT_LOCKED", status="warning",
                          details=f"Cuenta bloqueada por {MAX_FAILED} intentos fallidos", user_id=user.id)
                flash(f"Demasiados intentos. Cuenta bloqueada por {LOCKOUT_MINUTES} minutos.", "danger")
            else:
                remaining = MAX_FAILED - user.failed_logins
                flash(f"Contraseña incorrecta. {remaining} intentos restantes.", "danger")
                log_event("LOGIN_FAILED", status="failure",
                          details=f"Contraseña incorrecta (intento #{user.failed_logins})", user_id=user.id)
            db.session.commit()
            return render_template("auth/login.html")

        # Login exitoso — resetear contador
        user.failed_logins = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        # Si tiene MFA, redirigir a verificación
        if user.mfa_enabled:
            session["pending_user_id"] = user.id
            session["mfa_verified"] = False
            log_event("LOGIN_MFA_REQUIRED", resource="/auth/mfa", status="success",
                      details="Contraseña correcta — pendiente MFA", user_id=user.id)
            return redirect(url_for("auth.mfa_verify"))

        # Login completo sin MFA
        login_user(user, remember=False)
        session["mfa_verified"] = True
        log_event("LOGIN_SUCCESS", status="success", details="Login completo", user_id=user.id)
        flash(f"Bienvenido, {user.username}!", "success")
        return redirect(url_for("dash.index"))

    return render_template("auth/login.html")


# ─────────────────────────────────────────────────────────────
#  MFA VERIFY
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/mfa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def mfa_verify():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()

        if verify_totp(user.mfa_secret, token):
            login_user(user, remember=False)
            session.pop("pending_user_id", None)
            session["mfa_verified"] = True
            log_event("MFA_SUCCESS", status="success", details="TOTP verificado correctamente", user_id=user.id)
            flash(f"Bienvenido, {user.username}! (MFA verificado ✓)", "success")
            return redirect(url_for("dash.index"))
        else:
            log_event("MFA_FAILED", status="failure", details="Token TOTP incorrecto", user_id=user.id)
            flash("Código incorrecto o expirado. Intenta de nuevo.", "danger")

    return render_template("auth/mfa_verify.html", username=user.username)


# ─────────────────────────────────────────────────────────────
#  CONFIGURAR MFA (activar 2FA para la cuenta)
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if request.method == "POST":
        action = request.form.get("action")
        token = request.form.get("token", "").strip()
        temp_secret = session.get("mfa_temp_secret")

        if action == "enable":
            if not temp_secret:
                flash("Error: no hay secret temporal. Recarga la página.", "danger")
                return redirect(url_for("auth.mfa_setup"))

            if verify_totp(temp_secret, token):
                current_user.mfa_secret = temp_secret
                current_user.mfa_enabled = True
                session.pop("mfa_temp_secret", None)
                db.session.commit()
                log_event("MFA_ENABLED", status="success", details="2FA activado por el usuario")
                flash("Autenticación de dos factores activada correctamente.", "success")
                return redirect(url_for("dash.index"))
            else:
                flash("Código incorrecto. Escanea el QR nuevamente.", "danger")

        elif action == "disable":
            if verify_totp(current_user.mfa_secret, token):
                current_user.mfa_enabled = False
                current_user.mfa_secret = None
                db.session.commit()
                log_event("MFA_DISABLED", status="warning", details="2FA desactivado por el usuario")
                flash("Autenticación de dos factores desactivada.", "info")
                return redirect(url_for("dash.index"))
            else:
                flash("Código incorrecto.", "danger")

    # GET — generar nuevo secret
    if not current_user.mfa_enabled:
        secret = generate_mfa_secret()
        session["mfa_temp_secret"] = secret
        issuer = "WebSecLab"
        uri = get_totp_uri(secret, current_user.username, issuer)
        qr_b64 = generate_qr_code(uri)
        # Para demo: mostrar el código actual
        current_code = get_current_totp(secret)
        return render_template("auth/mfa_setup.html",
                               qr_b64=qr_b64, secret=secret,
                               current_code=current_code, enabled=False)
    else:
        current_code = get_current_totp(current_user.mfa_secret)
        return render_template("auth/mfa_setup.html", enabled=True, current_code=current_code)


# ─────────────────────────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    log_event("LOGOUT", status="success", details="Sesión cerrada correctamente")
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("auth.login"))


# ─────────────────────────────────────────────────────────────
#  CAMBIAR CONTRASEÑA
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pwd = request.form.get("current_password", "")
        new_pwd = request.form.get("new_password", "")
        confirm_pwd = request.form.get("confirm_password", "")

        if not verify_password(current_pwd, current_user.password_hash):
            flash("Contraseña actual incorrecta.", "danger")
            return render_template("auth/change_password.html")

        if new_pwd != confirm_pwd:
            flash("Las contraseñas nuevas no coinciden.", "danger")
            return render_template("auth/change_password.html")

        strength = check_password_strength(new_pwd)
        if not strength["strong"]:
            flash("Contraseña débil: " + ", ".join(strength["issues"]), "warning")
            return render_template("auth/change_password.html", strength=strength)

        current_user.password_hash = hash_password(new_pwd)
        db.session.commit()
        log_event("PASSWORD_CHANGED", status="success", details="Contraseña actualizada")
        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for("dash.index"))

    return render_template("auth/change_password.html")


# ─────────────────────────────────────────────────────────────
#  API: Verificar fortaleza de contraseña (AJAX)
# ─────────────────────────────────────────────────────────────
@auth_bp.route("/api/password-strength", methods=["POST"])
def api_password_strength():
    pwd = request.json.get("password", "") if request.is_json else ""
    return jsonify(check_password_strength(pwd))
