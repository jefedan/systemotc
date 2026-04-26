"""
Módulo de seguridad central — WebSec Lab
Implementa: hash de contraseñas, MFA, cifrado, integridad, RBAC
"""
import os
import io
import hashlib
import hmac
import base64
import secrets
from datetime import datetime, timezone
from functools import wraps

import bcrypt
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, request, abort, flash, redirect, url_for
from flask_login import current_user


# ══════════════════════════════════════════════════════════════
#  1. HASH SEGURO DE CONTRASEÑAS (bcrypt)
# ══════════════════════════════════════════════════════════════

def hash_password(plaintext: str) -> str:
    """
    Hash seguro con bcrypt (cost factor 12).
    Incluye salt aleatorio automáticamente.
    NUNCA almacenar contraseñas en texto plano.
    """
    if not plaintext or len(plaintext) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plaintext.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verifica contraseña contra hash bcrypt. Timing-safe."""
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def check_password_strength(password: str) -> dict:
    """
    Evalúa fortaleza de contraseña.
    Retorna dict con score y lista de requisitos faltantes.
    """
    issues = []
    if len(password) < 8:
        issues.append("Mínimo 8 caracteres")
    if not any(c.isupper() for c in password):
        issues.append("Al menos una mayúscula")
    if not any(c.islower() for c in password):
        issues.append("Al menos una minúscula")
    if not any(c.isdigit() for c in password):
        issues.append("Al menos un número")
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        issues.append("Al menos un carácter especial")
    score = max(0, 100 - len(issues) * 20)
    return {"score": score, "issues": issues, "strong": len(issues) == 0}


# ══════════════════════════════════════════════════════════════
#  2. AUTENTICACIÓN MULTIFACTOR (TOTP — RFC 6238)
# ══════════════════════════════════════════════════════════════

def generate_mfa_secret() -> str:
    """Genera secret TOTP aleatorio (base32, 32 chars)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "WebSecLab") -> str:
    """Genera URI para código QR de autenticadores (Google Authenticator, Authy)."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(uri: str) -> str:
    """Genera imagen QR en base64 PNG para insertar en HTML."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


def verify_totp(secret: str, token: str) -> bool:
    """
    Verifica token TOTP con ventana de ±1 intervalo (30s).
    Previene errores por desincronización de reloj.
    """
    if not secret or not token:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token.strip(), valid_window=1)


def get_current_totp(secret: str) -> str:
    """Retorna el TOTP actual (para demo/testing)."""
    return pyotp.TOTP(secret).now()


# ══════════════════════════════════════════════════════════════
#  3. CIFRADO DE DATOS SENSIBLES (Fernet AES-128-CBC)
# ══════════════════════════════════════════════════════════════

def _get_fernet() -> Fernet:
    """Obtiene instancia Fernet con la clave configurada."""
    key = current_app.config.get("FERNET_KEY", "")
    if not key:
        # Generar una clave temporal por sesión (no persistente — solo para demo)
        if not hasattr(current_app, "_demo_fernet_key"):
            current_app._demo_fernet_key = Fernet.generate_key()
        key = current_app._demo_fernet_key
    else:
        key = key.encode() if isinstance(key, str) else key
    return Fernet(key)


def encrypt_data(plaintext: str) -> str:
    """
    Cifra datos con Fernet (AES-128-CBC + HMAC-SHA256).
    Retorna token cifrado en base64.
    """
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_data(token: str) -> str | None:
    """
    Descifra token Fernet. Retorna None si el token es inválido o fue manipulado.
    Fernet verifica integridad automáticamente (HMAC).
    """
    try:
        f = _get_fernet()
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


# ══════════════════════════════════════════════════════════════
#  4. INTEGRIDAD DE DATOS (SHA-256 + HMAC)
# ══════════════════════════════════════════════════════════════

def compute_hash(data: str) -> str:
    """SHA-256 del dato. Detecta modificaciones."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_hmac(data: str, key: str = None) -> str:
    """
    HMAC-SHA256. Más seguro que SHA simple para verificación de integridad
    porque requiere la clave secreta (previene forjado).
    """
    if key is None:
        key = current_app.config["SECRET_KEY"]
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_integrity(data: str, expected_hash: str) -> bool:
    """Verifica integridad comparando hashes de forma timing-safe."""
    actual = compute_hash(data)
    return hmac.compare_digest(actual, expected_hash)


def compute_audit_chain_hash(entry_data: str, prev_hash: str) -> str:
    """
    Hash encadenado para el registro de auditoría (chain-of-custody).
    Cada entrada incluye el hash de la anterior, formando una cadena
    que hace imposible modificar entradas anteriores sin ser detectado.
    """
    combined = f"{prev_hash}:{entry_data}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════
#  5. CONTROL DE ACCESO RBAC — Decoradores
# ══════════════════════════════════════════════════════════════

def require_role(*roles):
    """
    Decorador RBAC: requiere que el usuario tenga uno de los roles indicados.
    Implementa principio de mínimo privilegio.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role.name not in roles:
                from .audit import log_event
                log_event(
                    action="ACCESS_DENIED",
                    resource=request.path,
                    status="failure",
                    details=f"Rol '{current_user.role.name}' no autorizado. Requerido: {roles}"
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission: str):
    """
    Decorador de permiso granular RBAC.
    Ej: @require_permission('can_view_audit')
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_permission(permission):
                from .audit import log_event
                log_event(
                    action="PERMISSION_DENIED",
                    resource=request.path,
                    status="failure",
                    details=f"Permiso '{permission}' denegado para rol '{current_user.role.name}'"
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_mfa_verified():
    """
    Decorador: requiere que el usuario haya completado la verificación MFA
    en la sesión actual.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import session
            if not current_user.is_authenticated:
                abort(401)
            if current_user.mfa_enabled and not session.get("mfa_verified"):
                flash("Se requiere verificación MFA para acceder a esta sección.", "warning")
                return redirect(url_for("auth.mfa_verify"))
            return f(*args, **kwargs)
        return decorated
    return decorator
