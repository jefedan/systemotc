"""
Rutas de Demostración — WebSec Lab
5 demos interactivos de seguridad web
"""
from flask import Blueprint, render_template, request, jsonify, session
from flask_login import login_required, current_user

from ..modules.security import (
    hash_password, verify_password, check_password_strength,
    encrypt_data, decrypt_data, compute_hash, compute_hmac,
    verify_integrity, require_permission, require_mfa_verified,
    get_current_totp, verify_totp
)
from ..modules.audit import log_event, verify_audit_chain
from ..models import AuditLog, User, SecretData, Role
from ..extensions import db

demo_bp = Blueprint("demo", __name__)


# ══════════════════════════════════════════════════════════════
#  DEMO 1 — Modelos de Seguridad Web (SOP / CSP / Headers)
# ══════════════════════════════════════════════════════════════
@demo_bp.route("/1-web-security-model")
@login_required
def demo1():
    log_event("DEMO_ACCESS", resource="/demo/1", status="success", details="Demo 1: Modelos de seguridad web")
    # Mostrar las cabeceras de seguridad activas
    from flask import current_app
    headers_info = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000 (activo en HTTPS)",
    }
    return render_template("demos/demo1.html", headers_info=headers_info)


@demo_bp.route("/api/test-sop", methods=["POST"])
@login_required
def test_sop():
    """Simula verificación Same-Origin Policy."""
    origin = request.json.get("origin", "")
    allowed_origins = ["https://websec.lab", "http://localhost:5000", "http://127.0.0.1:5000"]
    is_allowed = any(origin.startswith(ao) for ao in allowed_origins)
    log_event("SOP_TEST", resource="/demo/api/test-sop", status="success" if is_allowed else "failure",
              details=f"Origen probado: {origin}")
    return jsonify({
        "origin": origin,
        "allowed": is_allowed,
        "reason": "Origen en lista blanca CORS" if is_allowed else "Violación SOP: origen no permitido",
        "policy": "Same-Origin Policy activa"
    })


# ══════════════════════════════════════════════════════════════
#  DEMO 2 — Gestión de Sesiones
# ══════════════════════════════════════════════════════════════
@demo_bp.route("/2-session-management")
@login_required
def demo2():
    log_event("DEMO_ACCESS", resource="/demo/2", status="success", details="Demo 2: Gestión de sesiones")
    session_info = {
        "session_id_preview": "*** Oculto — almacenado en cookie HttpOnly ***",
        "cookie_flags": {
            "HttpOnly": True,
            "Secure": "Activo en HTTPS",
            "SameSite": "Strict",
        },
        "mfa_verified": session.get("mfa_verified", False),
        "user_role": current_user.role.name,
        "mfa_enabled": current_user.mfa_enabled,
    }
    return render_template("demos/demo2.html", session_info=session_info)


@demo_bp.route("/api/session-info")
@login_required
def api_session_info():
    """Retorna información de sesión sin exponer el token."""
    return jsonify({
        "authenticated": current_user.is_authenticated,
        "username": current_user.username,
        "role": current_user.role.name,
        "mfa_verified": session.get("mfa_verified", False),
        "mfa_enabled": current_user.mfa_enabled,
        "cookie_httponly": True,
        "cookie_samesite": "Strict",
        "note": "Session ID nunca expuesto al JavaScript (HttpOnly)"
    })


# ══════════════════════════════════════════════════════════════
#  DEMO 3 — Vulnerabilidades y Defensas (SQLi, XSS, Hash)
# ══════════════════════════════════════════════════════════════
@demo_bp.route("/3-vulnerabilities")
@login_required
def demo3():
    log_event("DEMO_ACCESS", resource="/demo/3", status="success", details="Demo 3: Vulnerabilidades y defensas")
    return render_template("demos/demo3.html")


@demo_bp.route("/api/demo-sqli", methods=["POST"])
@login_required
def demo_sqli():
    """
    Demuestra SQLi SEGURO vs INSEGURO (sin ejecutar código peligroso).
    Solo muestra la diferencia conceptual y técnica.
    """
    username = request.json.get("username", "")
    mode = request.json.get("mode", "safe")

    if mode == "unsafe":
        # VULNERABLE — solo ilustrativo, NUNCA ejecutar así
        vuln_query = f"SELECT * FROM users WHERE username = '{username}'"
        is_injection = "'" in username or "--" in username or ";" in username
        log_event("SQLI_TEST_UNSAFE", resource="/demo/api/demo-sqli", status="warning",
                  details=f"Query inseguro simulado: {vuln_query[:100]}")
        return jsonify({
            "mode": "INSEGURO ⚠️",
            "query": vuln_query,
            "injection_detected": is_injection,
            "risk": "CRÍTICO — el input del usuario se concatena directamente",
            "example_attack": "admin'-- (bypassea contraseña)",
            "status": "VULNERABLE"
        })
    else:
        # SEGURO — SQLAlchemy ORM con parámetros
        user = User.query.filter_by(username=username).first()
        safe_query = "SELECT * FROM users WHERE username = :username  ← parámetro vinculado"
        log_event("SQLI_TEST_SAFE", resource="/demo/api/demo-sqli", status="success",
                  details=f"Query seguro ejecutado para: {username}")
        return jsonify({
            "mode": "SEGURO ✅",
            "query": safe_query,
            "found": user is not None,
            "user": user.username if user else None,
            "protection": "SQLAlchemy ORM + Prepared Statements",
            "status": "PROTEGIDO"
        })


@demo_bp.route("/api/demo-xss", methods=["POST"])
@login_required
def demo_xss():
    """Demuestra protección XSS con escapado de HTML."""
    raw_input = request.json.get("input", "")

    # Jinja2 auto-escapa por defecto — esto es lo que hace el template
    from markupsafe import escape
    escaped = str(escape(raw_input))
    has_xss = "<script" in raw_input.lower() or "javascript:" in raw_input.lower() or "onerror" in raw_input.lower()

    log_event("XSS_TEST", resource="/demo/api/demo-xss",
              status="warning" if has_xss else "success",
              details=f"Input XSS {'detectado' if has_xss else 'limpio'}: {raw_input[:80]}")

    return jsonify({
        "raw_input": raw_input,
        "escaped_output": escaped,
        "xss_detected": has_xss,
        "protection": "Jinja2 auto-escape + CSP block",
        "csp_would_block": has_xss,
    })


@demo_bp.route("/api/demo-hash", methods=["POST"])
@login_required
def demo_hash():
    """Demuestra hash bcrypt vs MD5 (inseguro)."""
    import hashlib, time
    password = request.json.get("password", "test123")
    if len(password) > 100:
        password = password[:100]

    # MD5 — INSEGURO
    t0 = time.time()
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    md5_time = (time.time() - t0) * 1000

    # bcrypt — SEGURO
    t0 = time.time()
    bcrypt_hash = hash_password(password)
    bcrypt_time = (time.time() - t0) * 1000

    log_event("HASH_DEMO", resource="/demo/api/demo-hash", status="success",
              details=f"Demo hash comparativo ejecutado")

    return jsonify({
        "password": password,
        "md5": {"hash": md5_hash, "time_ms": round(md5_time, 3), "secure": False,
                "weakness": "Sin salt, reversible por rainbow tables, colisiones conocidas"},
        "bcrypt": {"hash": bcrypt_hash[:30] + "...", "time_ms": round(bcrypt_time, 1),
                   "secure": True, "strength": "Salt aleatorio, cost factor 12, timing-safe"},
        "winner": "bcrypt — lentitud intencional dificulta ataques de fuerza bruta"
    })


# ══════════════════════════════════════════════════════════════
#  DEMO 4 — Seguridad del Lado del Cliente
# ══════════════════════════════════════════════════════════════
@demo_bp.route("/4-client-security")
@login_required
def demo4():
    log_event("DEMO_ACCESS", resource="/demo/4", status="success", details="Demo 4: Seguridad del lado del cliente")
    return render_template("demos/demo4.html")


@demo_bp.route("/api/check-headers")
@login_required
def check_headers():
    """Verifica cabeceras de seguridad en la respuesta actual."""
    from flask import make_response
    security_headers = {
        "Content-Security-Policy": "Previene XSS y carga de recursos no autorizados",
        "X-Frame-Options": "Previene Clickjacking",
        "X-Content-Type-Options": "Previene MIME sniffing",
        "Referrer-Policy": "Controla información del referrer",
    }
    log_event("HEADERS_CHECK", resource="/demo/api/check-headers", status="success")
    return jsonify({
        "security_headers": security_headers,
        "csrf_protection": "Activo — Flask-WTF en todos los formularios",
        "cookie_flags": {"HttpOnly": True, "SameSite": "Strict", "Secure": "en HTTPS"},
        "sri_example": '<script src="https://cdn.example.com/lib.js" integrity="sha256-..." crossorigin="anonymous">',
    })


@demo_bp.route("/api/demo-csrf-info")
@login_required
def demo_csrf_info():
    """Muestra información sobre protección CSRF activa."""
    from flask_wtf.csrf import generate_csrf
    token = generate_csrf()
    return jsonify({
        "csrf_active": True,
        "token_preview": token[:20] + "...",
        "mechanism": "Token sincronizador (Double Submit Cookie pattern)",
        "protection": "Cada formulario POST requiere token CSRF válido",
        "samesite_cookie": "Strict — bloquea requests cross-site automáticamente"
    })


# ══════════════════════════════════════════════════════════════
#  DEMO 5 — Herramientas del Lado del Servidor
# ══════════════════════════════════════════════════════════════
@demo_bp.route("/5-server-security")
@login_required
def demo5():
    log_event("DEMO_ACCESS", resource="/demo/5", status="success", details="Demo 5: Herramientas del servidor")
    return render_template("demos/demo5.html")


@demo_bp.route("/api/demo-encrypt", methods=["POST"])
@login_required
def demo_encrypt():
    """Demo de cifrado/descifrado Fernet + verificación de integridad."""
    plaintext = request.json.get("text", "")
    if not plaintext or len(plaintext) > 500:
        return jsonify({"error": "Texto inválido (máx. 500 chars)"}), 400

    encrypted = encrypt_data(plaintext)
    integrity_hash = compute_hash(plaintext)

    log_event("DATA_ENCRYPTED", resource="/demo/api/demo-encrypt", status="success",
              details=f"Dato cifrado ({len(plaintext)} chars)")

    return jsonify({
        "original": plaintext,
        "encrypted": encrypted,
        "integrity_hash": integrity_hash,
        "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
        "note": "El token cifrado incluye verificación de autenticidad"
    })


@demo_bp.route("/api/demo-decrypt", methods=["POST"])
@login_required
def demo_decrypt():
    """Demo de descifrado con verificación de integridad."""
    token = request.json.get("token", "")
    expected_hash = request.json.get("hash", "")

    decrypted = decrypt_data(token)
    if decrypted is None:
        log_event("DECRYPT_FAILED", resource="/demo/api/demo-decrypt", status="failure",
                  details="Token inválido o manipulado")
        return jsonify({"error": "Token inválido o fue manipulado. Integridad comprometida.", "valid": False})

    integrity_ok = verify_integrity(decrypted, expected_hash) if expected_hash else None

    log_event("DATA_DECRYPTED", resource="/demo/api/demo-decrypt", status="success",
              details=f"Dato descifrado, integridad: {integrity_ok}")

    return jsonify({
        "decrypted": decrypted,
        "integrity_ok": integrity_ok,
        "valid": True,
        "message": "Integridad verificada ✓" if integrity_ok else "Hash no proporcionado"
    })


@demo_bp.route("/api/demo-rate-limit-info")
@login_required
def demo_rate_limit():
    """Muestra configuración de rate limiting activa."""
    return jsonify({
        "rate_limiting": "Activo — Flask-Limiter",
        "rules": {
            "login": "10 intentos por minuto",
            "global": "200 solicitudes por día, 50 por hora",
            "api": "30 solicitudes por minuto",
        },
        "on_exceeded": "HTTP 429 Too Many Requests",
        "key": "IP del cliente (X-Forwarded-For en producción)",
        "purpose": "Previene fuerza bruta, DDoS en capa de aplicación"
    })


@demo_bp.route("/api/demo-store-secret", methods=["POST"])
@login_required
def demo_store_secret():
    """Almacena un dato sensible cifrado (demo confidencialidad)."""
    label = request.json.get("label", "Mi secreto")
    value = request.json.get("value", "")

    if not value or len(value) > 500:
        return jsonify({"error": "Valor inválido"}), 400

    encrypted = encrypt_data(value)
    integrity_hash = compute_hash(value)

    secret = SecretData(
        owner_id=current_user.id,
        label=label[:100],
        encrypted_value=encrypted,
        integrity_hash=integrity_hash,
    )
    db.session.add(secret)
    db.session.commit()

    log_event("SECRET_STORED", resource="/demo/api/demo-store-secret", status="success",
              details=f"Secreto '{label}' almacenado cifrado")

    return jsonify({
        "id": secret.id,
        "label": secret.label,
        "stored_as": encrypted[:40] + "...",
        "integrity_hash": integrity_hash,
        "message": "Dato almacenado cifrado ✓"
    })


@demo_bp.route("/api/demo-read-secret/<int:secret_id>")
@login_required
def demo_read_secret(secret_id):
    """Lee y descifra un secreto — verifica que sea el dueño (RBAC)."""
    secret = SecretData.query.get_or_404(secret_id)

    # Principio de mínimo privilegio: solo el dueño o admin puede leer
    if secret.owner_id != current_user.id and current_user.role.name != "admin":
        log_event("SECRET_ACCESS_DENIED", resource=f"/demo/secret/{secret_id}",
                  status="failure", details="Intento de acceso a secreto ajeno")
        return jsonify({"error": "Acceso denegado — no eres el propietario de este secreto"}), 403

    decrypted = decrypt_data(secret.encrypted_value)
    integrity_ok = verify_integrity(decrypted, secret.integrity_hash) if decrypted else False

    log_event("SECRET_READ", resource=f"/demo/secret/{secret_id}", status="success",
              details=f"Secreto '{secret.label}' descifrado, integridad: {integrity_ok}")

    return jsonify({
        "id": secret.id,
        "label": secret.label,
        "value": decrypted,
        "integrity_ok": integrity_ok,
        "owner": secret.owner.username,
    })


@demo_bp.route("/api/my-secrets")
@login_required
def my_secrets():
    """Lista los secretos del usuario actual."""
    secrets = SecretData.query.filter_by(owner_id=current_user.id).all()
    return jsonify([{"id": s.id, "label": s.label, "created_at": s.created_at.isoformat()} for s in secrets])
