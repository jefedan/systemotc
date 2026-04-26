"""
Rutas de Administración — WebSec Lab
Protegidas por RBAC — solo admin y analyst
"""
from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from ..models import User, Role, AuditLog, SecretData
from ..modules.security import require_role, require_permission, hash_password
from ..modules.audit import log_event, verify_audit_chain
from ..extensions import db

admin_bp = Blueprint("admin", __name__)


# ─────────────────────────────────────────────────────────────
#  PANEL ADMIN — Solo rol admin
# ─────────────────────────────────────────────────────────────
@admin_bp.route("/")
@login_required
@require_role("admin")
def index():
    log_event("ADMIN_ACCESS", resource="/admin/", status="success", details="Panel admin accedido")
    users = User.query.all()
    roles = Role.query.all()
    return render_template("admin/index.html", users=users, roles=roles)


@admin_bp.route("/users")
@login_required
@require_permission("can_manage_users")
def list_users():
    log_event("ADMIN_USERS_LIST", resource="/admin/users", status="success")
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/users/<int:uid>/toggle", methods=["POST"])
@login_required
@require_role("admin")
def toggle_user(uid):
    """Activa/desactiva usuario."""
    if uid == current_user.id:
        return jsonify({"error": "No puedes desactivarte a ti mismo"}), 400

    user = User.query.get_or_404(uid)
    user.is_active = not user.is_active
    db.session.commit()
    status = "activado" if user.is_active else "desactivado"
    log_event("USER_TOGGLE", resource=f"/admin/users/{uid}/toggle", status="success",
              details=f"Usuario '{user.username}' {status}")
    return jsonify({"username": user.username, "is_active": user.is_active, "status": status})


@admin_bp.route("/users/<int:uid>/reset-password", methods=["POST"])
@login_required
@require_role("admin")
def reset_password(uid):
    """Resetea contraseña de usuario."""
    user = User.query.get_or_404(uid)
    new_pwd = request.json.get("password", "")

    from ..modules.security import check_password_strength
    strength = check_password_strength(new_pwd)
    if not strength["strong"]:
        return jsonify({"error": "Contraseña débil: " + ", ".join(strength["issues"])}), 400

    user.password_hash = hash_password(new_pwd)
    user.failed_logins = 0
    user.locked_until = None
    db.session.commit()
    log_event("PASSWORD_RESET", resource=f"/admin/users/{uid}", status="success",
              details=f"Contraseña de '{user.username}' reseteada por admin")
    return jsonify({"message": f"Contraseña de {user.username} actualizada"})


# ─────────────────────────────────────────────────────────────
#  AUDITORÍA — Admin y Analyst
# ─────────────────────────────────────────────────────────────
@admin_bp.route("/audit")
@login_required
@require_permission("can_view_audit")
def audit_log():
    log_event("AUDIT_VIEW", resource="/admin/audit", status="success", details="Log de auditoría consultado")
    page = request.args.get("page", 1, type=int)
    per_page = 20
    logs = AuditLog.query.order_by(AuditLog.id.desc()).paginate(page=page, per_page=per_page)
    chain_status = verify_audit_chain()
    return render_template("admin/audit.html", logs=logs, chain_status=chain_status)


@admin_bp.route("/audit/verify")
@login_required
@require_permission("can_view_audit")
def audit_verify():
    """Verifica integridad de la cadena de auditoría."""
    result = verify_audit_chain()
    log_event("AUDIT_CHAIN_VERIFY", resource="/admin/audit/verify", status="success",
              details=f"Verificación: {result}")
    return jsonify(result)


@admin_bp.route("/audit/api")
@login_required
@require_permission("can_view_audit")
def audit_api():
    """API JSON del log de auditoría."""
    limit = min(request.args.get("limit", 50, type=int), 200)
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(limit).all()
    return jsonify([l.to_dict() for l in logs])


# ─────────────────────────────────────────────────────────────
#  ROLES — Ver configuración RBAC
# ─────────────────────────────────────────────────────────────
@admin_bp.route("/roles")
@login_required
@require_role("admin")
def list_roles():
    roles = Role.query.all()
    log_event("ROLES_VIEW", resource="/admin/roles", status="success")
    return jsonify([r.to_dict() for r in roles])


# ─────────────────────────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────────────────────────
@admin_bp.app_errorhandler(403)
def forbidden(e):
    log_event("HTTP_403", resource=request.path, status="failure",
              details="Acceso denegado (403)")
    return render_template("errors/403.html"), 403


@admin_bp.app_errorhandler(401)
def unauthorized(e):
    return render_template("errors/401.html"), 401


@admin_bp.app_errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@admin_bp.app_errorhandler(429)
def rate_limited(e):
    log_event("RATE_LIMIT_HIT", resource=request.path, status="warning",
              details="Rate limit excedido")
    return render_template("errors/429.html"), 429
