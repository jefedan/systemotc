"""Rutas del Dashboard principal."""
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ..models import AuditLog, User, SecretData
from ..modules.audit import log_event

dash_bp = Blueprint("dash", __name__)


@dash_bp.route("/")
@login_required
def index():
    log_event("PAGE_VIEW", resource="/", status="success", details="Dashboard accedido")
    stats = {
        "total_users": User.query.count(),
        "audit_entries": AuditLog.query.count(),
        "recent_events": AuditLog.query.order_by(AuditLog.id.desc()).limit(5).all(),
        "my_secrets": SecretData.query.filter_by(owner_id=current_user.id).count(),
    }
    return render_template("dashboard/index.html", stats=stats)
