"""
Módulo de Auditoría — WebSec Lab
Registro inmutable con cadena de integridad (hash chaining)
"""
import hashlib
from datetime import datetime, timezone
from flask import request
from flask_login import current_user

from ..extensions import db


def log_event(action: str, resource: str = None, status: str = "success",
              details: str = None, user_id: int = None, username: str = None):
    """
    Registra un evento en el log de auditoría.
    Implementa hash chaining para garantizar integridad del log.
    """
    from ..models import AuditLog

    # Resolver usuario
    uid = user_id
    uname = username
    if uid is None and current_user and current_user.is_authenticated:
        uid = current_user.id
        uname = current_user.username
    elif uname is None:
        uname = "anonymous"

    # IP y User-Agent
    ip = _get_client_ip()
    ua = request.user_agent.string[:300] if request else "N/A"
    resource_val = resource or (request.path if request else "N/A")

    # Hash del registro anterior (chain-of-custody)
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last.entry_hash if last else "0" * 64

    # Usar timestamp naive (sin tzinfo) para consistencia con SQLite
    ts_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    ts = ts_dt.isoformat()

    entry_data = f"{ts}|{uname}|{action}|{resource_val}|{status}|{ip}|{details}"
    chain_input = f"{prev_hash}:{entry_data}"
    entry_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    log = AuditLog(
        timestamp=ts_dt,
        user_id=uid,
        username=uname,
        action=action,
        resource=resource_val,
        status=status,
        ip_address=ip,
        user_agent=ua,
        details=details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )

    try:
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[AUDIT ERROR] No se pudo registrar evento: {e}")


def verify_audit_chain() -> dict:
    """
    Verifica la integridad de toda la cadena de auditoría.
    Detecta si algún registro fue modificado o eliminado.
    """
    from ..models import AuditLog

    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    if not logs:
        return {"valid": True, "broken_at": None, "total": 0, "verified": 0}

    prev_hash = "0" * 64
    for i, log in enumerate(logs):
        ts = log.timestamp.isoformat()
        entry_data = (
            f"{ts}|{log.username}|{log.action}|{log.resource}"
            f"|{log.status}|{log.ip_address}|{log.details}"
        )
        chain_input = f"{prev_hash}:{entry_data}"
        expected_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

        if expected_hash != log.entry_hash:
            return {
                "valid": False,
                "broken_at": log.id,
                "total": len(logs),
                "verified": i,
                "message": f"Registro #{log.id} ha sido modificado o la cadena está rota."
            }
        prev_hash = log.entry_hash

    return {"valid": True, "broken_at": None, "total": len(logs), "verified": len(logs)}


def _get_client_ip() -> str:
    """Obtiene IP real del cliente considerando proxies."""
    if not request:
        return "N/A"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"
