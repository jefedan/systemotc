"""
Modelos de base de datos — WebSec Lab
"""
from datetime import datetime, timezone
from flask_login import UserMixin
from .extensions import db


class Role(db.Model):
    """Roles para RBAC (Control de Acceso Basado en Roles)."""
    __tablename__ = "roles"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))

    # Permisos por rol (principio de mínimo privilegio)
    can_view_audit    = db.Column(db.Boolean, default=False)
    can_manage_users  = db.Column(db.Boolean, default=False)
    can_access_demos  = db.Column(db.Boolean, default=True)
    can_view_secrets  = db.Column(db.Boolean, default=False)

    users = db.relationship("User", backref="role", lazy=True)

    def __repr__(self):
        return f"<Role {self.name}>"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "can_view_audit": self.can_view_audit,
            "can_manage_users": self.can_manage_users,
            "can_access_demos": self.can_access_demos,
            "can_view_secrets": self.can_view_secrets,
        }


class User(UserMixin, db.Model):
    """Usuarios del sistema con hash seguro de contraseña y MFA."""
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # MFA
    mfa_enabled   = db.Column(db.Boolean, default=False)
    mfa_secret    = db.Column(db.String(64))       # TOTP secret (cifrado en servicio)

    # Estado
    is_active     = db.Column(db.Boolean, default=True)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until  = db.Column(db.DateTime)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login    = db.Column(db.DateTime)

    # Relaciones
    role_id       = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    audit_logs    = db.relationship("AuditLog", backref="user", lazy=True, foreign_keys="AuditLog.user_id")

    def __repr__(self):
        return f"<User {self.username}>"

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return True
        return False

    def has_permission(self, perm: str) -> bool:
        """Verifica permiso RBAC."""
        if not self.role:
            return False
        return getattr(self.role, perm, False)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role.name if self.role else None,
            "mfa_enabled": self.mfa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class AuditLog(db.Model):
    """Registro de auditoría — inmutable, append-only."""
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username   = db.Column(db.String(80))           # Guardamos username por si el user se elimina
    action     = db.Column(db.String(100), nullable=False)
    resource   = db.Column(db.String(200))
    status     = db.Column(db.String(20))            # success / failure / warning
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(300))
    details    = db.Column(db.Text)
    # Hash de integridad del registro anterior (cadena de custodia)
    prev_hash  = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64))

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "action": self.action,
            "resource": self.resource,
            "status": self.status,
            "ip_address": self.ip_address,
            "details": self.details,
            "entry_hash": self.entry_hash,
        }


class SecretData(db.Model):
    """Datos confidenciales cifrados — demo de confidencialidad."""
    __tablename__ = "secret_data"

    id           = db.Column(db.Integer, primary_key=True)
    owner_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    label        = db.Column(db.String(100))
    encrypted_value = db.Column(db.Text, nullable=False)    # Cifrado con Fernet
    integrity_hash  = db.Column(db.String(64), nullable=False)  # SHA-256 del plaintext
    created_at   = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    owner = db.relationship("User", backref="secrets")
