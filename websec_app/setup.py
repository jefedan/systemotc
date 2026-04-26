"""
Script de configuración inicial — WebSec Lab
Ejecutar UNA VEZ después de instalar dependencias:
    python setup.py
"""
import os
import sys

# Generar .env si no existe
if not os.path.exists(".env"):
    from cryptography.fernet import Fernet
    import secrets
    fernet_key = Fernet.generate_key().decode()
    secret_key = secrets.token_hex(32)
    with open(".env", "w") as f:
        f.write(f"SECRET_KEY={secret_key}\n")
        f.write(f"FLASK_ENV=development\n")
        f.write(f"FLASK_DEBUG=0\n")
        f.write(f"DATABASE_URL=sqlite:///websec.db\n")
        f.write(f"SESSION_COOKIE_SECURE=False\n")
        f.write(f"SESSION_COOKIE_HTTPONLY=True\n")
        f.write(f"SESSION_COOKIE_SAMESITE=Strict\n")
        f.write(f"PERMANENT_SESSION_LIFETIME=900\n")
        f.write(f"FERNET_KEY={fernet_key}\n")
        f.write(f"MFA_ISSUER=WebSecLab\n")
    print("[✅] Archivo .env generado con claves aleatorias seguras")

from app import create_app
from app.extensions import db
from app.models import Role, User
from app.modules.security import hash_password

app = create_app()

with app.app_context():
    db.drop_all()
    db.create_all()

    # Roles con permisos RBAC (principio de mínimo privilegio)
    roles = {
        "admin": Role(
            name="admin",
            description="Administrador — acceso completo al sistema",
            can_view_audit=True,
            can_manage_users=True,
            can_access_demos=True,
            can_view_secrets=True,
        ),
        "analyst": Role(
            name="analyst",
            description="Analista de seguridad — solo lectura de auditoría",
            can_view_audit=True,
            can_manage_users=False,
            can_access_demos=True,
            can_view_secrets=False,
        ),
        "user": Role(
            name="user",
            description="Usuario estándar — acceso mínimo a demos",
            can_view_audit=False,
            can_manage_users=False,
            can_access_demos=True,
            can_view_secrets=False,
        ),
    }
    for r in roles.values():
        db.session.add(r)
    db.session.flush()

    users = [
        User(username="admin",   email="admin@websec.lab",
             password_hash=hash_password("Admin123!"),
             role_id=roles["admin"].id,   mfa_enabled=False),
        User(username="analyst", email="analyst@websec.lab",
             password_hash=hash_password("Analyst123!"),
             role_id=roles["analyst"].id, mfa_enabled=False),
        User(username="demo",    email="demo@websec.lab",
             password_hash=hash_password("Demo1234!"),
             role_id=roles["user"].id,    mfa_enabled=False),
    ]
    for u in users:
        db.session.add(u)
    db.session.commit()

    print("[✅] Base de datos inicializada")
    print("[✅] Roles creados: admin, analyst, user")
    print("[✅] Usuarios demo creados")
    print("\n─── Credenciales ───────────────────────")
    print("  admin    / Admin123!    (rol: admin)")
    print("  analyst  / Analyst123!  (rol: analyst)")
    print("  demo     / Demo1234!    (rol: user)")
    print("────────────────────────────────────────")
    print("\n[▶]  Ejecuta: python run.py")
