# 🔐 WebSec Lab — Sistema de Seguridad Web

Sistema Flask interactivo para demostrar y probar los 5 ejemplos prácticos de la Unidad 5 de Seguridad en la Web.

---

## 🚀 Instalación rápida

```bash
# 1. Crear entorno virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Inicializar BD y generar .env con claves seguras
python setup.py

# 4. Ejecutar
python run.py
```

Abrir en navegador: **http://localhost:5000**

---

## 👥 Usuarios de demo

| Usuario  | Contraseña    | Rol      | Permisos |
|----------|---------------|----------|----------|
| admin    | Admin123!     | admin    | Todo — gestión, auditoría, secretos |
| analyst  | Analyst123!   | analyst  | Ver auditoría + demos |
| demo     | Demo1234!     | user     | Solo demos |

---

## 🧪 5 Demos implementados

### Demo 5.1 — Modelos de Seguridad Web
- **Same-Origin Policy (SOP)**: Prueba interactiva de orígenes permitidos/bloqueados
- **Zero Trust**: Verificación de cada request con autenticación + RBAC
- **Cabeceras CSP**: Content-Security-Policy, X-Frame-Options, etc.

### Demo 5.2 — Gestión de Sesiones
- **Sesión segura**: Cookie HttpOnly + SameSite=Strict + expiración 15min
- **MFA/TOTP**: Activar 2FA con Google Authenticator/Authy (QR code)
- **Flujo completo**: Login → MFA verify → sesión autenticada
- **Ataques simulados**: Session Hijacking, Fixation, CSRF (con defensas activas)

### Demo 5.3 — Vulnerabilidades y Defensas
- **SQL Injection**: Consulta insegura vs SQLAlchemy ORM (modo seguro)
- **XSS**: Payload injection + Jinja2 auto-escape + CSP block
- **Hash seguro**: bcrypt (cost 12) vs MD5 — comparativa de tiempos y seguridad

### Demo 5.4 — Seguridad del Lado del Cliente
- **CSP activo**: Verificación de cabeceras en tiempo real
- **Clickjacking**: frame-ancestors 'none' + X-Frame-Options: DENY
- **SRI**: Ejemplo de Subresource Integrity para CDN
- **Cookie HttpOnly**: Demo de inaccesibilidad desde JavaScript

### Demo 5.5 — Herramientas del Lado del Servidor
- **Cifrado Fernet**: AES-128-CBC + HMAC-SHA256 — cifrar/descifrar + tamper demo
- **Secretos cifrados**: Almacenamiento cifrado en BD con verificación de integridad
- **Rate Limiting**: Flask-Limiter — simulación de múltiples requests
- **RBAC interactivo**: Prueba de acceso denegado (registrado en auditoría)

---

## 🛡️ Requisitos de seguridad implementados

| Requisito | Implementación |
|-----------|----------------|
| **Autenticación Multifactor** | TOTP RFC 6238 con pyotp — QR code + verificación de 6 dígitos |
| **Hash seguro de contraseñas** | bcrypt cost factor 12 — salt automático, timing-safe verify |
| **Control de acceso RBAC** | Roles admin/analyst/user con permisos granulares + decoradores |
| **Registro de auditoría** | Hash chaining SHA-256 — cadena de custodia inmutable |
| **Principio mínimo privilegio** | Cada rol solo tiene los permisos estrictamente necesarios |
| **Confidencialidad** | Cifrado Fernet (AES-128-CBC) para datos sensibles en BD |
| **Integridad** | SHA-256 + HMAC para verificación de integridad de datos |

---

## 📁 Estructura del proyecto

```
websec_app/
├── run.py                    # Punto de entrada
├── setup.py                  # Inicialización BD + .env
├── requirements.txt          # Dependencias
├── .env.example              # Plantilla de variables de entorno
└── app/
    ├── __init__.py           # App factory + cabeceras de seguridad
    ├── extensions.py         # SQLAlchemy
    ├── models.py             # User, Role, AuditLog, SecretData
    ├── modules/
    │   ├── security.py       # bcrypt, TOTP, Fernet, RBAC decoradores
    │   └── audit.py          # Hash chaining, log_event()
    └── routes/
        ├── auth.py           # Login, MFA, logout, cambio contraseña
        ├── dashboard.py      # Dashboard principal
        ├── demos.py          # 5 demos interactivos
        └── admin.py          # Panel admin, auditoría, gestión usuarios
```

---

## 🔧 Variables de entorno (.env)

Generadas automáticamente por `setup.py`:

| Variable | Descripción |
|----------|-------------|
| `SECRET_KEY` | Clave de firma Flask (32 bytes hex aleatorio) |
| `FERNET_KEY` | Clave de cifrado AES-128 (base64, generada con Fernet) |
| `DATABASE_URL` | SQLite por defecto, cambiar a PostgreSQL en producción |
| `SESSION_COOKIE_SECURE` | `True` en producción (HTTPS) |
| `PERMANENT_SESSION_LIFETIME` | Segundos de inactividad antes de expirar sesión |

---

## 📱 Configurar MFA con Google Authenticator

1. Iniciar sesión en la app
2. Clic en **"2FA"** en la barra de navegación
3. Escanear el código QR con Google Authenticator o Authy
4. Ingresar el código de 6 dígitos para confirmar
5. Próximo login requerirá el código TOTP

> **En modo demo**: el código actual se muestra en pantalla para facilitar pruebas.

---

## 🏭 Configuración para producción

```bash
# .env para producción
SESSION_COOKIE_SECURE=True       # Solo HTTPS
FLASK_DEBUG=0
DATABASE_URL=postgresql://user:pass@host/db

# Usar Gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 "app:create_app()"
```
