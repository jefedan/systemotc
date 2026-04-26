# modules package
from .security import (
    hash_password, verify_password, check_password_strength,
    generate_mfa_secret, get_totp_uri, generate_qr_code, verify_totp,
    encrypt_data, decrypt_data, compute_hash, compute_hmac, verify_integrity,
    require_role, require_permission, require_mfa_verified
)
from .audit import log_event, verify_audit_chain
