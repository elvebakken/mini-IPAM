from __future__ import annotations
import os
import time
import secrets
import bcrypt
import re
import base64
from io import BytesIO
from typing import Optional, Callable, Tuple, List
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException, Depends, Response
import pyotp
import qrcode

COOKIE_NAME = "miniipam_session"
CSRF_COOKIE_NAME = "csrf_token"
# Default to 1 hour, configurable via SESSION_TIMEOUT_SECONDS env var
DEFAULT_SESSION_TIMEOUT = 60 * 60  # 1 hour
MAX_AGE_SECONDS = int(os.getenv("SESSION_TIMEOUT_SECONDS", str(DEFAULT_SESSION_TIMEOUT)))

# Generate a unique server instance ID on startup
# This changes on each container restart, invalidating all existing sessions
SERVER_INSTANCE_ID = f"{int(time.time()*1000)}_{secrets.token_hex(8)}"

def get_secret() -> str:
    secret = os.getenv("SECRET_KEY", "")
    if not secret or len(secret) < 32:
        raise RuntimeError(
            "SECRET_KEY environment variable must be set and be at least 32 characters long. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    return secret

def serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_secret(), salt="mini-ipam")

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    Bcrypt has a 72-byte limit, so we truncate if necessary.
    """
    # Encode password to bytes and ensure it's within bcrypt's 72-byte limit
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return as string (bcrypt hashes are base64 encoded)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    """
    # Encode password to bytes and ensure it's within bcrypt's 72-byte limit
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Verify the password
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets complexity requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\[\]\\/_+=\-~`]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""

# Password policy configuration from environment variables
PASSWORD_HISTORY_COUNT = int(os.getenv("PASSWORD_HISTORY_COUNT", "5"))  # Number of previous passwords to remember
PASSWORD_EXPIRATION_DAYS = int(os.getenv("PASSWORD_EXPIRATION_DAYS", "0"))  # 0 = disabled, >0 = days until expiration

def check_password_history(new_password: str, password_history: List[str]) -> Tuple[bool, str]:
    """
    Check if the new password matches any of the recent passwords in history.
    Returns (is_reused, error_message)
    """
    if not password_history:
        return False, ""
    
    for old_hash in password_history:
        if verify_password(new_password, old_hash):
            return True, f"Password cannot be reused. You cannot use any of your last {PASSWORD_HISTORY_COUNT} passwords."
    
    return False, ""

def get_password_expiration_date(password_changed_at: Optional[str]) -> Optional[str]:
    """
    Calculate when the password will expire based on PASSWORD_EXPIRATION_DAYS.
    Returns ISO timestamp string or None if expiration is disabled.
    """
    if PASSWORD_EXPIRATION_DAYS <= 0:
        return None
    
    if not password_changed_at:
        return None
    
    try:
        # Parse the ISO timestamp
        changed_dt = datetime.fromisoformat(password_changed_at.replace('Z', '+00:00'))
        # Add expiration days
        expires_dt = changed_dt + timedelta(days=PASSWORD_EXPIRATION_DAYS)
        # Return as ISO string
        return expires_dt.isoformat().replace('+00:00', 'Z')
    except (ValueError, AttributeError):
        return None

def is_password_expired(password_changed_at: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Check if the password has expired.
    Returns (is_expired, expiration_date_iso)
    """
    if PASSWORD_EXPIRATION_DAYS <= 0:
        return False, None
    
    expiration_date = get_password_expiration_date(password_changed_at)
    if not expiration_date:
        return False, None
    
    try:
        expires_dt = datetime.fromisoformat(expiration_date.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        is_expired = now >= expires_dt
        return is_expired, expiration_date
    except (ValueError, AttributeError):
        return False, None

def update_password_history(current_hash: str, password_history: List[str]) -> List[str]:
    """
    Update password history by adding current hash and keeping only the last N passwords.
    """
    # Add current password to history
    new_history = [current_hash] + password_history
    # Keep only the last PASSWORD_HISTORY_COUNT passwords
    return new_history[:PASSWORD_HISTORY_COUNT]

def calculate_password_strength(password: str) -> dict:
    """
    Calculate password strength score (0-100) and feedback.
    Returns dict with score, level, and feedback messages.
    """
    score = 0
    feedback = []
    
    # Length scoring
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    
    # Character variety scoring
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>\[\]\\/_+=\-~`]', password))
    
    char_types = sum([has_upper, has_lower, has_digit, has_special])
    score += char_types * 10
    
    # Additional scoring for patterns
    if len(password) >= 8 and char_types >= 3:
        score += 10
    if len(password) >= 12 and char_types == 4:
        score += 10
    
    # Cap at 100
    score = min(score, 100)
    
    # Determine level
    if score < 40:
        level = "weak"
    elif score < 70:
        level = "fair"
    elif score < 90:
        level = "good"
    else:
        level = "strong"
    
    # Generate feedback
    if len(password) < 8:
        feedback.append("Use at least 8 characters")
    elif len(password) < 12:
        feedback.append("Consider using 12+ characters for better security")
    
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters")
    
    return {
        "score": score,
        "level": level,
        "feedback": feedback
    }

def create_session_token(username: str, role: str) -> str:
    # Include server instance ID to invalidate sessions on container restart
    return serializer().dumps({"u": username, "r": role, "i": SERVER_INSTANCE_ID})

def read_session_token(token: str) -> Optional[dict]:
    try:
        data = serializer().loads(token, max_age=MAX_AGE_SECONDS)
        # Validate that the token was issued by this server instance
        # This ensures sessions are invalidated on container restart
        if data.get("i") != SERVER_INSTANCE_ID:
            return None
        return data
    except (BadSignature, SignatureExpired):
        return None

def require_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")
    data = read_session_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid session")
    return data

def require_role(allowed: set[str]):
    def dep(user=Depends(require_user)):
        role = user.get("r")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return dep

def cookie_params():
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    return {
        "httponly": True,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
        "max_age": MAX_AGE_SECONDS,
    }

def generate_csrf_token() -> str:
    """Generate a random CSRF token."""
    return secrets.token_urlsafe(32)

def set_csrf_cookie(response: Response, token: str):
    """Set CSRF token cookie. Note: httponly=False so JavaScript can read it."""
    secure = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,  # Must be readable by JavaScript for double-submit pattern
        secure=secure,
        samesite="lax",
        path="/",
        max_age=MAX_AGE_SECONDS,
    )

def require_csrf(request: Request, user=Depends(require_user)) -> dict:
    """
    CSRF protection: require X-CSRF-Token header to match csrf_token cookie
    for state-changing requests (POST/PATCH/DELETE).
    """
    # Get token from cookie
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")
    
    # Get token from header
    header_token = request.headers.get("X-CSRF-Token")
    if not header_token:
        raise HTTPException(status_code=403, detail="CSRF token header missing")
    
    # Compare tokens (constant-time comparison to prevent timing attacks)
    if not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    
    return user

def require_csrf_and_role(allowed: set[str]):
    """Combine CSRF protection with role check."""
    def dep(request: Request, user=Depends(require_csrf)):
        role = user.get("r")
        if role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return dep

# MFA Configuration from environment variables
MFA_ENABLED = os.getenv("MFA_ENABLED", "false").lower() == "true"
MFA_ENFORCE_ALL = os.getenv("MFA_ENFORCE_ALL", "false").lower() == "true"
# Automatically enable MFA if MFA_ENFORCE_ALL is set (enforcing MFA requires MFA to be enabled)
if MFA_ENFORCE_ALL:
    MFA_ENABLED = True
MFA_REQUIRED_FOR_EXPORT = os.getenv("MFA_REQUIRED_FOR_EXPORT", "false").lower() == "true"
MFA_VERIFY_BEFORE_EXPORT = os.getenv("MFA_VERIFY_BEFORE_EXPORT", "false").lower() == "true"

def generate_mfa_secret() -> str:
    """Generate a new TOTP secret (base32 encoded)."""
    return pyotp.random_base32()

def get_mfa_issuer() -> str:
    """Get the issuer name for TOTP (appears in authenticator apps)."""
    return os.getenv("MFA_ISSUER_NAME", "Mini-IPAM")

def generate_mfa_qr_code(secret: str, username: str) -> str:
    """
    Generate a QR code for MFA setup.
    Returns base64-encoded PNG image data.
    """
    issuer = get_mfa_issuer()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=issuer
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode("utf-8")

def format_mfa_secret_for_display(secret: str) -> str:
    """Format secret for manual entry (adds spaces every 4 characters)."""
    return " ".join(secret[i:i+4] for i in range(0, len(secret), 4))

def verify_mfa_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.
    Returns True if the code is valid.
    """
    if not secret or not code:
        return False
    
    # Remove any whitespace from code
    code = code.strip().replace(" ", "")
    
    # Validate code format (6 digits)
    if not re.match(r'^\d{6}$', code):
        return False
    
    try:
        totp = pyotp.TOTP(secret)
        # Allow verification with a window of ±1 time step (30 seconds) for clock drift
        return totp.verify(code, valid_window=1)
    except Exception:
        return False

def is_mfa_required(user_mfa_enabled: bool) -> bool:
    """
    Check if MFA is required for a user.
    Returns True if MFA_ENFORCE_ALL is enabled OR if the user has MFA enabled.
    """
    if not MFA_ENABLED:
        return False
    return MFA_ENFORCE_ALL or user_mfa_enabled
