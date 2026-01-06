from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Dict, Any
from datetime import datetime

Role = Literal["admin", "readwrite", "readonly"]

class Icon(BaseModel):
    mime_type: str
    data_base64: str

class ReservedIP(BaseModel):
    ip: str
    reason: str = Field(default="", max_length=200)  # Max length enforced by validation

class Assignment(BaseModel):
    id: str
    ip: str
    hostname: str = Field(default="", max_length=255)  # RFC 1123 hostname max length
    type: str = Field(default="server", max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=20)  # Max 20 tags
    notes: str = Field(default="", max_length=5000)
    icon: Optional[Icon] = None
    archived: bool = False
    created_at: str
    updated_at: str

class Vlan(BaseModel):
    id: str
    name: str = Field(max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: str
    gateway_ip: Optional[str] = None
    reserved_ips: List[ReservedIP] = Field(default_factory=list)
    assignments: List[Assignment] = Field(default_factory=list)
    created_at: str
    updated_at: str

class Settings(BaseModel):
    type_options: List[str] = Field(default_factory=lambda: ["server", "docker", "network", "vm", "printer"])
    gateway_default: Literal["first_usable", "none"] = "first_usable"
    reserved_defaults: Dict[str, bool] = Field(default_factory=lambda: {
        "reserve_network": True,
        "reserve_broadcast": True,
        "reserve_gateway": True,
    })

class DataFile(BaseModel):
    schema_version: int = 1
    updated_at: str
    settings: Settings = Field(default_factory=Settings)
    vlans: List[Vlan] = Field(default_factory=list)

class User(BaseModel):
    id: str
    username: str
    password_bcrypt: str
    role: Role = "admin"
    created_at: str
    disabled: bool = False
    password_change_required: bool = False
    password_history: List[str] = Field(default_factory=list)  # Last 5 password hashes
    password_changed_at: Optional[str] = None  # ISO timestamp of last password change
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None  # TOTP secret (base32 encoded)
    last_login_at: Optional[str] = None  # ISO timestamp of last successful login

class UsersFile(BaseModel):
    schema_version: int = 1
    updated_at: str
    users: List[User] = Field(default_factory=list)

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None  # 2FA code for login verification

class MeResponse(BaseModel):
    username: str
    role: Role
    password_change_required: bool = False
    password_expires_at: Optional[str] = None  # ISO timestamp when password expires
    mfa_enabled: bool = False
    mfa_setup_required: bool = False  # True when MFA_ENFORCE_ALL is enabled but user hasn't set up MFA
    mfa_verify_before_export: bool = False  # True when MFA_VERIFY_BEFORE_EXPORT is enabled
    mfa_required_for_export: bool = False  # True when MFA_REQUIRED_FOR_EXPORT is enabled

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ChangeUsernameRequest(BaseModel):
    new_username: str = Field(max_length=50)  # Max length enforced by validation

class CreateVlanRequest(BaseModel):
    name: str = Field(max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: str

class PatchVlanRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=100)  # Max length enforced by validation
    vlan_id: Optional[int] = None
    subnet_cidr: Optional[str] = None
    gateway_ip: Optional[str] = None

class CreateAssignmentRequest(BaseModel):
    ip: str
    hostname: str = Field(default="", max_length=255)  # RFC 1123 hostname max length
    type: str = Field(default="server", max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=20)  # Max 20 tags
    notes: str = Field(default="", max_length=5000)
    icon: Optional[Icon] = None

class PatchAssignmentRequest(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = Field(None, max_length=255)  # RFC 1123 hostname max length
    type: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = Field(None, max_length=20)  # Max 20 tags
    notes: Optional[str] = Field(None, max_length=5000)
    icon: Optional[Icon] = None
    archived: Optional[bool] = None

class PatchSettingsRequest(BaseModel):
    type_options: Optional[List[str]] = None
    gateway_default: Optional[str] = None
    reserved_defaults: Optional[Dict[str, bool]] = None

class CreateUserRequest(BaseModel):
    username: str = Field(max_length=50)  # Max length enforced by validation
    password: str
    role: Role = "readonly"
    mfa_enabled: bool = False

class PasswordStrengthRequest(BaseModel):
    password: str

class MfaSetupResponse(BaseModel):
    session_key: str  # Session key to use for complete-setup (replaces secret)
    qr_code: str  # Base64 encoded QR code image
    manual_entry_key: str  # Formatted secret for manual entry (for display only)

class MfaVerifySetupRequest(BaseModel):
    code: str  # 6-digit TOTP code to verify setup

class MfaCompleteSetupRequest(BaseModel):
    session_key: str  # Session key from setup endpoint
    code: str  # 6-digit TOTP code to verify setup
    secret: Optional[str] = None  # Deprecated - kept for backward compatibility, ignored

class MfaVerifyRequest(BaseModel):
    code: str  # 6-digit TOTP code for login

class MfaDisableRequest(BaseModel):
    password: str  # Current password required to disable MFA

class MfaVerifyExportRequest(BaseModel):
    code: str  # 6-digit TOTP code for export verification

class MfaSetupDuringLoginRequest(BaseModel):
    username: str
    password: str  # Password verification required for security

class MfaCompleteSetupAndLoginRequest(BaseModel):
    username: str
    password: str  # Password verification required for security
    session_key: str  # Session key from setup endpoint
    code: str  # 6-digit TOTP code to verify setup
    secret: Optional[str] = None  # Deprecated - kept for backward compatibility, ignored

class PatchUserRequest(BaseModel):
    """Request model for updating user properties (admin only)."""
    disabled: Optional[bool] = None
    role: Optional[Role] = None
    username: Optional[str] = Field(None, max_length=50)  # Max length enforced by validation

class AdminChangePasswordRequest(BaseModel):
    """Request model for admin changing another user's password."""
    new_password: str

class AdminRecoverMfaRequest(BaseModel):
    """Request model for admin recovering a user's MFA (disables MFA and clears secret)."""
    confirm: bool = Field(default=False, description="Must be true to confirm recovery action")