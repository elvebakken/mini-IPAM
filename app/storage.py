from __future__ import annotations
import json
import os
import secrets
import string
from pathlib import Path
from typing import Any, Dict
from datetime import datetime, timezone
import portalocker

from .models import DataFile, UsersFile, User
from .auth import hash_password

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def generate_strong_password(length: int = 24) -> str:
    """Generate a strong random password (max 72 bytes for bcrypt compatibility)."""
    # Bcrypt has a 72-byte limit, so we'll generate a password that's well within that
    # Use only ASCII characters (1 byte each) to ensure we stay under the limit
    max_length = min(length, 72)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(max_length))
    # Double-check byte length and truncate if needed (shouldn't be necessary for ASCII)
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password = password_bytes[:72].decode('utf-8', errors='ignore')
    return password

def ensure_files(data_dir: Path) -> None:
    """Ensure data files exist. Does not create admin user - use ensure_admin_user() for that."""
    data_dir.mkdir(parents=True, exist_ok=True)
    data_path = data_dir / "data.json"
    users_path = data_dir / "users.json"
    audit_path = data_dir / "audit.log"

    if not data_path.exists():
        d = DataFile(updated_at=utcnow_iso()).model_dump()
        atomic_write_json(data_path, d)

    if not users_path.exists():
        u = UsersFile(updated_at=utcnow_iso()).model_dump()
        atomic_write_json(users_path, u)

    if not audit_path.exists():
        audit_path.touch()

def ensure_admin_user(data_dir: Path) -> None:
    """Create admin user if users.json exists but is empty. Called after app startup."""
    users_path = data_dir / "users.json"
    if not users_path.exists():
        return
    
    users_file = load_users(data_dir)
    if users_file.users:
        return  # Users already exist
    
    # Generate admin user with random password
    import time
    admin_password = generate_strong_password()
    admin_id = f"user_{int(time.time()*1000)}_{secrets.token_hex(6)}"
    
    now = utcnow_iso()
    admin_user = User(
        id=admin_id,
        username="admin",
        password_bcrypt=hash_password(admin_password),
        role="admin",
        created_at=now,
        disabled=False,
        password_change_required=True,
        password_history=[],
        password_changed_at=now,
        mfa_enabled=False,
        mfa_secret=None
    )
    
    users_file.users.append(admin_user)
    save_users(data_dir, users_file)
    
    # Print credentials to console
    print("=" * 60)
    print("Mini-IPAM: Initial admin user created")
    print("=" * 60)
    print(f"Username: admin")
    print(f"Password: {admin_password}")
    print("=" * 60)
    print("Please log in and change your username and password.")
    print("=" * 60)

def atomic_write_json(path: Path, obj: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(obj, indent=2, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def load_data(data_dir: Path) -> DataFile:
    path = data_dir / "data.json"
    with portalocker.Lock(str(path), mode="r", timeout=5) as f:
        raw = json.load(f)
    return DataFile.model_validate(raw)

def save_data(data_dir: Path, data: DataFile) -> None:
    path = data_dir / "data.json"
    lock_path = data_dir / ".data.lock"
    data.updated_at = utcnow_iso()

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with portalocker.Lock(str(lock_path), mode="w", timeout=5):
        atomic_write_json(path, data.model_dump())

def load_users(data_dir: Path) -> UsersFile:
    path = data_dir / "users.json"
    with portalocker.Lock(str(path), mode="r", timeout=5) as f:
        raw = json.load(f)
    return UsersFile.model_validate(raw)

def save_users(data_dir: Path, users: UsersFile) -> None:
    path = data_dir / "users.json"
    lock_path = data_dir / ".users.lock"
    users.updated_at = utcnow_iso()

    with portalocker.Lock(str(lock_path), mode="w", timeout=5):
        atomic_write_json(path, users.model_dump())
