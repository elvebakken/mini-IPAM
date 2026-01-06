from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Dict, List, Optional
import portalocker

# Configuration
MAX_ATTEMPTS_PER_MINUTE = 5  # Maximum login attempts per minute
BASE_LOCKOUT_DURATION_SECONDS = 300  # Base lockout duration: 5 minutes
LOCKOUT_THRESHOLD = 5  # Number of failures before lockout
MAX_LOCKOUT_DURATION_SECONDS = 3600  # Maximum lockout duration: 60 minutes

class RateLimitState:
    """Tracks rate limiting state for login attempts."""
    def __init__(self):
        # Per-IP tracking: {ip: [timestamps]}
        self.ip_attempts: Dict[str, List[float]] = {}
        # Per-username tracking: {username: [timestamps]}
        self.username_attempts: Dict[str, List[float]] = {}
        # Lockouts: {key: lockout_until_timestamp}
        self.lockouts: Dict[str, float] = {}
        # Lockout counts: {key: count} - tracks how many times an IP/username has been locked out
        self.lockout_counts: Dict[str, int] = {}
        # Lockout count timestamps: {key: timestamp} - tracks when lockout count was last incremented
        self.lockout_count_timestamps: Dict[str, float] = {}

def calculate_lockout_duration(lockout_count: int) -> int:
    """
    Calculate lockout duration based on number of previous lockouts.
    Uses exponential backoff with a cap.
    
    Examples:
    - 1st lockout: 5 minutes (300 seconds)
    - 2nd lockout: 15 minutes (900 seconds)
    - 3rd lockout: 30 minutes (1800 seconds)
    - 4th+ lockout: 60 minutes (3600 seconds)
    """
    if lockout_count <= 1:
        return BASE_LOCKOUT_DURATION_SECONDS
    elif lockout_count == 2:
        return BASE_LOCKOUT_DURATION_SECONDS * 3  # 15 minutes
    elif lockout_count == 3:
        return BASE_LOCKOUT_DURATION_SECONDS * 6  # 30 minutes
    else:
        return MAX_LOCKOUT_DURATION_SECONDS  # 60 minutes (cap)

def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (common in reverse proxy setups)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    # Fallback to direct client
    if request.client:
        return request.client.host
    return "unknown"

def load_auth_state(data_dir: Path) -> RateLimitState:
    """Load rate limiting state from JSON file."""
    path = data_dir / "auth_state.json"
    state = RateLimitState()
    
    if not path.exists():
        return state
    
    try:
        with portalocker.Lock(str(path), mode="r", timeout=5) as f:
            raw = json.load(f)
        
        # Convert lists of timestamps back to floats
        state.ip_attempts = {k: [float(ts) for ts in v] for k, v in raw.get("ip_attempts", {}).items()}
        state.username_attempts = {k: [float(ts) for ts in v] for k, v in raw.get("username_attempts", {}).items()}
        state.lockouts = {k: float(v) for k, v in raw.get("lockouts", {}).items()}
        state.lockout_counts = {k: int(v) for k, v in raw.get("lockout_counts", {}).items()}
        state.lockout_count_timestamps = {k: float(v) for k, v in raw.get("lockout_count_timestamps", {}).items()}
    except (json.JSONDecodeError, KeyError, ValueError):
        # If file is corrupted, start fresh
        return state
    
    return state

def save_auth_state(data_dir: Path, state: RateLimitState) -> None:
    """Save rate limiting state to JSON file."""
    path = data_dir / "auth_state.json"
    lock_path = data_dir / ".auth_state.lock"
    
    # Clean up old entries before saving
    now = time.time()
    cleanup_old_entries(state, now)
    
    # Prepare data for JSON (convert floats to lists)
    data = {
        "ip_attempts": {k: v for k, v in state.ip_attempts.items()},
        "username_attempts": {k: v for k, v in state.username_attempts.items()},
        "lockouts": {k: v for k, v in state.lockouts.items() if v > now},  # Only save active lockouts
        "lockout_counts": {k: v for k, v in state.lockout_counts.items()},  # Persist lockout counts
        "lockout_count_timestamps": {k: v for k, v in state.lockout_count_timestamps.items()}  # Persist timestamps
    }
    
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with portalocker.Lock(str(lock_path), mode="w", timeout=5):
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
        tmp.replace(path)

def cleanup_old_entries(state: RateLimitState, now: float) -> None:
    """Remove old attempt timestamps and expired lockouts."""
    window_start = now - 60  # Keep only last minute of attempts
    
    # Clean IP attempts
    for ip in list(state.ip_attempts.keys()):
        state.ip_attempts[ip] = [ts for ts in state.ip_attempts[ip] if ts > window_start]
        if not state.ip_attempts[ip]:
            del state.ip_attempts[ip]
    
    # Clean username attempts
    for username in list(state.username_attempts.keys()):
        state.username_attempts[username] = [ts for ts in state.username_attempts[username] if ts > window_start]
        if not state.username_attempts[username]:
            del state.username_attempts[username]
    
    # Clean expired lockouts
    for key in list(state.lockouts.keys()):
        if state.lockouts[key] <= now:
            del state.lockouts[key]
    
    # Clean lockout counts for entries that have been expired for more than 24 hours
    # This allows lockout counts to reset after a period of good behavior
    reset_window = 24 * 60 * 60  # 24 hours
    
    # First, clean up entries in lockout_counts
    for key in list(state.lockout_counts.keys()):
        # If there's no active lockout, check if 24 hours have passed since last lockout
        if key not in state.lockouts:
            # Get the timestamp when this lockout count was last incremented
            last_lockout_time = state.lockout_count_timestamps.get(key)
            if last_lockout_time is None:
                # If no timestamp exists, treat as orphaned/invalid and remove
                del state.lockout_counts[key]
            elif now - last_lockout_time >= reset_window:
                # 24 hours have passed since last lockout, reset the count
                del state.lockout_counts[key]
                # Also remove the corresponding timestamp
                if key in state.lockout_count_timestamps:
                    del state.lockout_count_timestamps[key]
    
    # Second, clean up orphaned timestamps (keys in lockout_count_timestamps but not in lockout_counts)
    # This handles edge cases where timestamps exist without corresponding counts
    for key in list(state.lockout_count_timestamps.keys()):
        if key not in state.lockout_counts:
            # Orphaned timestamp - remove it
            del state.lockout_count_timestamps[key]

def check_rate_limit(data_dir: Path, ip: str, username: Optional[str]) -> tuple[bool, Optional[str]]:
    """
    Check if login attempt should be allowed.
    Returns (allowed, error_message)
    """
    state = load_auth_state(data_dir)
    now = time.time()
    
    # Clean up old entries
    cleanup_old_entries(state, now)
    
    # Check IP lockout
    ip_lockout_key = f"ip:{ip}"
    if ip_lockout_key in state.lockouts:
        lockout_until = state.lockouts[ip_lockout_key]
        if lockout_until > now:
            remaining = int(lockout_until - now)
            return False, f"Too many login attempts from this IP. Please try again in {remaining} seconds."
    
    # Check username lockout
    if username:
        username_lockout_key = f"user:{username}"
        if username_lockout_key in state.lockouts:
            lockout_until = state.lockouts[username_lockout_key]
            if lockout_until > now:
                remaining = int(lockout_until - now)
                return False, f"Too many login attempts for this username. Please try again in {remaining} seconds."
    
    # Check IP rate limit
    ip_attempts = state.ip_attempts.get(ip, [])
    recent_ip_attempts = [ts for ts in ip_attempts if ts > now - 60]
    if len(recent_ip_attempts) >= MAX_ATTEMPTS_PER_MINUTE:
        # Trigger lockout with incremental backoff
        lockout_count = state.lockout_counts.get(ip_lockout_key, 0) + 1
        state.lockout_counts[ip_lockout_key] = lockout_count
        state.lockout_count_timestamps[ip_lockout_key] = now
        lockout_duration = calculate_lockout_duration(lockout_count)
        state.lockouts[ip_lockout_key] = now + lockout_duration
        save_auth_state(data_dir, state)
        return False, f"Too many login attempts from this IP. Please try again in {lockout_duration} seconds."
    
    # Check username rate limit
    if username:
        username_attempts = state.username_attempts.get(username, [])
        recent_username_attempts = [ts for ts in username_attempts if ts > now - 60]
        if len(recent_username_attempts) >= MAX_ATTEMPTS_PER_MINUTE:
            # Trigger lockout with incremental backoff
            username_lockout_key = f"user:{username}"
            lockout_count = state.lockout_counts.get(username_lockout_key, 0) + 1
            state.lockout_counts[username_lockout_key] = lockout_count
            state.lockout_count_timestamps[username_lockout_key] = now
            lockout_duration = calculate_lockout_duration(lockout_count)
            state.lockouts[username_lockout_key] = now + lockout_duration
            save_auth_state(data_dir, state)
            return False, f"Too many login attempts for this username. Please try again in {lockout_duration} seconds."
    
    return True, None

def record_failed_attempt(data_dir: Path, ip: str, username: Optional[str]) -> None:
    """Record a failed login attempt."""
    state = load_auth_state(data_dir)
    now = time.time()
    
    # Record IP attempt
    if ip not in state.ip_attempts:
        state.ip_attempts[ip] = []
    state.ip_attempts[ip].append(now)
    
    # Record username attempt
    if username:
        if username not in state.username_attempts:
            state.username_attempts[username] = []
        state.username_attempts[username].append(now)
        
        # Check if we should trigger lockout based on failure count
        recent_failures = [ts for ts in state.username_attempts[username] if ts > now - 60]
        if len(recent_failures) >= LOCKOUT_THRESHOLD:
            username_lockout_key = f"user:{username}"
            lockout_count = state.lockout_counts.get(username_lockout_key, 0) + 1
            state.lockout_counts[username_lockout_key] = lockout_count
            state.lockout_count_timestamps[username_lockout_key] = now
            lockout_duration = calculate_lockout_duration(lockout_count)
            state.lockouts[username_lockout_key] = now + lockout_duration
    
    # Check if we should trigger IP lockout
    recent_ip_failures = [ts for ts in state.ip_attempts[ip] if ts > now - 60]
    if len(recent_ip_failures) >= LOCKOUT_THRESHOLD:
        ip_lockout_key = f"ip:{ip}"
        lockout_count = state.lockout_counts.get(ip_lockout_key, 0) + 1
        state.lockout_counts[ip_lockout_key] = lockout_count
        state.lockout_count_timestamps[ip_lockout_key] = now
        lockout_duration = calculate_lockout_duration(lockout_count)
        state.lockouts[ip_lockout_key] = now + lockout_duration
    
    save_auth_state(data_dir, state)

def record_successful_login(data_dir: Path, ip: str, username: Optional[str]) -> None:
    """Clear rate limiting state on successful login."""
    state = load_auth_state(data_dir)
    
    # Clear username attempts, lockout, and lockout count on successful login
    if username:
        if username in state.username_attempts:
            del state.username_attempts[username]
        username_lockout_key = f"user:{username}"
        if username_lockout_key in state.lockouts:
            del state.lockouts[username_lockout_key]
        # Reset lockout count on successful login (good behavior reward)
        if username_lockout_key in state.lockout_counts:
            del state.lockout_counts[username_lockout_key]
        if username_lockout_key in state.lockout_count_timestamps:
            del state.lockout_count_timestamps[username_lockout_key]
    
    # Note: We don't clear IP attempts/lockouts on success, as the same IP
    # might be used by multiple users or attackers
    
    save_auth_state(data_dir, state)

