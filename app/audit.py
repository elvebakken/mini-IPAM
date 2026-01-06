from __future__ import annotations
import json
import os
import gzip
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, Dict, List
from pathlib import Path
import portalocker

# Log rotation configuration
LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))
LOG_ROTATION_CHECK_INTERVAL = 3600  # Check for rotation every hour (in seconds)

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

# Thread-safe rotation state tracking
_last_rotation_check: Optional[datetime] = None
_last_rotation_date: Optional[str] = None

def _get_rotation_date() -> str:
    """Get current date string for log rotation (YYYY-MM-DD format)."""
    return datetime.now(timezone.utc).date().isoformat()

def _should_rotate_log(audit_path: Path) -> bool:
    """
    Check if the audit log should be rotated.
    Rotates daily - if the log file exists and was last modified on a different day.
    """
    if not audit_path.exists():
        return False
    
    try:
        # Get file modification time
        mtime = audit_path.stat().st_mtime
        file_date = datetime.fromtimestamp(mtime, tz=timezone.utc).date()
        current_date = datetime.now(timezone.utc).date()
        
        # Rotate if file is from a different day
        return file_date < current_date
    except Exception:
        # On error, don't rotate
        return False

def _rotate_audit_log(audit_path: Path) -> None:
    """
    Rotate the current audit log file by renaming it with a date suffix.
    Thread-safe using file locking.
    """
    if not audit_path.exists():
        return
    
    try:
        # Get the date from the file's modification time (when it was last written)
        mtime = audit_path.stat().st_mtime
        file_date = datetime.fromtimestamp(mtime, tz=timezone.utc).date()
        date_str = file_date.isoformat()
        
        # Create rotated filename: audit.log.2024-01-15
        rotated_path = audit_path.parent / f"{audit_path.name}.{date_str}"
        
        # Use file lock to ensure atomic operation
        with portalocker.Lock(str(audit_path), mode="r", timeout=5) as f:
            # Double-check the file still exists and needs rotation
            if not audit_path.exists():
                return
            
            # Check if rotation already happened (another process might have done it)
            if rotated_path.exists():
                # File already rotated, just remove the current file if it's empty
                if audit_path.stat().st_size == 0:
                    audit_path.unlink()
                return
            
            # Rename the file atomically
            shutil.move(str(audit_path), str(rotated_path))
    except portalocker.LockException:
        # Another process is rotating, skip
        pass
    except Exception:
        # On error, log but don't fail
        pass

def _compress_old_logs(audit_dir: Path) -> None:
    """
    Compress old audit log files that haven't been compressed yet.
    Compresses files matching pattern: audit.log.YYYY-MM-DD (not .gz)
    """
    if not audit_dir.exists():
        return
    
    try:
        audit_log_name = "audit.log"
        for log_file in audit_dir.glob(f"{audit_log_name}.*"):
            # Skip already compressed files and the current log
            if log_file.suffix == ".gz" or log_file.name == audit_log_name:
                continue
            
            # Check if it's a date-stamped rotated log (audit.log.YYYY-MM-DD)
            parts = log_file.name.split(".")
            if len(parts) >= 3:
                try:
                    # Try to parse the date part
                    date_part = parts[-1]
                    datetime.strptime(date_part, "%Y-%m-%d")
                    
                    # This is a rotated log, compress it
                    compressed_path = log_file.with_suffix(log_file.suffix + ".gz")
                    
                    # Skip if already compressed
                    if compressed_path.exists():
                        continue
                    
                    # Compress the file
                    with open(log_file, "rb") as f_in:
                        with gzip.open(compressed_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    # Remove original after successful compression
                    log_file.unlink()
                except (ValueError, Exception):
                    # Not a date-stamped file, skip
                    pass
    except Exception:
        # On error, don't fail
        pass

def _cleanup_old_logs(audit_dir: Path, retention_days: int = LOG_RETENTION_DAYS) -> None:
    """
    Remove audit log files older than the retention period.
    Deletes both compressed (.gz) and uncompressed rotated logs.
    """
    if not audit_dir.exists():
        return
    
    try:
        cutoff_date = datetime.now(timezone.utc).date() - timedelta(days=retention_days)
        audit_log_name = "audit.log"
        
        for log_file in audit_dir.glob(f"{audit_log_name}.*"):
            # Skip the current log file
            if log_file.name == audit_log_name:
                continue
            
            try:
                # Extract date from filename
                # Pattern: audit.log.YYYY-MM-DD or audit.log.YYYY-MM-DD.gz
                name_without_ext = log_file.stem  # Removes .gz if present
                parts = name_without_ext.split(".")
                
                if len(parts) >= 3:
                    date_str = parts[-1]
                    file_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    
                    # Delete if older than retention period
                    if file_date < cutoff_date:
                        log_file.unlink()
            except (ValueError, Exception):
                # Can't parse date, skip this file
                pass
    except Exception:
        # On error, don't fail
        pass

def maybe_rotate_audit_log(audit_path: Path) -> None:
    """
    Check if rotation is needed and perform it if necessary.
    This function is called before appending to the log.
    Uses a simple time-based check to avoid checking on every append.
    """
    global _last_rotation_check, _last_rotation_date
    
    now = datetime.now(timezone.utc)
    current_date = _get_rotation_date()
    
    # Check rotation at most once per hour, or if date changed
    if _last_rotation_check is None:
        _last_rotation_check = now
        _last_rotation_date = current_date
    
    # Check if we need to rotate (date changed or hourly check)
    time_since_check = (now - _last_rotation_check).total_seconds()
    date_changed = _last_rotation_date != current_date
    
    if date_changed or time_since_check >= LOG_ROTATION_CHECK_INTERVAL:
        if _should_rotate_log(audit_path):
            _rotate_audit_log(audit_path)
            # Compress the newly rotated log
            _compress_old_logs(audit_path.parent)
        
        _last_rotation_check = now
        _last_rotation_date = current_date

def cleanup_audit_logs(audit_dir: Path, retention_days: Optional[int] = None) -> None:
    """
    Perform maintenance on audit logs:
    1. Compress old uncompressed logs
    2. Delete logs older than retention period
    
    This should be called periodically (e.g., on startup, daily via cron).
    """
    if retention_days is None:
        retention_days = LOG_RETENTION_DAYS
    
    audit_path = audit_dir / "audit.log"
    
    # Rotate if needed
    maybe_rotate_audit_log(audit_path)
    
    # Compress old logs
    _compress_old_logs(audit_dir)
    
    # Cleanup old logs
    _cleanup_old_logs(audit_dir, retention_days)

def append_audit(audit_path: Path, entry: Dict[str, Any]) -> None:
    """
    Append an audit log entry. Automatically handles log rotation before appending.
    """
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check if rotation is needed before appending
    maybe_rotate_audit_log(audit_path)
    
    line = json.dumps(entry, ensure_ascii=False)
    # lock audit file for append
    with portalocker.Lock(str(audit_path), mode="a", timeout=5) as f:
        f.write(line + "\n")

def read_audit_logs(audit_path: Path, user_filter: Optional[str] = None, action_filter: Optional[str] = None, 
                    date_from: Optional[str] = None, date_to: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
    """
    Read audit logs from file with optional filtering.
    Optimized for large files by reading backwards (tail-like approach) to avoid loading entire file into memory.
    """
    if not audit_path.exists():
        return []
    
    entries = []
    
    # Parse date filters once
    from_ts = None
    to_ts = None
    if date_from:
        try:
            from_ts = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
        except:
            pass
    if date_to:
        try:
            to_ts = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
        except:
            pass
    
    try:
        with portalocker.Lock(str(audit_path), mode="rb", timeout=5) as f:
            # Get file size
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            
            if file_size == 0:
                return []
            
            # Read file backwards in chunks
            chunk_size = 8192  # 8KB chunks
            buffer = b""
            position = file_size
            
            while position > 0 and len(entries) < limit:
                # Calculate how much to read
                read_size = min(chunk_size, position)
                position -= read_size
                f.seek(position)
                
                # Read chunk
                chunk = f.read(read_size)
                buffer = chunk + buffer
                
                # Process complete lines from buffer
                while b'\n' in buffer:
                    # Find last newline
                    last_newline = buffer.rfind(b'\n')
                    if last_newline == -1:
                        break
                    
                    # Extract line (everything after last newline)
                    line_bytes = buffer[last_newline + 1:]
                    buffer = buffer[:last_newline]
                    
                    if not line_bytes.strip():
                        continue
                    
                    # Try to parse line
                    try:
                        line = line_bytes.decode('utf-8', errors='ignore').strip()
                        if not line:
                            continue
                        
                        entry = json.loads(line)
                        
                        # Apply filters
                        if user_filter and entry.get("user") != user_filter:
                            continue
                        if action_filter and entry.get("action") != action_filter:
                            continue
                        
                        # Date filtering
                        if from_ts or to_ts:
                            try:
                                entry_ts_str = entry.get("ts", "")
                                if not entry_ts_str:
                                    continue
                                entry_ts = datetime.fromisoformat(entry_ts_str.replace("Z", "+00:00"))
                                
                                if from_ts and entry_ts < from_ts:
                                    continue
                                if to_ts and entry_ts > to_ts:
                                    continue
                            except:
                                continue
                        
                        # Add entry (most recent first)
                        entries.append(entry)
                        
                        # Stop if we have enough entries
                        if len(entries) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
                    except Exception:
                        continue
                
                # Break outer loop if we have enough entries
                if len(entries) >= limit:
                    break
            
            # Process any remaining buffer content (first line in file, oldest entry)
            if buffer.strip() and len(entries) < limit:
                try:
                    line = buffer.decode('utf-8', errors='ignore').strip()
                    if line:
                        entry = json.loads(line)
                        
                        # Apply filters
                        if user_filter and entry.get("user") != user_filter:
                            pass  # Skip this entry
                        elif action_filter and entry.get("action") != action_filter:
                            pass  # Skip this entry
                        elif from_ts or to_ts:
                            try:
                                entry_ts_str = entry.get("ts", "")
                                if entry_ts_str:
                                    entry_ts = datetime.fromisoformat(entry_ts_str.replace("Z", "+00:00"))
                                    if from_ts and entry_ts < from_ts:
                                        pass  # Skip this entry
                                    elif to_ts and entry_ts > to_ts:
                                        pass  # Skip this entry
                                    else:
                                        entries.append(entry)
                            except:
                                pass  # Skip on date parse error
                        else:
                            entries.append(entry)
                except (json.JSONDecodeError, Exception):
                    pass  # Skip invalid entries
            
    except Exception:
        pass
    
    # Entries are already in reverse chronological order (most recent first)
    return entries[:limit]
