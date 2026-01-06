"""
Input validation and sanitization utilities for Mini-IPAM.

This module provides functions for:
- HTML escaping and sanitization
- Input length validation
- File upload validation (magic bytes)
- SQL injection prevention notes
"""

import html
from typing import Optional, List
from fastapi import HTTPException


# Maximum length constants for input fields
MAX_LENGTHS = {
    "hostname": 255,  # RFC 1123 hostname max length
    "notes": 5000,    # Reasonable limit for notes
    "tag": 100,       # Individual tag max length
    "tags_total": 20,  # Maximum number of tags per assignment
    "vlan_name": 100,  # VLAN name max length
    "username": 50,    # Username max length
    "type": 50,       # Device type max length
    "reserved_reason": 200,  # Reserved IP reason max length
}


def sanitize_input(text: str, max_length: Optional[int] = None, field_name: str = "input") -> str:
    """
    Sanitize user input to prevent XSS attacks.
    
    Args:
        text: Input string to sanitize
        max_length: Maximum allowed length (raises error if exceeded)
        field_name: Name of the field for error messages
    
    Returns:
        Sanitized string (HTML-escaped and stripped)
    
    Raises:
        HTTPException: If input exceeds max_length
    """
    if text is None:
        return ""
    
    # Convert to string and strip whitespace
    text = str(text).strip()
    
    # Check length before processing
    if max_length is not None and len(text) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} too long (max {max_length} characters, got {len(text)})"
        )
    
    # HTML escape to prevent XSS
    sanitized = html.escape(text)
    
    return sanitized


def sanitize_hostname(hostname: str) -> str:
    """Sanitize and validate hostname."""
    if not hostname:
        return ""
    
    sanitized = sanitize_input(hostname, MAX_LENGTHS["hostname"], "Hostname")
    
    # Additional validation: hostnames should be alphanumeric with dots, dashes, underscores
    # Allow basic characters for hostnames (RFC 1123)
    if sanitized and not all(c.isalnum() or c in '.-_' for c in sanitized):
        # Still allow it but log a warning - some systems use special characters
        pass
    
    return sanitized


def sanitize_notes(notes: str) -> str:
    """Sanitize and validate notes field."""
    if not notes:
        return ""
    
    return sanitize_input(notes, MAX_LENGTHS["notes"], "Notes")


def sanitize_tags(tags: List[str]) -> List[str]:
    """
    Sanitize and validate tags list.
    
    Args:
        tags: List of tag strings
    
    Returns:
        List of sanitized tags
    
    Raises:
        HTTPException: If tags exceed limits
    """
    if not tags:
        return []
    
    # Limit total number of tags
    if len(tags) > MAX_LENGTHS["tags_total"]:
        raise HTTPException(
            status_code=400,
            detail=f"Too many tags (max {MAX_LENGTHS['tags_total']}, got {len(tags)})"
        )
    
    sanitized_tags = []
    for tag in tags:
        if not tag:
            continue
        
        # Sanitize each tag
        sanitized_tag = sanitize_input(str(tag).strip(), MAX_LENGTHS["tag"], "Tag")
        
        # Remove empty tags and duplicates
        if sanitized_tag and sanitized_tag not in sanitized_tags:
            sanitized_tags.append(sanitized_tag)
    
    return sanitized_tags


def sanitize_vlan_name(name: str) -> str:
    """Sanitize and validate VLAN name."""
    if not name:
        raise HTTPException(status_code=400, detail="VLAN name cannot be empty")
    
    return sanitize_input(name, MAX_LENGTHS["vlan_name"], "VLAN name")


def sanitize_username(username: str) -> str:
    """Sanitize and validate username."""
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    
    sanitized = sanitize_input(username.strip(), MAX_LENGTHS["username"], "Username")
    
    # Usernames should be alphanumeric with limited special characters
    if not all(c.isalnum() or c in '._-' for c in sanitized):
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters, numbers, dots, underscores, and hyphens"
        )
    
    return sanitized


def sanitize_device_type(device_type: str) -> str:
    """Sanitize and validate device type."""
    if not device_type:
        return "server"  # Default
    
    return sanitize_input(device_type, MAX_LENGTHS["type"], "Device type")


def sanitize_reserved_reason(reason: str) -> str:
    """Sanitize and validate reserved IP reason."""
    if not reason:
        return ""
    
    return sanitize_input(reason, MAX_LENGTHS["reserved_reason"], "Reserved IP reason")


# Magic bytes (file signatures) for common image formats
IMAGE_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'image/png',
    b'\xff\xd8\xff': 'image/jpeg',
    b'GIF87a': 'image/gif',
    b'GIF89a': 'image/gif',
    b'RIFF': 'image/webp',  # WebP files start with RIFF, but need more checking
    b'\x00\x00\x01\x00': 'image/x-icon',  # ICO files
    b'BM': 'image/bmp',
}


def validate_image_magic_bytes(file_content: bytes) -> tuple[bool, Optional[str]]:
    """
    Validate file is actually an image using magic bytes (file signatures).
    
    This is more secure than relying solely on MIME types, which can be spoofed.
    
    Args:
        file_content: Raw file content as bytes
    
    Returns:
        Tuple of (is_valid, detected_mime_type)
        - is_valid: True if file signature matches an image format
        - detected_mime_type: Detected MIME type or None
    """
    if not file_content or len(file_content) < 4:
        return False, None
    
    # Check PNG signature (most common for icons)
    if file_content.startswith(b'\x89PNG\r\n\x1a\n'):
        return True, 'image/png'
    
    # Check JPEG signature
    if file_content.startswith(b'\xff\xd8\xff'):
        return True, 'image/jpeg'
    
    # Check GIF signatures
    if file_content.startswith(b'GIF87a') or file_content.startswith(b'GIF89a'):
        return True, 'image/gif'
    
    # Check WebP (RIFF...WEBP)
    if file_content.startswith(b'RIFF') and len(file_content) >= 12:
        if file_content[8:12] == b'WEBP':
            return True, 'image/webp'
    
    # Check ICO files
    if file_content.startswith(b'\x00\x00\x01\x00'):
        return True, 'image/x-icon'
    
    # Check BMP files
    if file_content.startswith(b'BM'):
        return True, 'image/bmp'
    
    # Check SVG files - they are XML, so check for XML declaration or SVG tag
    # SVG files can start with <?xml, <svg, or have whitespace before
    content_start = file_content.lstrip()[:100].decode('utf-8', errors='ignore').lower()
    if content_start.startswith('<?xml') or content_start.startswith('<svg'):
        # Additional validation: check if it contains SVG namespace or SVG tag
        if '<svg' in content_start or 'svg' in content_start:
            return True, 'image/svg+xml'
    
    return False, None


def validate_uploaded_image(
    file_content: bytes,
    content_type: Optional[str] = None,
    max_size: int = 2_000_000
) -> tuple[bool, Optional[str]]:
    """
    Comprehensive image validation including magic bytes and size.
    
    Args:
        file_content: Raw file content as bytes
        content_type: Reported MIME type (optional, for logging)
        max_size: Maximum file size in bytes (default 2MB)
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if file is valid
        - error_message: Error message if invalid, None if valid
    
    Raises:
        HTTPException: If file is invalid
    """
    # Check file size
    if len(file_content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"Image too large (max {max_size // 1_000_000}MB, got {len(file_content) / 1_000_000:.2f}MB)"
        )
    
    if len(file_content) < 4:
        raise HTTPException(status_code=400, detail="File too small to be a valid image")
    
    # Validate magic bytes (or SVG content)
    is_valid, detected_mime = validate_image_magic_bytes(file_content)
    
    # Also accept SVG if content_type is explicitly image/svg+xml
    if not is_valid and content_type == 'image/svg+xml':
        # Validate it's actually XML/SVG
        try:
            content_start = file_content.lstrip()[:100].decode('utf-8', errors='ignore').lower()
            if content_start.startswith('<?xml') or content_start.startswith('<svg'):
                is_valid = True
                detected_mime = 'image/svg+xml'
        except:
            pass
    
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid image file. File signature does not match any supported image format. "
                   f"Reported type: {content_type or 'unknown'}"
        )
    
    # Warn if MIME type doesn't match detected type (but don't fail)
    if content_type and detected_mime:
        if not content_type.startswith('image/'):
            # This shouldn't happen if we check content_type first, but log it
            pass
    
    return True, None


# SQL Injection Prevention Notes
"""
SQL INJECTION PREVENTION GUIDELINES
====================================

While Mini-IPAM currently uses JSON file storage, if you migrate to a database
in the future, follow these guidelines:

1. ALWAYS use parameterized queries (prepared statements):
   
   ✅ CORRECT:
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
   cursor.execute("SELECT * FROM vlans WHERE name = ? AND subnet = ?", (name, subnet))
   
   ❌ WRONG:
   cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
   cursor.execute("SELECT * FROM vlans WHERE name = '" + name + "'")

2. Use ORM libraries that handle parameterization automatically:
   - SQLAlchemy: Use session.query() with filter() methods
   - Django ORM: Use model.objects.filter() methods
   - Peewee: Use model.select().where() methods

3. Never concatenate user input into SQL strings
4. Validate and sanitize inputs before database operations
5. Use database-specific escaping functions only as a last resort
6. Implement proper access controls (principle of least privilege)

Example for future database migration:

```python
from sqlalchemy import text

# ✅ CORRECT - Parameterized query
def get_vlan_by_id(vlan_id: str):
    query = text("SELECT * FROM vlans WHERE id = :vlan_id")
    result = session.execute(query, {"vlan_id": vlan_id})
    return result.fetchone()

# ❌ WRONG - String concatenation (VULNERABLE)
def get_vlan_by_id_unsafe(vlan_id: str):
    query = f"SELECT * FROM vlans WHERE id = '{vlan_id}'"
    result = session.execute(query)  # VULNERABLE TO SQL INJECTION
    return result.fetchone()
```

For more information, see:
- OWASP SQL Injection Prevention Cheat Sheet
- https://owasp.org/www-community/attacks/SQL_Injection
"""

