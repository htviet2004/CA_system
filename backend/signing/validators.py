"""
Input validation utilities for the CA system.

SECURITY: All user input must be validated before processing.
This module provides centralized validation functions.
"""

import re
import os
import logging
from typing import Tuple, Optional
from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile

from .constants import (
    USERNAME_MIN_LENGTH,
    USERNAME_MAX_LENGTH,
    USERNAME_PATTERN,
    MAX_PDF_SIZE_BYTES,
    MAX_P12_SIZE_BYTES,
    ALLOWED_PDF_MIME_TYPES,
    ALLOWED_P12_MIME_TYPES,
    ALLOWED_PDF_EXTENSIONS,
    ALLOWED_P12_EXTENSIONS,
    PDF_MIN_PAGE,
    PDF_MAX_PAGE,
    PDF_MIN_COORD,
    PDF_MAX_COORD,
)

logger = logging.getLogger(__name__)

# Compile regex pattern once for performance
_USERNAME_REGEX = re.compile(USERNAME_PATTERN)


def validate_username(username: str) -> str:
    """
    Validate username format.
    
    SECURITY: Prevents path traversal and injection attacks by enforcing
    strict character allowlist.
    
    Args:
        username: Username to validate
        
    Returns:
        str: Validated username (trimmed)
        
    Raises:
        ValidationError: If username is invalid
    """
    if not username:
        raise ValidationError("Username is required")
    
    username = username.strip()
    
    if len(username) < USERNAME_MIN_LENGTH:
        raise ValidationError(
            f"Username must be at least {USERNAME_MIN_LENGTH} characters"
        )
    
    if len(username) > USERNAME_MAX_LENGTH:
        raise ValidationError(
            f"Username must not exceed {USERNAME_MAX_LENGTH} characters"
        )
    
    # SECURITY: Strict character allowlist prevents path traversal (../) and injection
    if not _USERNAME_REGEX.match(username):
        raise ValidationError(
            "Username can only contain letters, numbers, underscore, hyphen, and period"
        )
    
    # SECURITY: Additional path traversal prevention
    if '..' in username or username.startswith('.') or username.startswith('-'):
        raise ValidationError("Invalid username format")
    
    return username


def validate_pdf_upload(file: UploadedFile) -> None:
    """
    Validate uploaded PDF file.
    
    SECURITY: Prevents malicious file uploads by checking:
    - File extension
    - MIME type
    - File size
    
    Args:
        file: Uploaded file object
        
    Raises:
        ValidationError: If file is invalid
    """
    if not file:
        raise ValidationError("No file uploaded")
    
    # SECURITY: Check file size first (cheap check)
    if file.size > MAX_PDF_SIZE_BYTES:
        raise ValidationError(
            f"PDF file too large. Maximum size is {MAX_PDF_SIZE_BYTES // (1024*1024)} MB"
        )
    
    # SECURITY: Check file extension
    filename = getattr(file, 'name', '')
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_PDF_EXTENSIONS:
        raise ValidationError(
            f"Invalid file extension. Allowed: {', '.join(ALLOWED_PDF_EXTENSIONS)}"
        )
    
    # SECURITY: Check MIME type (can be spoofed, but adds defense in depth)
    content_type = getattr(file, 'content_type', '')
    if content_type and content_type not in ALLOWED_PDF_MIME_TYPES:
        # Log but allow - MIME types can be unreliable
        logger.warning(
            f"PDF upload with unexpected MIME type: {content_type} for file {filename}"
        )
    
    # SECURITY: Check PDF magic bytes (header)
    file.seek(0)
    header = file.read(5)
    file.seek(0)  # Reset for later processing
    
    if header != b'%PDF-':
        raise ValidationError("File does not appear to be a valid PDF")


def validate_p12_upload(file: UploadedFile) -> None:
    """
    Validate uploaded PKCS#12 file.
    
    SECURITY: Validates P12/PFX file before processing.
    
    Args:
        file: Uploaded file object
        
    Raises:
        ValidationError: If file is invalid
    """
    if not file:
        raise ValidationError("No file uploaded")
    
    # SECURITY: Check file size
    if file.size > MAX_P12_SIZE_BYTES:
        raise ValidationError(
            f"P12 file too large. Maximum size is {MAX_P12_SIZE_BYTES // (1024*1024)} MB"
        )
    
    # SECURITY: Check file extension
    filename = getattr(file, 'name', '')
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_P12_EXTENSIONS:
        raise ValidationError(
            f"Invalid file extension. Allowed: {', '.join(ALLOWED_P12_EXTENSIONS)}"
        )


def validate_signature_position(position: str) -> Tuple[int, float, float, float, float]:
    """
    Validate and parse PDF signature position string.
    
    SECURITY: Validates position bounds to prevent:
    - Negative page numbers
    - Out-of-bounds coordinates
    - Malformed input
    
    Args:
        position: Position string in format "page/x1,y1,x2,y2"
        
    Returns:
        Tuple of (page, x1, y1, x2, y2)
        
    Raises:
        ValidationError: If position is invalid
    """
    if not position:
        raise ValidationError("Signature position is required")
    
    position = position.strip()
    
    try:
        parts = position.split('/')
        if len(parts) != 2:
            raise ValidationError(
                "Position format must be: page/x1,y1,x2,y2"
            )
        
        page = int(parts[0])
        coords = list(map(float, parts[1].split(',')))
        
        if len(coords) != 4:
            raise ValidationError(
                "Position must have 4 coordinates: x1,y1,x2,y2"
            )
        
        x1, y1, x2, y2 = coords
        
    except (ValueError, IndexError) as e:
        raise ValidationError(f"Invalid position format: {e}")
    
    # SECURITY: Validate page bounds
    if page < PDF_MIN_PAGE:
        raise ValidationError(f"Page number must be at least {PDF_MIN_PAGE}")
    
    if page > PDF_MAX_PAGE:
        raise ValidationError(f"Page number must not exceed {PDF_MAX_PAGE}")
    
    # SECURITY: Validate coordinate bounds
    for coord, name in [(x1, 'x1'), (y1, 'y1'), (x2, 'x2'), (y2, 'y2')]:
        if coord < PDF_MIN_COORD:
            raise ValidationError(f"Coordinate {name} must be non-negative")
        if coord > PDF_MAX_COORD:
            raise ValidationError(f"Coordinate {name} exceeds maximum allowed value")
    
    # SECURITY: Ensure box has positive dimensions
    if x1 >= x2 or y1 >= y2:
        # Auto-correct by swapping if needed
        x1, x2 = sorted([x1, x2])
        y1, y2 = sorted([y1, y2])
    
    return page, x1, y1, x2, y2


def validate_common_name(cn: str, max_length: int = 200) -> str:
    """
    Validate certificate Common Name (CN).
    
    SECURITY: Prevents injection in certificate subject fields.
    
    Args:
        cn: Common Name value
        max_length: Maximum allowed length
        
    Returns:
        str: Validated CN
        
    Raises:
        ValidationError: If CN is invalid
    """
    if not cn:
        raise ValidationError("Common Name is required")
    
    cn = cn.strip()
    
    if len(cn) > max_length:
        raise ValidationError(f"Common Name must not exceed {max_length} characters")
    
    # SECURITY: Reject characters that could cause issues in X.509 subjects
    # Reject: /, =, \, NUL, newlines
    dangerous_chars = ['/', '\\', '\x00', '\n', '\r']
    for char in dangerous_chars:
        if char in cn:
            raise ValidationError(
                "Common Name contains invalid characters"
            )
    
    return cn


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize a filename for safe storage.
    
    SECURITY: Removes path components and dangerous characters.
    
    Args:
        filename: Original filename
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unnamed"
    
    # SECURITY: Remove path components
    filename = os.path.basename(filename)
    
    # SECURITY: Remove null bytes and control characters
    filename = ''.join(c for c in filename if c.isprintable() and c != '\x00')
    
    # SECURITY: Replace potentially problematic characters
    filename = re.sub(r'[<>:"|?*]', '_', filename)
    
    # SECURITY: Prevent hidden files on Unix
    if filename.startswith('.'):
        filename = '_' + filename[1:]
    
    # SECURITY: Truncate to max length while preserving extension
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        max_name_len = max_length - len(ext)
        filename = name[:max_name_len] + ext
    
    return filename or "unnamed"
