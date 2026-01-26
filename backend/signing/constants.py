"""
Security-related constants for the CA system.
Centralizes magic strings and security parameters.

SECURITY: These constants define security-critical parameters.
Changes should be reviewed by security team.
"""

# =============================================================================
# KEY DERIVATION PARAMETERS (PBKDF2)
# =============================================================================
# SECURITY: Higher iteration counts increase brute-force resistance.
# NIST recommends minimum 10,000 iterations. We use 480,000 for modern hardware.
PBKDF2_ITERATIONS = 480_000  # OWASP 2023 recommendation for SHA256
PBKDF2_SALT_LENGTH = 32  # 256-bit salt
PBKDF2_KEY_LENGTH = 32  # 256-bit key for Fernet (AES-128)
PBKDF2_HASH_ALGORITHM = 'sha256'

# SECURITY: Static salt for key derivation. Must be kept secret alongside SECRET_KEY.
# In production, this should also be loaded from environment.
PBKDF2_SALT_ENV_VAR = 'FERNET_SALT'

# =============================================================================
# PASSWORD GENERATION
# =============================================================================
# SECURITY: Minimum entropy for generated passwords
PASSWORD_MIN_LENGTH = 24  # ~144 bits of entropy with urlsafe base64

# =============================================================================
# CERTIFICATE PARAMETERS
# =============================================================================
CERT_DEFAULT_DAYS = 365
CERT_RSA_KEY_BITS = 2048
CERT_SIGNATURE_HASH = 'sha256'

# =============================================================================
# FILE UPLOAD LIMITS
# =============================================================================
# SECURITY: Prevents DoS via large file uploads
MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_P12_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

ALLOWED_PDF_MIME_TYPES = frozenset([
    'application/pdf',
])

ALLOWED_P12_MIME_TYPES = frozenset([
    'application/x-pkcs12',
    'application/pkcs12',
    'application/octet-stream',  # Generic binary, often used for P12
])

ALLOWED_PDF_EXTENSIONS = frozenset(['.pdf'])
ALLOWED_P12_EXTENSIONS = frozenset(['.p12', '.pfx'])

# =============================================================================
# USERNAME VALIDATION
# =============================================================================
# SECURITY: Strict allowlist prevents path traversal and injection attacks
USERNAME_MIN_LENGTH = 2
USERNAME_MAX_LENGTH = 64
# Only alphanumeric, underscore, hyphen, and period
USERNAME_PATTERN = r'^[a-zA-Z0-9_\-\.]+$'

# =============================================================================
# PDF SIGNATURE BOUNDS
# =============================================================================
# SECURITY: Prevents signature placement outside valid PDF areas
PDF_MIN_PAGE = 1
PDF_MAX_PAGE = 10000  # Reasonable upper bound
PDF_MIN_COORD = 0
PDF_MAX_COORD = 10000  # Reasonable upper bound for PDF points

# =============================================================================
# SIGNING DEFAULTS
# =============================================================================
SIGNING_DEFAULT_REASON = 'Digital Signature'
SIGNING_DEFAULT_LOCATION = 'Vietnam'

# =============================================================================
# AUDIT LOG ACTIONS
# =============================================================================
AUDIT_ACTION_CERT_ISSUED = 'certificate_issued'
AUDIT_ACTION_CERT_REVOKED = 'certificate_revoked'
AUDIT_ACTION_PDF_SIGNED = 'pdf_signed'
AUDIT_ACTION_PDF_VERIFIED = 'pdf_verified'
AUDIT_ACTION_LOGIN_SUCCESS = 'login_success'
AUDIT_ACTION_LOGIN_FAILED = 'login_failed'
AUDIT_ACTION_PASSWORD_RESET = 'password_reset'
AUDIT_ACTION_P12_UPLOADED = 'p12_uploaded'

AUDIT_RESULT_SUCCESS = 'success'
AUDIT_RESULT_FAILURE = 'failure'

# =============================================================================
# REQUIRED ENVIRONMENT VARIABLES
# =============================================================================
# SECURITY: System will fail to start if these are not set in production
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
]

# Optional but recommended
RECOMMENDED_ENV_VARS = [
    'FERNET_SALT',
    'DEBUG',
]
