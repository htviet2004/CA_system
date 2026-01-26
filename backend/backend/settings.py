import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# SECURITY: SECRET_KEY must be loaded from environment in production.
# Never commit secrets to source control.
SECRET_KEY = os.environ.get('SECRET_KEY')

# SECURITY: Fail fast if SECRET_KEY is not set or is insecure
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(50))\" "
        "and add it to your .env file."
    )

# SECURITY: Reject known insecure placeholder values
if 'django-insecure' in SECRET_KEY.lower() or SECRET_KEY == 'your-super-secret-key-here':
    raise RuntimeError(
        "SECRET_KEY contains an insecure default value. "
        "Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(50))\""
    )

# SECURITY: DEBUG should default to False. Only enable explicitly in development.
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')

# SECURITY: Warn if DEBUG is enabled with a production-looking configuration
if DEBUG and os.environ.get('DJANGO_ENV') == 'production':
    import warnings
    warnings.warn(
        "DEBUG is enabled in a production environment. "
        "Set DEBUG=False in your environment.",
        RuntimeWarning
    )

# SECURITY: ALLOWED_HOSTS should be configured via environment in production
ALLOWED_HOSTS_STR = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS_STR.split(',') if h.strip()]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'signing',
    'usercerts',
    'usermanage',
    'django_extensions',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
TEMPLATES[0]["DIRS"] = [BASE_DIR / "templates"]
STATIC_URL = 'static/'
STATICFILES_DIRS = [
    BASE_DIR / "static",
    BASE_DIR.parent / 'frontend' / 'build',
    BASE_DIR.parent / 'frontend' / 'dist',
]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# =============================================================================
# SIGNED PDF STORAGE CONFIGURATION
# =============================================================================
# Directory for storing signed PDFs temporarily
SIGNED_PDF_STORAGE_DIR = BASE_DIR / "signed_documents"
# Retention period in days (configurable: 7-30 days)
SIGNED_PDF_RETENTION_DAYS = int(os.environ.get('SIGNED_PDF_RETENTION_DAYS', '14'))
# Maximum file size for signed PDFs (50MB)
SIGNED_PDF_MAX_SIZE = 52428800

PYHANKO_CLI = str(BASE_DIR.parent / 'env' / 'Scripts' / 'pyhanko.exe')
DEFAULT_SIGNER_P12 = str(BASE_DIR / 'users' / 'userA' / 'userA.p12')
DEFAULT_SIGNER_P12_PASSFILE = str(BASE_DIR / 'users' / 'userA' / 'p12.pass')

WSGI_APPLICATION = 'backend.wsgi.application'

# Database Configuration
# Supports both MySQL (production) and SQLite (development fallback)
# Set environment variables for MySQL connection
DATABASE_ENGINE = os.environ.get('DB_ENGINE', 'sqlite3')

if DATABASE_ENGINE == 'mysql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.mysql',
            'NAME': os.environ.get('DB_NAME', 'ca_system'),
            'USER': os.environ.get('DB_USER', 'root'),
            'PASSWORD': os.environ.get('DB_PASSWORD', ''),
            'HOST': os.environ.get('DB_HOST', 'localhost'),
            'PORT': os.environ.get('DB_PORT', '3306'),
            'OPTIONS': {
                'charset': 'utf8mb4',
                'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            },
        }
    }
else:
    # SQLite fallback for development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
# SECURITY: These settings enforce HTTPS and protect session cookies.
# Enable all of these in production.

# SECURITY: Redirect all HTTP requests to HTTPS
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False').lower() in ('true', '1', 'yes')

# SECURITY: Session cookie only sent over HTTPS
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 'yes')

# SECURITY: CSRF cookie only sent over HTTPS
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'False').lower() in ('true', '1', 'yes')

# SECURITY: HttpOnly flag on session cookie (prevents JavaScript access)
SESSION_COOKIE_HTTPONLY = True

# SECURITY: CSRF cookie HttpOnly (allows reading by frontend but adds defense in depth)
CSRF_COOKIE_HTTPONLY = False  # Must be False for frontend to read CSRF token

# SECURITY: SameSite cookie attribute
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# SECURITY: Enable HTTP Strict Transport Security (HSTS) in production
SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', '0'))  # Set to 31536000 in production
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'False').lower() in ('true', '1', 'yes')
SECURE_HSTS_PRELOAD = os.environ.get('SECURE_HSTS_PRELOAD', 'False').lower() in ('true', '1', 'yes')

# SECURITY: Prevent browsers from MIME-sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# SECURITY: Enable XSS filter in browsers
SECURE_BROWSER_XSS_FILTER = True

# SECURITY: Prevent clickjacking
X_FRAME_OPTIONS = 'DENY'

# SECURITY: CSRF trusted origins for cross-origin requests
CSRF_TRUSTED_ORIGINS_STR = os.environ.get('CSRF_TRUSTED_ORIGINS', '')
if CSRF_TRUSTED_ORIGINS_STR:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in CSRF_TRUSTED_ORIGINS_STR.split(',') if o.strip()]
else:
    CSRF_TRUSTED_ORIGINS = []

# SECURITY: File upload limits to prevent DoS
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50 MB

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'security': {
            'format': '[SECURITY] {levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'security_file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'formatter': 'security',
        } if (BASE_DIR / 'logs').exists() else {
            'class': 'logging.StreamHandler',
            'formatter': 'security',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'django.security': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'signing': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'usercerts': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'usermanage': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'