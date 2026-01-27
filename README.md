# CA System - Certificate Authority & PDF Digital Signing

A full-stack web application for digital certificate management and PDF document signing. Built with Django (backend) and React + Vite (frontend).

## Table of Contents

- [System Requirements](#system-requirements)
- [Project Structure](#project-structure)
- [Environment Setup](#environment-setup)
- [Backend Setup (Django)](#backend-setup-django)
- [Frontend Setup (React + Vite)](#frontend-setup-react--vite)
- [Running the Full System](#running-the-full-system)
- [Certificate Authority Setup](#certificate-authority-setup)
- [Important Security Notes](#important-security-notes)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

| Component | Required Version | Notes |
|-----------|------------------|-------|
| **Python** | 3.10 or higher | Tested with Python 3.11 |
| **Node.js** | 18.x or higher | Required for frontend |
| **npm** | 9.x or higher | Comes with Node.js |
| **Database** | SQLite (dev) / MySQL 8.0+ (prod) | SQLite is default for development |
| **OpenSSL** | 1.1.1+ | Required for certificate generation |

### Verify Installations

```bash
python3 --version   # Should output Python 3.10+
node --version      # Should output v18+
npm --version       # Should output 9+
openssl version     # Should output OpenSSL 1.1.1+
```

---

## Project Structure

```
CA_system/
├── backend/                    # Django backend
│   ├── backend/               # Django project settings
│   ├── signing/               # PDF signing module
│   ├── usercerts/             # User certificate management
│   ├── usermanage/            # User & admin management
│   ├── certs/                 # CA certificates (Root & Intermediate)
│   │   ├── root-ca/          # Root CA files
│   │   └── intermediate-ca/   # Intermediate CA files
│   ├── users/                 # User certificate storage (gitignored)
│   ├── signed_documents/      # Signed PDFs storage (gitignored)
│   └── requirements.txt       # Python dependencies
├── frontend/                   # React + Vite frontend
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── static/styles/     # CSS stylesheets
│   │   ├── api.js            # API client
│   │   └── App.jsx           # Main application
│   └── package.json           # Node.js dependencies
└── README.md
```

---

## Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/CA_system.git
cd CA_system
```

### 2. Create Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
.\venv\Scripts\activate
```

### 3. Create Environment File

Copy the example environment file and configure it:

```bash
cd backend
cp .env.example .env
```

### 4. Configure Environment Variables

Open `backend/.env` and set the required values:

```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(50))"

# Generate FERNET_SALT  
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated values into your `.env` file:

```env
SECRET_KEY=paste-your-generated-secret-key-here
FERNET_SALT=paste-your-generated-salt-here
```

> **Note:** See `.env.example` for all available configuration options including database and production security settings.

#### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | **Yes** | - | Django secret key for cryptographic signing |
| `FERNET_SALT` | Recommended | Derived from SECRET_KEY | Salt for certificate encryption |
| `DEBUG` | No | `False` | Enable Django debug mode |
| `ALLOWED_HOSTS` | No | `localhost,127.0.0.1` | Allowed hostnames |
| `DB_ENGINE` | No | `sqlite3` | Database engine (`sqlite3` or `mysql`) |
| `DB_NAME` | No | `ca_system` | Database name |
| `DB_USER` | No | `root` | Database username |
| `DB_PASSWORD` | No | - | Database password |
| `DB_HOST` | No | `localhost` | Database host |
| `DB_PORT` | No | `3306` | Database port |
| `SIGNED_PDF_RETENTION_DAYS` | No | `14` | Days to keep signed PDFs |

---

## Backend Setup (Django)

### 1. Install Python Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Create Required Directories

```bash
# Create directories for user data and logs
mkdir -p users signed_documents logs
```

### 3. Run Database Migrations

```bash
python manage.py migrate
```

### 4. Create Superuser (Admin Account)

```bash
python manage.py createsuperuser
```

Follow the prompts to create an admin account.

### 5. Run Development Server

```bash
python manage.py runserver
```

The backend API will be available at: `http://127.0.0.1:8000`

---

## Frontend Setup (React + Vite)

### 1. Install Node Dependencies

```bash
cd frontend
npm install
```

### 2. Run Development Server

```bash
npm start
```

The frontend will be available at: `http://localhost:3000`

> **Note:** The frontend is configured to proxy API requests to the Django backend at `http://127.0.0.1:8000`.

### 3. Build for Production (Optional)

```bash
npm run build
```

This creates a production build in `frontend/dist/` which Django can serve.

---

## Running the Full System

### Development Mode

Open **two terminal windows**:

**Terminal 1 - Backend:**
```bash
cd CA_system/backend
source ../venv/bin/activate  # Activate virtual environment
python manage.py runserver
```

**Terminal 2 - Frontend:**
```bash
cd CA_system/frontend
npm start
```

### Access URLs

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | React application |
| Backend API | http://127.0.0.1:8000/api/ | REST API endpoints |
| Django Admin | http://127.0.0.1:8000/admin/ | Admin interface |

If needed, update API base URL in `frontend/src/api.js`
---

## Certificate Authority Setup

The system uses a two-tier PKI hierarchy:

```
Root CA
  └── Intermediate CA
        └── User Certificates
```

### CA Directory Structure

```
backend/certs/
├── root-ca/
│   ├── rootCA.crt             # Root CA certificate
│   ├── rootCA.key             # Root CA private key (KEEP SECRET!)
│   ├── root-openssl.cnf       # OpenSSL config
│   ├── index.txt              # Certificate database
│   └── serial                 # Serial number counter
└── intermediate-ca/
    ├── certs/
    │   ├── intermediateCA.crt  # Intermediate CA certificate
    │   └── ca-chain.crt        # Full certificate chain
    ├── private/
    │   └── intermediate.key    # Intermediate CA private key
    ├── intermediate-openssl.cnf
    ├── index.txt
    └── serial
```

### Initializing Certificate Authority

If you need to set up a new CA (fresh installation):

```bash
cd backend

# 1. Create Root CA
mkdir -p certs/root-ca/newcerts
cd certs/root-ca
echo 01 > serial
touch index.txt

# Generate Root CA key and certificate
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key \
    -sha256 -days 3650 \
    -config root-openssl.cnf \
    -out rootCA.crt

# 2. Create Intermediate CA
cd ../intermediate-ca
mkdir -p certs csr private
echo 01 > serial
touch index.txt
echo 01 > crlnumber

# Generate Intermediate CA key and CSR
openssl genrsa -out private/intermediate.key 4096
openssl req -new -key private/intermediate.key \
    -config intermediate-openssl.cnf \
    -out csr/intermediate.csr

# Sign Intermediate CA with Root CA
cd ../root-ca
openssl ca -config root-openssl.cnf \
    -extensions v3_intermediate_ca \
    -days 1825 -notext -md sha256 \
    -in ../intermediate-ca/csr/intermediate.csr \
    -out ../intermediate-ca/certs/intermediateCA.crt

# Create certificate chain
cat ../intermediate-ca/certs/intermediateCA.crt rootCA.crt > ../intermediate-ca/certs/ca-chain.crt
```

### User Certificate Generation

User certificates are automatically generated during user registration. They are stored in:

```
backend/users/{username}/
├── user.p12.enc      # Encrypted PKCS#12 bundle
├── p12.pass.enc      # Encrypted passphrase
└── v3_ext.cnf        # Certificate extensions config
```

---

## Important Security Notes

### Development Environment

1. **Never commit `.env` files** - They contain secrets
2. **Keep `DEBUG=True` only in development** - Exposes sensitive info
3. **SQLite is fine for development** - Use MySQL/PostgreSQL in production

### Production Environment

1. **Generate strong keys:**
   ```bash
   # Generate SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(50))"
   
   # Generate FERNET_SALT
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Enable security settings in `.env`:**
   ```env
   DEBUG=False
   SECURE_SSL_REDIRECT=True
   SESSION_COOKIE_SECURE=True
   CSRF_COOKIE_SECURE=True
   SECURE_HSTS_SECONDS=31536000
   ```

3. **File permissions (Linux/macOS):**
   ```bash
   # Protect private keys
   chmod 600 backend/certs/root-ca/rootCA.key
   chmod 600 backend/certs/intermediate-ca/private/intermediate.key
   chmod 700 backend/users/
   
   # Protect .env file
   chmod 600 backend/.env
   ```

4. **Certificate Security:**
   - Store Root CA key offline (not on production server)
   - Intermediate CA key should have restricted access
   - User certificates are encrypted with Fernet (AES-128)

### Folder Permission Summary

| Path | Permission | Owner | Description |
|------|------------|-------|-------------|
| `certs/root-ca/rootCA.key` | 600 | www-data | Root CA private key |
| `certs/intermediate-ca/private/` | 700 | www-data | Intermediate CA keys |
| `users/` | 700 | www-data | User certificate storage |
| `signed_documents/` | 700 | www-data | Signed PDF storage |
| `.env` | 600 | www-data | Environment secrets |

---

## Troubleshooting

### Common Issues

**1. "SECRET_KEY environment variable is not set"**
```bash
# Create .env file with SECRET_KEY
echo "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(50))')" > backend/.env
echo "DEBUG=True" >> backend/.env
```

**2. "ModuleNotFoundError: No module named 'xyz'"**
```bash
# Make sure virtual environment is activated
source venv/bin/activate
pip install -r backend/requirements.txt
```

**3. MySQL connection errors**
```bash
# Install MySQL client
pip install mysqlclient

# On macOS, you may need:
brew install mysql-client
export LDFLAGS="-L/opt/homebrew/opt/mysql-client/lib"
export CPPFLAGS="-I/opt/homebrew/opt/mysql-client/include"
```

**4. Frontend proxy errors**
- Ensure Django backend is running on port 8000
- Check `frontend/vite.config.js` proxy settings

**5. Certificate generation fails**
```bash
# Check OpenSSL version
openssl version

# Ensure CA files exist
ls -la backend/certs/intermediate-ca/certs/
ls -la backend/certs/intermediate-ca/private/
```

### Logs

- Django logs: Console output when running `manage.py runserver`
- Security logs: `backend/logs/security.log` (if directory exists)

---

## License

This project is developed for educational purposes as part of a university course on Information Security.

---

## Contributors

- Development Team - CA System Project
