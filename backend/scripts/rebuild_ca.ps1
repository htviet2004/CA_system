# Script để tạo lại toàn bộ CA infrastructure với thông tin DUT chuẩn
# Chạy từ backend directory: powershell -ExecutionPolicy Bypass .\scripts\rebuild_ca.ps1

param(
    [switch]$Force = $false
)

Write-Host "=== DUT CA Infrastructure Rebuild ===" -ForegroundColor Cyan

# Thông tin tổ chức - CHỈNH SỬA Ở ĐÂY
$ORG_NAME = "Da Nang University of Science and Technology"
$ORG_SHORT = "DUT"
$OU_ROOT = "Information Technology"
$OU_INTERMEDIATE = "Intermediate Certification Authority"
$COUNTRY = "VN"
$STATE = "Da Nang"
$LOCALITY = "Da Nang"
$EMAIL_DOMAIN = "dut.udn.vn"

# Paths
$CERTS_DIR = "certs"
$ROOT_DIR = "$CERTS_DIR\root-ca"
$INTERMEDIATE_DIR = "$CERTS_DIR\intermediate-ca"

# Kiểm tra xác nhận
if (-not $Force) {
    Write-Host "`nCẢNH BÁO: Script này sẽ XÓA và TẠO LẠI toàn bộ CA!" -ForegroundColor Yellow
    Write-Host "- Root CA và Intermediate CA sẽ bị xóa" -ForegroundColor Yellow
    Write-Host "- TẤT CẢ certificates hiện tại sẽ KHÔNG HỢP LỆ" -ForegroundColor Yellow
    Write-Host "- Cần issue lại certificates cho tất cả users" -ForegroundColor Yellow
    $confirm = Read-Host "`nBạn có chắc chắn muốn tiếp tục? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Đã hủy." -ForegroundColor Red
        exit 1
    }
}

# Backup CA hiện tại
Write-Host "`n[1/7] Backup CA hiện tại..." -ForegroundColor Green
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "certs_backup_$timestamp"
if (Test-Path $CERTS_DIR) {
    Copy-Item -Path $CERTS_DIR -Destination $backupDir -Recurse -Force
    Write-Host "Đã backup vào: $backupDir" -ForegroundColor Gray
}

# Xóa CA cũ
Write-Host "`n[2/7] Xóa CA cũ..." -ForegroundColor Green
Remove-Item -Path $ROOT_DIR -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $INTERMEDIATE_DIR -Recurse -Force -ErrorAction SilentlyContinue

# Tạo cấu trúc thư mục
Write-Host "`n[3/7] Tạo cấu trúc thư mục..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "$ROOT_DIR" | Out-Null
New-Item -ItemType Directory -Force -Path "$ROOT_DIR\newcerts" | Out-Null
New-Item -ItemType Directory -Force -Path "$INTERMEDIATE_DIR\certs" | Out-Null
New-Item -ItemType Directory -Force -Path "$INTERMEDIATE_DIR\crl" | Out-Null
New-Item -ItemType Directory -Force -Path "$INTERMEDIATE_DIR\csr" | Out-Null
New-Item -ItemType Directory -Force -Path "$INTERMEDIATE_DIR\newcerts" | Out-Null
New-Item -ItemType Directory -Force -Path "$INTERMEDIATE_DIR\private" | Out-Null

# Khởi tạo database files - index.txt phải là file rỗng hoàn toàn
New-Item -ItemType File -Path "$ROOT_DIR\index.txt" -Force | Out-Null
"1000" | Out-File -FilePath "$ROOT_DIR\serial" -Encoding ASCII -NoNewline
New-Item -ItemType File -Path "$INTERMEDIATE_DIR\index.txt" -Force | Out-Null
"1000" | Out-File -FilePath "$INTERMEDIATE_DIR\serial" -Encoding ASCII -NoNewline
"1000" | Out-File -FilePath "$INTERMEDIATE_DIR\crlnumber" -Encoding ASCII -NoNewline

# Copy OpenSSL config files từ backup hoặc tạo mới
Write-Host "Copying OpenSSL config files..." -ForegroundColor Gray
if (Test-Path "$backupDir\root-ca\root-openssl.cnf") {
    Copy-Item "$backupDir\root-ca\root-openssl.cnf" "$ROOT_DIR\" -Force
    Copy-Item "$backupDir\intermediate-ca\intermediate-openssl.cnf" "$INTERMEDIATE_DIR\" -Force
} else {
    # Tạo root-openssl.cnf
    @"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
database          = `$dir/index.txt
new_certs_dir     = `$dir/newcerts
certificate       = `$dir/rootCA.crt
private_key       = `$dir/rootCA.key
serial            = `$dir/serial
default_md        = sha256
policy            = policy_loose
x509_extensions   = v3_intermediate_ca
default_days      = 3650

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"@ | Out-File -FilePath "$ROOT_DIR\root-openssl.cnf" -Encoding ASCII

    # Tạo intermediate-openssl.cnf
    @"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = `$dir/certs
crl_dir           = `$dir/crl
new_certs_dir     = `$dir/newcerts
database          = `$dir/index.txt
serial            = `$dir/serial
private_key       = `$dir/private/intermediate.key
certificate       = `$dir/certs/intermediateCA.crt
default_md        = sha256
policy            = policy_loose
email_in_dn       = no
copy_extensions   = copy
default_days      = 730

[ policy_loose ]
commonName              = supplied
organizationName        = optional
organizationalUnitName  = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
emailAddress            = optional

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = emailProtection, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"@ | Out-File -FilePath "$INTERMEDIATE_DIR\intermediate-openssl.cnf" -Encoding ASCII
}


# Tạo Root CA
Write-Host "`n[4/7] Tạo Root CA..." -ForegroundColor Green
$rootSubject = "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG_NAME/OU=$OU_ROOT/CN=$ORG_SHORT Root CA"

Write-Host "Subject: $rootSubject" -ForegroundColor Gray
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$ROOT_DIR\rootCA.key" 2>&1 | Out-Null
openssl req -new -x509 -key "$ROOT_DIR\rootCA.key" -sha256 -days 7300 -subj $rootSubject -out "$ROOT_DIR\rootCA.crt"

if ($LASTEXITCODE -eq 0) {
    Write-Host "Root CA created successfully" -ForegroundColor Green
} else {
    Write-Host "Error creating Root CA" -ForegroundColor Red
    exit 1
}

# Tạo Intermediate CA
Write-Host "`n[5/7] Tạo Intermediate CA..." -ForegroundColor Green
$intermediateSubject = "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORG_NAME/OU=$OU_INTERMEDIATE/CN=$ORG_SHORT Intermediate CA 2026"

Write-Host "Subject: $intermediateSubject" -ForegroundColor Gray
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$INTERMEDIATE_DIR\private\intermediate.key" 2>&1 | Out-Null
openssl req -new -key "$INTERMEDIATE_DIR\private\intermediate.key" -sha256 -subj $intermediateSubject -out "$INTERMEDIATE_DIR\csr\intermediate.csr"

# Sign Intermediate CA with Root CA
Set-Location $ROOT_DIR
openssl ca -batch -config "root-openssl.cnf" -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in "..\intermediate-ca\csr\intermediate.csr" -out "..\intermediate-ca\certs\intermediateCA.crt"
$exitCode = $LASTEXITCODE
Set-Location ..\..

if ($exitCode -eq 0) {
    Write-Host "Intermediate CA created successfully" -ForegroundColor Green
} else {
    Write-Host "Error creating Intermediate CA" -ForegroundColor Red
    exit 1
}

# Create certificate chain
Write-Host "`n[6/7] Create certificate chain..." -ForegroundColor Green
Get-Content "$INTERMEDIATE_DIR\certs\intermediateCA.crt", "$ROOT_DIR\rootCA.crt" | Set-Content "$INTERMEDIATE_DIR\certs\ca-chain.crt"
Write-Host "Chain certificate created" -ForegroundColor Green

# Verify
Write-Host "`n[7/7] Verify CA..." -ForegroundColor Green
openssl verify -CAfile "$ROOT_DIR\rootCA.crt" "$INTERMEDIATE_DIR\certs\intermediateCA.crt"

# Results
Write-Host "`n=== COMPLETED ===" -ForegroundColor Cyan
Write-Host "`nRoot CA: $ROOT_DIR\rootCA.crt" -ForegroundColor Green
Write-Host "Intermediate CA: $INTERMEDIATE_DIR\certs\intermediateCA.crt" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Re-issue certificates for all users:" -ForegroundColor White
Write-Host "   `$users = @('viet', 'user1', 'user2', 'test')" -ForegroundColor Gray
Write-Host "   foreach(`$u in `$users) { .venv\Scripts\python.exe scripts\issue_cert.py `$u changeit }" -ForegroundColor Gray
Write-Host "`n2. Import rootCA.crt to Trusted Root on client machines" -ForegroundColor White
Write-Host "`n3. Restart Django server to load new CA" -ForegroundColor White
