# Cài đặt lần đầu: môi trường Python, thư viện frontend, database. Chạy từ thư mục gốc project:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$psql = 'C:\Program Files\PostgreSQL\16\bin\psql.exe'

Write-Host '== 1. Môi trường Python cho backend' -ForegroundColor Cyan
Set-Location "$root\backend"
if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -q --upgrade pip
.\.venv\Scripts\python.exe -m pip install -q -r requirements-dev.txt
if (-not (Test-Path .env)) {
    $secret = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
    (Get-Content .env.example) -replace '^JWT_SECRET=.*', "JWT_SECRET=$secret" | Set-Content .env -Encoding utf8
    Write-Host 'Đã tạo backend\.env'
}

Write-Host '== 2. Database PostgreSQL (nhập mật khẩu tài khoản postgres khi được hỏi)' -ForegroundColor Cyan
& $psql -U postgres -h localhost -f scripts\setup_db.sql
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe -m app.seed

Write-Host '== 3. Thư viện frontend' -ForegroundColor Cyan
Set-Location "$root\frontend"
npm install --no-audit --no-fund

Write-Host 'Xong. Chạy hệ thống: powershell -ExecutionPolicy Bypass -File scripts\start.ps1' -ForegroundColor Green
