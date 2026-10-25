#!/usr/bin/env bash
# Triển khai hệ thống IDS AAHKL lên Ubuntu 22.04. Chạy bằng root, từ thư mục gốc repo đã clone về /opt/aahkl:
#   sudo bash deploy/setup_vps.sh
#
# Làm các việc: cài gói hệ thống (Python 3.12, PostgreSQL 16, Nginx, Node 20) -> tạo user dịch vụ 'ids'
# -> tạo CSDL và tài khoản -> môi trường Python + thư viện -> backend/.env -> seed bảng + admin
# -> build frontend -> cài Nginx + 2 dịch vụ systemd -> bật tường lửa. Chạy lại nhiều lần không hỏng.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/aahkl}"
SERVICE_USER="ids"
WEB_ROOT="/var/www/ids"
PSQL="sudo -u postgres psql"

if [[ $EUID -ne 0 ]]; then echo "Phai chay bang root: sudo bash deploy/setup_vps.sh"; exit 1; fi
if [[ ! -f "$APP_DIR/backend/requirements.txt" ]]; then
  echo "Khong thay $APP_DIR/backend. Hay clone repo vao $APP_DIR truoc (xem deploy/README.md)."; exit 1
fi

echo "== 1/9 Goi he thong"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common curl ca-certificates gnupg git ufw
add-apt-repository -y ppa:deadsnakes/ppa
# Kho chính thức PGDG để lấy PostgreSQL 16 (Ubuntu 22.04 mặc định chỉ có 14, luận văn dùng 16)
if [[ ! -f /etc/apt/sources.list.d/pgdg.list ]]; then
  install -d /usr/share/postgresql-common/pgdg
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
  echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(. /etc/os-release; echo "$VERSION_CODENAME")-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
fi
apt-get update -y
# Chỉ cài postgresql-16 (KHÔNG cài gói meta 'postgresql' để tránh dựng thêm cluster 14 chiếm cổng 5432)
apt-get install -y python3.12 python3.12-venv python3.12-dev \
                   postgresql-16 postgresql-contrib-16 nginx
if ! command -v node >/dev/null 2>&1 || [[ "$(node -v 2>/dev/null | cut -dv -f2 | cut -d. -f1)" -lt 18 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo "== 2/9 User dich vu '$SERVICE_USER'"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"

echo "== 3/9 CSDL PostgreSQL (role ids_app + database ids, ids_test)"
systemctl enable --now postgresql
$PSQL -v ON_ERROR_STOP=1 -f "$APP_DIR/backend/scripts/setup_db.sql"

echo "== 4/9 Moi truong Python + thu vien"
cd "$APP_DIR/backend"
[[ -d .venv ]] || python3.12 -m venv .venv
./.venv/bin/python -m pip install -q --upgrade pip
./.venv/bin/python -m pip install -q -r requirements.txt

echo "== 5/9 backend/.env"
ADMIN_PW_NOTE=""
if [[ ! -f .env ]]; then
  cp "$APP_DIR/deploy/env.production.example" .env
  SECRET="$(./.venv/bin/python -c 'import secrets;print(secrets.token_urlsafe(32))')"
  sed -i "s#^JWT_SECRET=.*#JWT_SECRET=${SECRET}#" .env
  # Neu van con mat khau admin mau thi sinh ngau nhien (tranh dung mat khau da biet tren Internet)
  if grep -q '^ADMIN_PASSWORD=doi-mat-khau-nay-ngay$' .env; then
    ADMIN_PW="$(./.venv/bin/python -c 'import secrets;print(secrets.token_urlsafe(12))')"
    sed -i "s#^ADMIN_PASSWORD=.*#ADMIN_PASSWORD=${ADMIN_PW}#" .env
    ADMIN_PW_NOTE="   >>> Mat khau admin da sinh ngau nhien: ${ADMIN_PW}  (ghi lai, doi tiep trong Ho so)"
  fi
  echo "   Da tao backend/.env (JWT_SECRET ngau nhien)."
else
  echo "   backend/.env da co, giu nguyen."
fi

echo "== 6/9 Tao bang + tai khoan admin"
PYTHONUTF8=1 ./.venv/bin/python -m app.seed

echo "== 7/9 Build frontend"
cd "$APP_DIR/frontend"
npm ci --no-audit --no-fund
npm run build
mkdir -p "$WEB_ROOT"
rm -rf "${WEB_ROOT:?}/"*
cp -r dist/* "$WEB_ROOT/"

echo "== 8/9 Quyen + dich vu systemd + Nginx"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/backend"
install -m 644 "$APP_DIR/deploy/ids-api.service" /etc/systemd/system/ids-api.service
install -m 644 "$APP_DIR/deploy/ids-pipeline.service" /etc/systemd/system/ids-pipeline.service
install -m 644 "$APP_DIR/deploy/nginx-ids.conf" /etc/nginx/sites-available/ids
ln -sf /etc/nginx/sites-available/ids /etc/nginx/sites-enabled/ids
rm -f /etc/nginx/sites-enabled/default
systemctl daemon-reload
systemctl enable --now ids-api.service ids-pipeline.service
nginx -t && systemctl reload nginx

echo "== 9/9 Tuong lua (chi mo 22/80/443)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo
echo "XONG. Dashboard: http://$(hostname -I | awk '{print $1}')/"
[[ -n "$ADMIN_PW_NOTE" ]] && echo "$ADMIN_PW_NOTE"
echo "Tai khoan admin xem trong $APP_DIR/backend/.env (ADMIN_USERNAME / ADMIN_PASSWORD)."
echo "Kiem tra:  systemctl status ids-api ids-pipeline --no-pager"
echo "Nhat ky :  journalctl -u ids-pipeline -f"
