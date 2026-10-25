#!/usr/bin/env bash
# Sensor sống: mỗi cửa sổ WINDOW giây, bắt gói trên cổng mạng -> trích xuất luồng -> nạp vào pipeline.
# Biến hệ thống từ "replay pcap" thành "giám sát trực tiếp" lưu lượng đến/đi của chính VPS.
# Chạy bằng dịch vụ ids-sensor.service (User=root, vì tcpdump cần quyền bắt gói).
#
# Cấu hình qua biến môi trường (đặt trong file service nếu muốn đổi):
#   IFACE   cổng mạng cần nghe (mặc định: cổng ra Internet; dùng 'tailscale0' để nghe mạng riêng)
#   WINDOW  độ dài mỗi cửa sổ bắt gói, giây (mặc định 30)
set -uo pipefail

APP_DIR="${APP_DIR:-/opt/aahkl}"
PY="$APP_DIR/backend/.venv/bin/python"
WINDOW="${WINDOW:-30}"
# Tự tìm cổng ra Internet nếu không chỉ định IFACE
IFACE="${IFACE:-$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || echo eth0)}"
CAPDIR="/tmp/ids_sensor"

mkdir -p "$CAPDIR"
cd "$APP_DIR/backend" || exit 1
echo "Sensor bắt đầu: cổng=$IFACE, cửa sổ=${WINDOW}s"

while true; do
  CAP="$CAPDIR/cap_$(date +%Y%m%d_%H%M%S).pcap"
  # Bắt gói TCP/UDP trong WINDOW giây (snaplen đầy đủ để độ dài gói chính xác như CICFlowMeter)
  timeout "$WINDOW" tcpdump -i "$IFACE" -n -w "$CAP" '(tcp or udp)' >/dev/null 2>&1 || true
  if [[ -s "$CAP" ]]; then
    PYTHONUTF8=1 "$PY" -m tools.pcap_to_incoming "$CAP" || true
  fi
  rm -f "$CAP"
  # Dọn CSV cũ hơn 60 phút để không đầy ổ đĩa (pipeline đã đọc xong từ lâu)
  find data/incoming -name 'sensor_*.csv' -mmin +60 -delete 2>/dev/null || true
done
