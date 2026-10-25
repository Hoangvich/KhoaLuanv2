"""pcap_to_incoming.py — trích xuất luồng từ một pcap rồi ghi CSV vào thư mục incoming.

Dùng cho SENSOR SỐNG: khác tools.replay_pcap ở chỗ GIỮ NGUYÊN Timestamp thật của gói
(không nhả dần, không dời về hiện tại, không cache), để pipeline thấy đúng thời điểm thật.

    python -m tools.pcap_to_incoming /tmp/cap.pcap
"""
import sys
import time
from pathlib import Path

from app.config import get_settings
from tools.pcap_flow_extractor import extract_pcap_to_df

# Bỏ các cột cờ đếm đúng (chỉ dùng để phân tích độ nhạy), như CSV của CICFlowMeter
DROP = ['true_FIN Flag', 'true_SYN Flag', 'true_RST Flag', 'true_PSH Flag', 'true_ACK Flag', 'true_URG Flag']


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    if len(sys.argv) < 2:
        print('Thiếu đường dẫn pcap'); return
    pcap = Path(sys.argv[1])
    df = extract_pcap_to_df(pcap).drop(columns=DROP, errors='ignore')
    if df.empty:
        print('Không có luồng TCP/UDP nào'); return
    s = get_settings()
    incoming = s.path(s.incoming_dir)
    incoming.mkdir(parents=True, exist_ok=True)
    out = incoming / f"sensor_{time.strftime('%Y%m%d_%H%M%S')}_{pcap.stem}.csv"
    df.to_csv(out, index=False)
    print(f'Đã ghi {len(df):,} luồng vào {out.name}')


if __name__ == '__main__':
    main()
