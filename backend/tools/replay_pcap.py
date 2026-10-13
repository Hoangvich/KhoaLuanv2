"""Phát lại pcap như một sensor CICFlowMeter: trích xuất luồng rồi ghi CSV vào thư mục incoming.

Dùng khi chưa có CICFlowMeter chạy trên cổng SPAN, hoặc để demo/kiểm thử lặp lại được.

    python -m tools.replay_pcap "../File Pcap/file pcap/portscan.pcap"
    python -m tools.replay_pcap benign.pcap bruteforce.pcap --speed 20     # nhả dần, nhanh gấp 20 lần
    python -m tools.replay_pcap ddos.pcap --instant                       # ghi một lần

Thời gian luồng được dời sao cho luồng đầu tiên bắt đầu ở thời điểm hiện tại (dashboard hiển thị như thật);
khoảng cách thời gian giữa các luồng giữ nguyên như trong pcap.
Kết quả trích xuất được lưu đệm ở data/replay_cache để lần sau không phải đọc lại pcap.
"""
import argparse
import sys
import time
from pathlib import Path

import pandas as pd

from app.config import BACKEND_DIR, get_settings

PCAP_DIR = BACKEND_DIR.parent / 'File Pcap' / 'file pcap'
CACHE_DIR = BACKEND_DIR / 'data' / 'replay_cache'
DROP = ['true_FIN Flag', 'true_SYN Flag', 'true_RST Flag', 'true_PSH Flag', 'true_ACK Flag', 'true_URG Flag']


def resolve(p: str) -> Path:
    q = Path(p)
    if q.exists():
        return q
    if (PCAP_DIR / p).exists():
        return PCAP_DIR / p
    raise FileNotFoundError(p)


def flows_of(pcap: Path) -> pd.DataFrame:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / (pcap.stem + '.csv')
    if cache.exists() and cache.stat().st_mtime >= pcap.stat().st_mtime:
        return pd.read_csv(cache)
    from tools.pcap_flow_extractor import extract_pcap_to_df  # scapy chỉ cần khi phải trích xuất
    df = extract_pcap_to_df(pcap).drop(columns=DROP, errors='ignore')
    df.to_csv(cache, index=False)
    return df


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    ap = argparse.ArgumentParser()
    ap.add_argument('pcaps', nargs='+')
    ap.add_argument('--speed', type=float, default=1.0, help='hệ số tăng tốc khi nhả dần (mặc định 1 = thời gian thật)')
    ap.add_argument('--instant', action='store_true', help='ghi toàn bộ luồng một lần')
    ap.add_argument('--gap', type=float, default=5.0, help='giây nghỉ giữa các pcap khi phát nhiều file')
    args = ap.parse_args()

    s = get_settings()
    incoming = s.path(s.incoming_dir)
    incoming.mkdir(parents=True, exist_ok=True)

    frames, offset = [], 0.0
    for p in args.pcaps:
        pcap = resolve(p)
        df = flows_of(pcap).sort_values('Timestamp')
        dur = df['Timestamp'].max() - df['Timestamp'].min()
        df['Timestamp'] = df['Timestamp'] - df['Timestamp'].min() + offset
        offset += dur + args.gap
        frames.append(df)
        print(f'{pcap.name}: {len(df):,} luồng, dài {dur:,.1f} s')
    flows = pd.concat(frames, ignore_index=True).sort_values('Timestamp').reset_index(drop=True)

    out = incoming / f"replay_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    start = time.time()
    rel = flows['Timestamp'].to_numpy()
    flows['Timestamp'] = rel + start
    if args.instant:
        flows.to_csv(out, index=False)
        print(f'Đã ghi {len(flows):,} luồng vào {out}')
        return

    total = rel.max() / args.speed
    print(f'Nhả {len(flows):,} luồng vào {out.name} trong khoảng {total:,.0f} s (tốc độ x{args.speed:g})')
    flows.iloc[0:0].to_csv(out, index=False)
    sent = 0
    while sent < len(flows):
        elapsed = (time.time() - start) * args.speed
        upto = int((rel <= elapsed).sum())
        if upto > sent:
            # Giữ nguyên khoảng cách thời gian gốc giữa các luồng (cửa sổ 10 s / 60 s của luật phải thấy đúng
            # nhịp thật); với --speed > 1 thời gian luồng vì thế chạy trước đồng hồ.
            flows.iloc[sent:upto].to_csv(out, mode='a', header=False, index=False)
            sent = upto
            print(f'\r  {sent:,}/{len(flows):,} luồng', end='', flush=True)
        time.sleep(1.0)
    print('\nXong.')


if __name__ == '__main__':
    main()
