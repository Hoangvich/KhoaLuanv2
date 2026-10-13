"""pcap_flow_extractor.py
Trích xuất đặc trưng luồng từ PCAP sao cho KHỚP với cách CICFlowMeter đã tạo dữ liệu huấn luyện.

Các quy ước dưới đây được đối chiếu trực tiếp với Data/data/processed/unified.parquet (CIC-IDS2017/2018/2019):
- Độ dài gói = payload tầng vận chuyển CÓ TÍNH padding Ethernet
  (CIC-2017: gói ACK thuần 60 byte có độ dài 6, gói SYN 58 byte có độ dài 2).
- Header = độ dài header TCP thật (data offset × 4: 20/24/32/40) hoặc 8 với UDP.
- Chỉ xử lý gói TCP/UDP như CICFlowMeter (ICMP và các mảnh IP không có header UDP bị bỏ qua).
- Hướng forward = hướng gói đầu tiên; luồng kết thúc khi gặp FIN hoặc sau 120 s.
- Active/Idle theo ngưỡng 5 s; Active chỉ được ghi khi luồng có ít nhất một khoảng Idle.
- Cờ TCP: trong dữ liệu huấn luyện các cột cờ là nhị phân và bị ghi lệch
  (SYN Flag Count trùng 100% với Fwd PSH Flags, RST Flag Count trùng 100% với ECE Flag Count).
  Quy tắc suy ra từ dữ liệu, khớp với 10 kiểu luồng phổ biến nhất của CIC-2017:
      PSH Flag Count = gói forward đầu tiên có SYN
      ACK Flag Count = gói forward đầu tiên có ACK
      FIN Flag Count = gói forward đầu tiên có FIN
      SYN Flag Count = gói forward đầu tiên có PSH
      URG Flag Count = gói backward đầu tiên chỉ có cờ ACK
      RST Flag Count = 0
  Cờ đếm đúng (nhị phân) được giữ ở các cột 'true_* Flag' để so sánh.
"""
import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP

FLOW_TIMEOUT = 120.0          # giây
ACTIVITY_TIMEOUT = 5_000_000  # micro giây
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class Flow:
    def __init__(self, src, dst, sport, dport, proto, ts):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.start = self.last = ts
        self.fwd, self.bwd = [], []  # (ts, payload_len, flags, header_len)
        self.start_active = self.end_active = ts
        self.active, self.idle = [], []

    def add(self, is_fwd, ts, plen, flags, hlen):
        gap_us = (ts - self.end_active) * 1e6
        if gap_us > ACTIVITY_TIMEOUT:
            if self.end_active > self.start_active:
                self.active.append((self.end_active - self.start_active) * 1e6)
            self.idle.append(gap_us)
            self.start_active = ts
        self.end_active = self.last = ts
        (self.fwd if is_fwd else self.bwd).append((ts, plen, flags, hlen))


def _stats(v):
    if not v:
        return 0.0, 0.0, 0.0, 0.0
    a = np.asarray(v, dtype=np.float64)
    return float(a.mean()), float(a.std()), float(a.max()), float(a.min())


def _iat(ts):
    return list(np.diff(np.asarray(ts)) * 1e6) if len(ts) > 1 else []


def flow_features(fl: Flow) -> dict:
    allp = sorted(fl.fwd + fl.bwd, key=lambda p: p[0])
    dur_us = (fl.last - fl.start) * 1e6
    dur_s = dur_us / 1e6
    fl_len, bl_len, al_len = [p[1] for p in fl.fwd], [p[1] for p in fl.bwd], [p[1] for p in allp]
    n_f, n_b, n = len(fl.fwd), len(fl.bwd), len(allp)

    # CICFlowMeter chỉ ghi khoảng active khi luồng có ít nhất một khoảng idle
    # (unified.parquet: Active > 0 khi Idle = 0 ở 0% số dòng của cả 3 bộ dữ liệu)
    active = []
    if fl.idle:
        active = list(fl.active)
        if fl.end_active > fl.start_active:
            active.append((fl.end_active - fl.start_active) * 1e6)

    fm, fs, fx, fn = _stats(fl_len)
    bm, bs, bx, bn = _stats(bl_len)
    am, as_, ax, an = _stats(al_len)
    a_iat, f_iat, b_iat = _iat([p[0] for p in allp]), _iat([p[0] for p in fl.fwd]), _iat([p[0] for p in fl.bwd])
    iam, ias, iax, ian = _stats(a_iat)
    ifm, ifs, ifx, ifn = _stats(f_iat)
    ibm, ibs, ibx, ibn = _stats(b_iat)
    acm, acs, acx, acn = _stats(active)
    idm, ids, idx, idn = _stats(fl.idle)

    tcp = fl.proto == 6
    f0 = fl.fwd[0][2] if (tcp and fl.fwd) else 0
    b0 = fl.bwd[0][2] if (tcp and fl.bwd) else -1

    def has(bit):
        return int(any(p[2] & bit for p in allp)) if tcp else 0

    rate = (lambda x: x / dur_s) if dur_s > 0 else (lambda x: np.inf)
    return {
        'Destination Port': fl.dport,
        'Flow Duration': dur_us,
        'Total Fwd Packets': n_f, 'Total Backward Packets': n_b,
        'Total Length of Fwd Packets': sum(fl_len), 'Total Length of Bwd Packets': sum(bl_len),
        'Fwd Packet Length Max': fx, 'Fwd Packet Length Min': fn,
        'Fwd Packet Length Mean': fm, 'Fwd Packet Length Std': fs,
        'Bwd Packet Length Max': bx, 'Bwd Packet Length Min': bn,
        'Bwd Packet Length Mean': bm, 'Bwd Packet Length Std': bs,
        'Flow Bytes/s': rate(sum(al_len)), 'Flow Packets/s': rate(n),
        'Flow IAT Mean': iam, 'Flow IAT Std': ias, 'Flow IAT Max': iax, 'Flow IAT Min': ian,
        'Fwd IAT Total': sum(f_iat), 'Fwd IAT Mean': ifm, 'Fwd IAT Std': ifs, 'Fwd IAT Max': ifx, 'Fwd IAT Min': ifn,
        'Bwd IAT Total': sum(b_iat), 'Bwd IAT Mean': ibm, 'Bwd IAT Std': ibs, 'Bwd IAT Max': ibx, 'Bwd IAT Min': ibn,
        'Fwd Header Length': sum(p[3] for p in fl.fwd), 'Bwd Header Length': sum(p[3] for p in fl.bwd),
        'Fwd Packets/s': rate(n_f), 'Bwd Packets/s': rate(n_b),
        'Min Packet Length': an, 'Max Packet Length': ax,
        'Packet Length Mean': am, 'Packet Length Std': as_, 'Packet Length Variance': as_ ** 2,
        # Cờ theo quy ước của dữ liệu huấn luyện (xem docstring)
        'FIN Flag Count': int(bool(f0 & FIN)), 'SYN Flag Count': int(bool(f0 & PSH)),
        'RST Flag Count': 0, 'PSH Flag Count': int(bool(f0 & SYN)),
        'ACK Flag Count': int(bool(f0 & ACK)), 'URG Flag Count': int(b0 == ACK),
        'Down/Up Ratio': (n_b // n_f) if n_f else 0,
        'Average Packet Size': (sum(al_len) / n) if n else 0.0,
        'act_data_pkt_fwd': sum(1 for p in fl.fwd if p[1] > 0),
        'Active Mean': acm, 'Active Std': acs, 'Active Max': acx, 'Active Min': acn,
        'Idle Mean': idm, 'Idle Std': ids, 'Idle Max': idx, 'Idle Min': idn,
        # Cờ đếm đúng (nhị phân), chỉ dùng cho phân tích độ nhạy
        'true_FIN Flag': has(FIN), 'true_SYN Flag': has(SYN), 'true_RST Flag': has(RST),
        'true_PSH Flag': has(PSH), 'true_ACK Flag': has(ACK), 'true_URG Flag': has(URG),
        # Định danh, không phải đặc trưng mô hình (dùng để gán nhãn và cho tầng luật ids_rules)
        'Timestamp': fl.start, 'Src IP': fl.src, 'Dst IP': fl.dst, 'Src Port': fl.sport, 'Protocol': fl.proto,
    }


def _parse(pkt):
    """Trả về (src, dst, sport, dport, proto, flags, header_len, payload_len) hoặc None nếu không phải TCP/UDP."""
    ip = pkt[IP]
    if TCP in pkt:
        l4 = pkt[TCP]
        hlen, flags = (l4.dataofs or 5) * 4, int(l4.flags)
    elif UDP in pkt:
        l4 = pkt[UDP]
        hlen, flags = 8, 0
    else:
        return None
    # len(l4.payload) gồm cả padding Ethernet (scapy để Padding dưới payload), đúng như CICFlowMeter
    return ip.src, ip.dst, l4.sport, l4.dport, ip.proto, flags, hlen, len(l4.payload)


def extract_pcap_to_df(pcap_path, max_packets=None) -> pd.DataFrame:
    """Đọc toàn bộ pcap (hoặc max_packets gói đầu) và trả về DataFrame luồng."""
    active, done = {}, []
    count = skipped = 0
    for pkt in PcapReader(str(pcap_path)):
        count += 1
        if max_packets and count > max_packets:
            break
        r = _parse(pkt) if IP in pkt else None
        if r is None:
            skipped += 1
            continue
        src, dst, sport, dport, proto, flags, hlen, plen = r
        ts = float(pkt.time)
        fk, bk = (src, dst, sport, dport, proto), (dst, src, dport, sport, proto)
        key, is_fwd = (fk, True) if fk in active else ((bk, False) if bk in active else (fk, True))
        fl = active.get(key)
        if fl is not None and ts - fl.start > FLOW_TIMEOUT:
            done.append(active.pop(key))
            fl, key, is_fwd = None, fk, True
        if fl is None:
            fl = active[key] = Flow(src, dst, sport, dport, proto, ts)
        fl.add(is_fwd, ts, plen, flags, hlen)
        if flags & FIN:  # CICFlowMeter đóng luồng khi gặp FIN
            done.append(active.pop(key))
    done.extend(active.values())
    df = pd.DataFrame([flow_features(f) for f in done])
    name = getattr(pcap_path, 'name', pcap_path)
    print(f"  {name}: {count:,} gói ({skipped:,} không phải TCP/UDP, bỏ qua) -> {len(df):,} luồng")
    return df
