"""ids_rules.py — tầng luật tổng hợp theo nguồn, chạy song song với mô hình phân loại luồng.

Một số tấn công chỉ lộ ra khi gom nhiều luồng của cùng một IP nguồn trong một cửa sổ thời gian:
  - BruteForce: mỗi lần thử mật khẩu là một phiên đăng nhập bình thường; điểm bất thường là SỐ phiên
    mới liên tiếp từ một nguồn tới cùng một cổng dịch vụ đăng nhập.
  - PortScan  : một nguồn chạm tới rất nhiều cổng khác nhau của cùng một đích (lớp dự phòng cho mô hình).

Chỉ phụ thuộc numpy + pandas để backend dùng lại được. Đầu vào là DataFrame luồng có các cột
'Timestamp' (giây, thời điểm bắt đầu luồng), 'Src IP', 'Dst IP', 'Destination Port', 'Protocol' và
'Total Fwd Packets', 'Total Backward Packets'.
"""
from collections import Counter

import numpy as np
import pandas as pd

PORTSCAN_WINDOW = 10.0     # giây
BRUTEFORCE_WINDOW = 60.0   # giây
# Ngưỡng sàn: không hạ thấp hơn mức này dù lưu lượng benign dùng để chọn ngưỡng rất "sạch".
PORTSCAN_FLOOR = 20        # số cổng đích khác nhau trong cửa sổ
BRUTEFORCE_FLOOR = 10      # số phiên mới trong cửa sổ
AUTH_PORTS = {21, 22, 23, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}


def _distinct_in_window(t, keys, window):
    """Với mỗi i (t đã sắp xếp tăng dần): số giá trị khác nhau của keys trong (t[i]-window, t[i]]."""
    out = np.empty(len(t), dtype=np.int64)
    cnt = Counter()
    left = 0
    for i in range(len(t)):
        cnt[keys[i]] += 1
        while t[left] <= t[i] - window:
            cnt[keys[left]] -= 1
            if cnt[keys[left]] == 0:
                del cnt[keys[left]]
            left += 1
        out[i] = len(cnt)
    return out


def source_stats(df: pd.DataFrame, group_cols=()) -> pd.DataFrame:
    """Tính 2 thống kê theo nguồn cho từng luồng (cùng index với df).

    ps_ports : số cổng đích khác nhau mà Src IP chạm tới ở Dst IP trong PORTSCAN_WINDOW giây.
    bf_conns : số phiên TCP (có gói ở cả hai chiều) từ Src IP tới cùng Dst IP:cổng đăng nhập trong
               BRUTEFORCE_WINDOW giây; bằng 0 với luồng không thuộc diện này.
    group_cols: cột tách thêm (ví dụ tên file pcap) để không trộn lưu lượng từ các bản ghi khác nhau.
    """
    gc = list(group_cols)
    out = pd.DataFrame(0, index=df.index, columns=['ps_ports', 'bf_conns'], dtype=np.int64)

    for _, g in df.groupby(gc + ['Src IP', 'Dst IP'], sort=False):
        g = g.sort_values('Timestamp', kind='stable')
        out.loc[g.index, 'ps_ports'] = _distinct_in_window(
            g['Timestamp'].to_numpy(), g['Destination Port'].to_numpy(), PORTSCAN_WINDOW)

    sess = (df['Protocol'] == 6) & df['Destination Port'].isin(AUTH_PORTS) \
        & (df['Total Fwd Packets'] > 0) & (df['Total Backward Packets'] > 0)
    for _, g in df[sess].groupby(gc + ['Src IP', 'Dst IP', 'Destination Port'], sort=False):
        g = g.sort_values('Timestamp', kind='stable')
        t = g['Timestamp'].to_numpy()
        out.loc[g.index, 'bf_conns'] = np.arange(1, len(t) + 1) - np.searchsorted(t, t - BRUTEFORCE_WINDOW, side='right')
    return out


def fit_thresholds(stats_benign: pd.DataFrame):
    """Ngưỡng = giá trị lớn nhất trên lưu lượng benign + 1 (không báo động giả trên tập chọn ngưỡng),
    nhưng không thấp hơn mức sàn."""
    if len(stats_benign) == 0:
        return PORTSCAN_FLOOR, BRUTEFORCE_FLOOR
    return (max(PORTSCAN_FLOOR, int(stats_benign['ps_ports'].max()) + 1),
            max(BRUTEFORCE_FLOOR, int(stats_benign['bf_conns'].max()) + 1))


def apply_rules(stats: pd.DataFrame, ps_min: int, bf_min: int, classes) -> np.ndarray:
    """Chỉ số lớp do luật gán (theo danh sách classes), -1 nếu luật không kích hoạt.
    BruteForce được ưu tiên khi cả hai luật cùng kích hoạt."""
    idx = {c: i for i, c in enumerate(classes)}
    out = np.full(len(stats), -1, dtype=np.int64)
    out[stats['ps_ports'].to_numpy() >= ps_min] = idx['PortScan']
    out[stats['bf_conns'].to_numpy() >= bf_min] = idx['BruteForce']
    return out


def combine(model_pred: np.ndarray, rule_pred: np.ndarray, benign_index: int = 0) -> np.ndarray:
    """Hệ lai: luật chỉ BỔ SUNG cảnh báo cho luồng mà mô hình cho là BENIGN;
    luồng mô hình đã báo tấn công thì giữ nhãn của mô hình."""
    return np.where((model_pred == benign_index) & (rule_pred >= 0), rule_pred, model_pred)
