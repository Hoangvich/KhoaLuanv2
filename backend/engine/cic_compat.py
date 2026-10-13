"""cic_compat.py — chuẩn hoá đầu ra CICFlowMeter trước khi đưa vào mô hình và tầng luật.

Ba việc:
1. Tên cột: kiểu CIC-IDS2017 ('Source IP'), kiểu CICFlowMeter-V4 ('Src IP', 'Dst Port') -> một tên chuẩn.
2. Timestamp: số giây epoch (UTC) hoặc chuỗi ngày giờ địa phương của CICFlowMeter -> số giây epoch UTC.
3. Cờ TCP: dữ liệu huấn luyện (CIC-2017) ghi cờ dạng nhị phân và lệch cột (xem
   Test_Kich_Ban_C/results/Bao_Cao_Kich_Ban_C.md, mục 2). Nếu sensor đếm cờ theo chuẩn thì phải chuyển về
   quy ước huấn luyện, nếu không mô hình bỏ sót PortScan.
"""
import numpy as np
import pandas as pd

from engine.ids_features import canonicalize

ID_ALIASES = {
    'Source IP': 'Src IP', 'Source Port': 'Src Port', 'Destination IP': 'Dst IP',
    'Src Port': 'Src Port', 'Dst IP': 'Dst IP',
}
FLAG_COLS = ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
             'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count']
ID_COLS = ['Src IP', 'Src Port', 'Dst IP', 'Destination Port', 'Protocol', 'Timestamp']


def normalize_columns(df_raw: pd.DataFrame) -> pd.DataFrame:
    df = canonicalize(df_raw).rename(columns=ID_ALIASES)
    missing = [c for c in ID_COLS if c not in df.columns]
    if missing:
        raise KeyError(f'Thiếu cột định danh luồng: {missing}')
    return df


def parse_timestamp(col: pd.Series, tz: str) -> np.ndarray:
    """Trả về số giây epoch (UTC) dạng float."""
    num = pd.to_numeric(col, errors='coerce')
    if num.notna().all():
        return num.to_numpy(np.float64)
    dt = pd.to_datetime(col, dayfirst=True, errors='coerce', format='mixed')
    if dt.dt.tz is None:
        dt = dt.dt.tz_localize(tz, ambiguous='NaT', nonexistent='NaT')
    sec = dt.dt.tz_convert('UTC').astype('int64') / 1e9
    return np.where(dt.isna(), np.nan, sec)


def detect_flag_mode(df: pd.DataFrame) -> str:
    """'cic2017' nếu cờ đã theo quy ước huấn luyện, 'standard' nếu là số đếm theo chuẩn.

    Dấu hiệu: quy ước CIC-2017 chỉ có 0/1 và RST Flag Count luôn bằng 0.
    """
    flags = df[FLAG_COLS].apply(pd.to_numeric, errors='coerce').fillna(0)
    if (flags.to_numpy() > 1).any() or (flags['RST Flag Count'] > 0).any():
        return 'standard'
    return 'cic2017'


def standard_to_cic2017(df: pd.DataFrame) -> pd.DataFrame:
    """Chuyển số đếm cờ theo chuẩn sang quy ước CIC-2017 (xấp xỉ).

    Quy ước gốc dựa trên gói đầu tiên của mỗi chiều; từ số đếm chỉ suy ra được gần đúng:
    luồng có SYN coi như bắt đầu bằng SYN (PSH=1, các cột khác 0), luồng không có SYN là luồng bắt
    giữa chừng (ACK/FIN theo số đếm, cột SYN mang ý nghĩa 'gói đi có PSH').
    """
    d = df.copy()
    get = lambda c: pd.to_numeric(d.get(c, 0), errors='coerce').fillna(0) > 0  # noqa: E731
    syn, ack, fin = get('SYN Flag Count'), get('ACK Flag Count'), get('FIN Flag Count')
    fwd_psh = get('Fwd PSH Flags') if 'Fwd PSH Flags' in d.columns else get('PSH Flag Count')
    d['PSH Flag Count'] = syn.astype(int)
    d['ACK Flag Count'] = (~syn & ack).astype(int)
    d['FIN Flag Count'] = (~syn & fin).astype(int)
    d['SYN Flag Count'] = (~syn & fwd_psh).astype(int)
    d['URG Flag Count'] = 0
    d['RST Flag Count'] = 0
    return d


def prepare_input(df_raw: pd.DataFrame, flag_mode: str = 'auto', tz: str = 'Asia/Ho_Chi_Minh'):
    """Chuẩn hoá một lô luồng thô. Trả về (df, flag_mode_đã_dùng)."""
    df = normalize_columns(df_raw).reset_index(drop=True)
    df['Timestamp'] = parse_timestamp(df['Timestamp'], tz)
    mode = detect_flag_mode(df) if flag_mode == 'auto' else flag_mode
    if mode == 'standard':
        df = standard_to_cic2017(df)
    for c in ['Src Port', 'Destination Port', 'Protocol']:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0).astype(int)
    for c in ['Src IP', 'Dst IP']:
        df[c] = df[c].astype(str)
    return df, mode
