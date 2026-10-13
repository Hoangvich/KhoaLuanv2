"""ids_features.py — tiền xử lý đặc trưng và luật quyết định DÙNG CHUNG.

File này được dùng ở CẢ BA nơi, không được viết lại ở đâu khác:
  1. notebook huấn luyện (Kaggle),
  2. đánh giá trên dữ liệu lab,
  3. backend FastAPI.
Chỉ phụ thuộc numpy + pandas để backend không phải cài thêm gì.
"""
import numpy as np
import pandas as pd

# Tên cột kiểu CSE-CIC-IDS2018 / CICFlowMeter-V4 -> tên chuẩn (theo CIC-IDS2017).
# CICFlowMeter bản Java mới xuất ra tên kiểu 2018, nên backend cần bảng này.
RENAME_2018 = {
    'ACK Flag Cnt': 'ACK Flag Count', 'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk', 'Bwd Header Len': 'Bwd Header Length',
    'Bwd IAT Tot': 'Bwd IAT Total', 'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean', 'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std', 'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Pkts/s': 'Bwd Packets/s', 'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Dst Port': 'Destination Port', 'ECE Flag Cnt': 'ECE Flag Count',
    'FIN Flag Cnt': 'FIN Flag Count', 'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s', 'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate', 'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Header Len': 'Fwd Header Length', 'Fwd IAT Tot': 'Fwd IAT Total',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max', 'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min', 'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk', 'Fwd Pkts/s': 'Fwd Packets/s',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size', 'Fwd Seg Size Min': 'min_seg_size_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward', 'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'PSH Flag Cnt': 'PSH Flag Count', 'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean', 'Pkt Len Min': 'Min Packet Length',
    'Pkt Len Std': 'Packet Length Std', 'Pkt Len Var': 'Packet Length Variance',
    'Pkt Size Avg': 'Average Packet Size', 'RST Flag Cnt': 'RST Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count', 'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets', 'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets', 'Tot Bwd Pkts': 'Total Backward Packets',
    'Tot Fwd Pkts': 'Total Fwd Packets', 'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets', 'URG Flag Cnt': 'URG Flag Count',
}


def port_class(port):
    """0: cổng hệ thống (<1024), 1: cổng đăng ký (1024-49151), 2: cổng tạm (>=49152)."""
    p = pd.to_numeric(pd.Series(port), errors='coerce').to_numpy(np.float64)
    out = np.where(p < 1024, 0.0, np.where(p < 49152, 1.0, 2.0))
    out[np.isnan(p)] = np.nan
    return out


def canonicalize(df_raw: pd.DataFrame) -> pd.DataFrame:
    """Chuẩn hoá tên cột (bỏ khoảng trắng, đổi tên kiểu 2018) và suy ra dst_port_class."""
    df = df_raw.rename(columns=lambda c: str(c).strip()).rename(columns=RENAME_2018)
    if 'dst_port_class' not in df.columns and 'Destination Port' in df.columns:
        df['dst_port_class'] = port_class(df['Destination Port'])
    return df


def prepare_features(df_raw: pd.DataFrame, features: list):
    """Trả về (X float32 đúng thứ tự `features`, valid: mask dòng dùng được).

    Dòng không hợp lệ (NaN/inf, thời lượng <= 0) KHÔNG có trong dữ liệu huấn luyện,
    nên không được đưa vào mô hình: backend đánh dấu riêng các dòng này.
    """
    df = canonicalize(df_raw)
    missing = [c for c in features if c not in df.columns]
    if missing:
        raise KeyError(f'Thiếu {len(missing)} cột đặc trưng: {missing}')
    X = df[features].apply(pd.to_numeric, errors='coerce').to_numpy(np.float32)
    valid = np.isfinite(X).all(axis=1)
    if 'Flow Duration' in df.columns:
        valid &= pd.to_numeric(df['Flow Duration'], errors='coerce').to_numpy() > 0
    return X, valid


def decide(proba: np.ndarray, benign_index: int, threshold=None) -> np.ndarray:
    """Luật quyết định duy nhất cho mọi nơi.

    threshold=None : lớp có xác suất cao nhất (argmax).
    threshold=t    : là tấn công nếu 1 - P(BENIGN) >= t; khi đó chọn lớp tấn công
                     có xác suất cao nhất. Ngưỡng t được chọn trên tập validation.
    """
    if threshold is None:
        return proba.argmax(axis=1)
    attack = proba.copy()
    attack[:, benign_index] = -1.0
    return np.where(1.0 - proba[:, benign_index] >= threshold,
                     attack.argmax(axis=1), benign_index)


def predict_frame(bundle: dict, df_raw: pd.DataFrame) -> pd.DataFrame:
    """Hàm backend gọi: nhận DataFrame thô từ CICFlowMeter, trả nhãn + điểm tấn công."""
    X, valid = prepare_features(df_raw, bundle['features'])
    out = pd.DataFrame({'valid': valid, 'label': None, 'attack_score': np.nan})
    if valid.any():
        model = bundle['model']
        p = np.zeros((int(valid.sum()), len(bundle['classes'])), np.float32)
        p[:, model.classes_] = model.predict_proba(X[valid])
        pred = decide(p, bundle['benign_index'], bundle['threshold'])
        out.loc[valid, 'label'] = np.asarray(bundle['classes'], dtype=object)[pred]
        out.loc[valid, 'attack_score'] = 1.0 - p[:, bundle['benign_index']]
    return out
