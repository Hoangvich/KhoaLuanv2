"""test_lab_3_models.py
Kiểm thử Kịch bản C trên môi trường Lab mô phỏng (3 VLAN, pfSense, hping3 / nmap / hydra):
- Dữ liệu: 4 file PCAP lab gốc (benign.pcap, ddos.pcap, portscan.pcap, bruteforce.pcap).
- Mô hình: 3 mô hình cây (LightGBM, Random Forest, XGBoost) trên bộ đặc trưng triển khai F_NOOS (bỏ MLP).
- Hiệu chỉnh ngưỡng: Ràng buộc FPR(BENIGN) <= 1.0%.
- Đối chiếu quy tắc chốt mô hình triển khai của đề tài.
"""
import sys
import json
import time
import warnings
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_recall_fscore_support, f1_score, confusion_matrix, roc_auc_score
)

warnings.filterwarnings('ignore')

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "Model Train" / "LGBM"))

from ids_features import prepare_features, decide
from pcap_flow_extractor import extract_pcap_to_df

TEST_DIR = Path(__file__).resolve().parent
DATA_DIR = TEST_DIR / "data"
RESULTS_DIR = TEST_DIR / "results"
DATA_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

PCAP_DIR = PROJECT_ROOT / "File Pcap" / "file pcap"

# 4 kịch bản Lab thu thập từ pfSense:
LAB_PCAPS = [
    ("benign.pcap", "BENIGN", 25000),         # Lưu lượng duyệt web, SSH người dùng thường
    ("ddos.pcap", "DoS/DDoS", 25000),         # hping3 SYN / UDP flood
    ("portscan.pcap", "PortScan", 25000),     # nmap scan (SYN / TCP connect)
    ("bruteforce.pcap", "BruteForce", 25000)  # hydra dò mật khẩu SSH
]

# 3 mô hình cây (loại trừ MLP theo yêu cầu đề tài):
MODELS_TO_TEST = [
    ("LightGBM", PROJECT_ROOT / "Model Train" / "LGBM" / "models" / "lgbm_F_NOOS.joblib"),
    ("RandomForest", PROJECT_ROOT / "Model Train" / "RF" / "models" / "rf_F_NOOS.joblib"),
    ("XGBoost", PROJECT_ROOT / "Model Train" / "XGBOOST" / "models" / "xgb_F_NOOS.joblib"),
]

def load_or_extract_lab_flows():
    cache_file = DATA_DIR / "lab_pcap_clean_flows.csv"
    if cache_file.exists():
        print(f"[*] Đã nạp dữ liệu luồng Lab từ cache: {cache_file}")
        df = pd.read_csv(cache_file)
        print(f"[*] Phân bố các nhãn Lab:\n{df['Label'].value_counts()}\n")
        return df

    print("[*] Đang trích xuất đặc trưng luồng từ 4 file PCAP Lab...")
    dfs = []
    for pcap_name, label, max_pkts in LAB_PCAPS:
        p_path = PCAP_DIR / pcap_name
        if not p_path.exists():
            print(f"[!] CẢNH BÁO: Không tìm thấy {p_path}")
            continue
        print(f"  -> Trích xuất {pcap_name} ({label})...")
        sub_df = extract_pcap_to_df(str(p_path), label, max_packets=max_pkts)
        dfs.append(sub_df)

    full_df = pd.concat(dfs, ignore_index=True)
    full_df.to_csv(cache_file, index=False)
    print(f"[*] Đã lưu {len(full_df):,} luồng mạng vào: {cache_file}")
    print(full_df['Label'].value_counts())
    print()
    return full_df

def calibrate_threshold(y_true, proba, b_idx, target_fpr=0.01):
    """Quét ngưỡng tối ưu thỏa mãn FPR(BENIGN) <= target_fpr."""
    is_b = (y_true == b_idx)
    cand_thresh = np.unique(np.concatenate([
        np.linspace(0.0001, 0.05, 50),
        np.linspace(0.05, 0.95, 91),
        [0.3, 0.34, 0.36, 0.48, 0.5, 0.64]
    ]))
    cand_thresh.sort()
    
    best_t = 0.5
    best_dr = -1.0
    best_f1 = -1.0
    best_fpr = 1.0
    present = list(np.unique(y_true))
    
    for t in cand_thresh:
        pred = decide(proba, b_idx, t)
        fpr = float((pred[is_b] != b_idx).mean())
        if fpr <= target_fpr:
            dr = float((pred[~is_b] != b_idx).mean())
            f1 = f1_score(y_true, pred, labels=present, average='macro', zero_division=0)
            if (dr > best_dr) or (dr == best_dr and f1 > best_f1):
                best_dr = dr
                best_t = t
                best_f1 = f1
                best_fpr = fpr
                
    if best_dr < 0:
        best_t = 0.5
        pred = decide(proba, b_idx, best_t)
        best_fpr = float((pred[is_b] != b_idx).mean())
        best_dr = float((pred[~is_b] != b_idx).mean())
        best_f1 = f1_score(y_true, pred, labels=present, average='macro', zero_division=0)
        
    return float(best_t), float(best_f1), float(best_dr), float(best_fpr)

def evaluate_lab_model(model_name, bundle_path, df_lab):
    bundle = joblib.load(bundle_path)
    features = bundle['features']
    classes = bundle['classes']
    b_idx = bundle['benign_index']
    model = bundle['model']
    
    X, valid = prepare_features(df_lab, features)
    v_df = df_lab[valid].copy()
    
    label_map = {'BENIGN': 0, 'DoS/DDoS': 1, 'PortScan': 2, 'BruteForce': 3}
    y_true = v_df['Label'].map(label_map).to_numpy()
    
    proba = np.zeros((len(X), len(classes)), dtype=np.float32)
    proba[:, model.classes_] = model.predict_proba(X)
    
    is_attack = (y_true != b_idx)
    try:
        auc_score = float(roc_auc_score(is_attack, 1.0 - proba[:, b_idx]))
    except Exception:
        auc_score = np.nan
        
    # 1. Theo ngưỡng triển khai gốc
    orig_t = bundle.get('threshold', 0.5)
    pred_orig = decide(proba, b_idx, orig_t)
    present = list(np.unique(y_true))
    f1_orig = f1_score(y_true, pred_orig, labels=present, average='macro', zero_division=0)
    dr_orig = float((pred_orig[is_attack] != b_idx).mean())
    fpr_orig = float((pred_orig[~is_attack] != b_idx).mean())
    
    # 2. Sau khi hiệu chỉnh ngưỡng với ràng buộc FPR <= 1%
    calib_t, calib_f1, calib_dr, calib_fpr = calibrate_threshold(y_true, proba, b_idx, target_fpr=0.01)
    pred_calib = decide(proba, b_idx, calib_t)
    
    p, r, f, sup = precision_recall_fscore_support(y_true, pred_calib, labels=range(len(classes)), zero_division=0)
    
    cm = pd.DataFrame(
        confusion_matrix(y_true, pred_calib, labels=range(len(classes))),
        index=[f'Thực_tế_{c}' for c in classes],
        columns=[f'Dự_đoán_{c}' for c in classes]
    )
    
    res = {
        'model_name': model_name,
        'auc_attack_vs_benign': round(auc_score, 4),
        'orig_threshold': round(float(orig_t), 4),
        'orig_macro_f1': round(f1_orig, 4),
        'orig_detection_rate': round(dr_orig * 100, 2),
        'orig_fpr': round(fpr_orig * 100, 2),
        'calib_threshold': round(calib_t, 4),
        'calib_macro_f1': round(calib_f1, 4),
        'calib_detection_rate': round(calib_dr * 100, 2),
        'calib_fpr': round(calib_fpr * 100, 2),
        'precision_BENIGN': round(p[0] * 100, 2),
        'recall_BENIGN': round(r[0] * 100, 2),
        'f1_BENIGN': round(f[0] * 100, 2),
        'precision_DDoS': round(p[1] * 100, 2),
        'recall_DDoS': round(r[1] * 100, 2),
        'f1_DDoS': round(f[1] * 100, 2),
        'precision_PortScan': round(p[2] * 100, 2),
        'recall_PortScan': round(r[2] * 100, 2),
        'f1_PortScan': round(f[2] * 100, 2),
        'precision_BruteForce': round(p[3] * 100, 2),
        'recall_BruteForce': round(r[3] * 100, 2),
        'f1_BruteForce': round(f[3] * 100, 2),
        'cm': cm
    }
    return res

def main():
    print("=" * 80)
    print("KỊCH BẢN C: KIỂM CHỨNG TRÊN DỮ LIỆU LAB MÔ PHỎNG (3 VLAN, pfSense)")
    print("So sánh 3 mô hình cây: LightGBM vs Random Forest vs XGBoost (F_NOOS)")
    print("=" * 80 + "\n")
    
    df_lab = load_or_extract_lab_flows()
    
    results = []
    for name, path in MODELS_TO_TEST:
        print(f"[*] Đang đánh giá mô hình: {name} ...")
        res = evaluate_lab_model(name, path, df_lab)
        results.append(res)
        res['cm'].to_csv(RESULTS_DIR / f"cm_lab_{name}.csv", encoding='utf-8-sig')
        
    summary_df = pd.DataFrame([{
        'Mô hình': r['model_name'],
        'AUC (Lab)': r['auc_attack_vs_benign'],
        'Ngưỡng gốc': r['orig_threshold'],
        'Detection gốc (%)': f"{r['orig_detection_rate']}%",
        'Ngưỡng hiệu chỉnh τ*': r['calib_threshold'],
        'FPR (Benign) (%)': f"{r['calib_fpr']}%",
        'Tỉ lệ phát hiện sau hiệu chỉnh (%)': f"{r['calib_detection_rate']}%",
        'Macro-F1 (Lab)': r['calib_macro_f1'],
        'Recall BENIGN (%)': f"{r['recall_BENIGN']}%",
        'Recall DDoS (%)': f"{r['recall_DDoS']}%",
        'Recall PortScan (%)': f"{r['recall_PortScan']}%",
        'Recall BruteForce (%)': f"{r['recall_BruteForce']}%"
    } for r in results])
    
    out_csv = RESULTS_DIR / "lab_3_models_summary.csv"
    summary_df.to_csv(out_csv, index=False, encoding='utf-8-sig')
    
    print("\n" + summary_df.to_string(index=False) + "\n")
    
    # ĐỐI CHIẾU QUY TẮC MỤC 3.8.5
    lgbm = next(r for r in results if r['model_name'] == 'LightGBM')
    rf = next(r for r in results if r['model_name'] == 'RandomForest')
    xgb = next(r for r in results if r['model_name'] == 'XGBoost')
    
    diff_auc = rf['auc_attack_vs_benign'] - lgbm['auc_attack_vs_benign']
    diff_dr = rf['calib_detection_rate'] - lgbm['calib_detection_rate']
    
    print("=" * 80)
    print("ĐỐI CHIẾU QUY TẮC CHỐT MÔ HÌNH TRIỂN KHAI (MỤC 3.8.5 BÁO CÁO):")
    print(f"- AUC (Lab):  RF = {rf['auc_attack_vs_benign']:.4f} | LightGBM = {lgbm['auc_attack_vs_benign']:.4f} | ΔAUC = {diff_auc:+.4f}")
    print(f"- Tỉ lệ phát hiện (DR): RF = {rf['calib_detection_rate']:.2f}% | LightGBM = {lgbm['calib_detection_rate']:.2f}% | ΔDR = {diff_dr:+.2f}%")
    print("-" * 80)
    
    rf_wins = (diff_auc > 0.02) or (diff_dr > 2.0)
    final_model = "Random Forest" if rf_wins else "LightGBM"
    
    print(f"==> KẾT LUẬN CUỐI CÙNG: CHỌN {final_model.upper()}")
    print("=" * 80 + "\n")
    
    # Báo cáo Markdown
    report_file = RESULTS_DIR / "Bao_Cao_Kich_Ban_C_3_Mo_Hinh_Lab.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# BÁO CÁO THỰC NGHIỆM KỊCH BẢN C TRÊN LAB MÔ PHỎNG (3 VLAN, pfSense)\n\n")
        f.write("> **Môi trường:** 3 VLAN, pfSense, tấn công bằng hping3 / nmap / hydra (Kịch bản C Báo cáo Khóa luận)\n")
        f.write(f"> **Thời gian thực hiện:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"> **Tổng số luồng Lab đánh giá:** {len(df_lab):,} luồng\n\n")
        
        f.write("## 1. Kết quả đánh giá so sánh 3 mô hình cây (Bộ đặc trưng triển khai F_NOOS)\n\n")
        f.write(summary_df.to_markdown(index=False))
        f.write("\n\n")
        
        f.write("## 2. Ma trận nhầm lẫn chi tiết (Sau hiệu chỉnh ngưỡng)\n\n")
        for r in results:
            f.write(f"### {r['model_name']} (Ngưỡng $\\tau^* = {r['calib_threshold']}$)\n\n")
            f.write(r['cm'].to_markdown())
            f.write("\n\n")
            
        f.write("## 3. Kết luận và Chốt mô hình triển khai theo Mục 3.8.5\n\n")
        f.write(f"- Theo quy tắc Mục 3.8.5, Random Forest {'vượt trội' if rf_wins else 'không vượt trội hơn'} LightGBM trên dữ liệu Lab.\n")
        f.write(f"- **Chốt mô hình triển khai chính thức:** **{final_model.upper()}**.\n")
        f.write(f"- **Lợi thế khi chọn {final_model}:** Dung lượng gọn nhẹ ({'4.3 MB' if rf_wins else '0.76 MB'}), tốc độ suy luận nhanh ({'46.8 ms' if rf_wins else '1.56 ms'}/lô), phù hợp tích hợp vào FastAPI và Sensor theo dõi mạng gần thời gian thực.\n")

    print(f"[*] Đã xuất file báo cáo đầy đủ: {report_file}")

if __name__ == "__main__":
    main()
