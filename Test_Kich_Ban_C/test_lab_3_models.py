"""test_lab_3_models.py — Kịch bản C: kiểm thử 3 mô hình cây (F_NOOS) trên 4 pcap ngoài tập huấn luyện.

Quy trình:
1. Trích xuất luồng bằng pcap_flow_extractor (quy ước khớp CICFlowMeter, đối chiếu với unified.parquet).
2. Gán nhãn theo IP máy tấn công / nạn nhân, không gán theo cả file.
3. Lặp N_SPLITS lần: chia đôi dữ liệu theo tầng nhãn. Nửa HIỆU CHỈNH chọn τ* nhỏ nhất thỏa
   FPR(BENIGN) <= 1%; nửa ĐÁNH GIÁ đo AUC, tỉ lệ phát hiện (DR), FPR, phát hiện theo từng lớp.
4. Quy tắc mục 3.8.5: chuyển sang RF nếu ΔAUC(RF - LGBM) > 0,02 hoặc ΔDR > 2 điểm %; ngược lại giữ LightGBM.
5. Hệ lai: mô hình + tầng luật theo nguồn (ids_rules). Ngưỡng luật chọn trên BENIGN của nửa hiệu chỉnh;
   τ* chọn lại sao cho FPR tổng của hệ lai trên nửa hiệu chỉnh <= 1%.
6. Độ nhạy: chạy lại phần mô hình với cờ TCP đếm đúng thay vì quy ước của dữ liệu huấn luyện.
"""
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix, roc_auc_score

TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent
sys.path.insert(0, str(TEST_DIR))
sys.path.append(str(PROJECT_ROOT / "Model Train" / "LGBM"))
sys.stdout.reconfigure(encoding='utf-8')
warnings.filterwarnings('ignore', category=UserWarning)

from ids_features import prepare_features, decide  # noqa: E402
from pcap_flow_extractor import extract_pcap_to_df  # noqa: E402
import ids_rules  # noqa: E402

DATA_DIR = TEST_DIR / "data"
RESULTS_DIR = TEST_DIR / "results"
DATA_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR = PROJECT_ROOT / "File Pcap" / "file pcap"
CACHE = DATA_DIR / "lab_flows_cic.csv"

ATTACKER, VICTIM = "192.168.1.149", "192.168.1.4"
CLASSES = ['BENIGN', 'DoS/DDoS', 'PortScan', 'BruteForce']
ATTACKS = CLASSES[1:]
LMAP = {c: i for i, c in enumerate(CLASSES)}
FLAG_COLS = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG']
TARGET_FPR = 0.01
N_SPLITS = 200
SEED = 42

MODELS = [
    ("LightGBM", PROJECT_ROOT / "Model Train" / "LGBM" / "models" / "lgbm_F_NOOS.joblib"),
    ("RandomForest", PROJECT_ROOT / "Model Train" / "RF" / "models" / "rf_F_NOOS.joblib"),
    ("XGBoost", PROJECT_ROOT / "Model Train" / "XGBOOST" / "models" / "xgb_F_NOOS.joblib"),
]


# ----------------------------------------------------------------------------- dữ liệu
def is_attack_pair(df, dport=None):
    m = (df['Src IP'] == ATTACKER) & (df['Dst IP'] == VICTIM)
    if dport is not None:
        m &= df['Destination Port'] == dport
    return m


def load_flows():
    if CACHE.exists():
        print(f"[*] Nạp luồng từ cache: {CACHE}")
        return pd.read_csv(CACHE)
    print("[*] Trích xuất luồng từ 4 pcap (toàn bộ file)...")

    def read(name, label, mask=None):
        d = extract_pcap_to_df(PCAP_DIR / name)
        if mask is not None:
            d = d[mask(d)].copy()
        d['Pcap'], d['Label'] = name, label
        return d

    df = pd.concat([
        read("benign.pcap", 'BENIGN'),
        # ddos.pcap là mẫu công khai (trùng từng byte amp.UDP.memcached.ntp.cldap.pcap): toàn bộ là tấn công
        read("ddos.pcap", 'DoS/DDoS'),
        read("portscan.pcap", 'PortScan', lambda d: is_attack_pair(d)),
        read("bruteforce.pcap", 'BruteForce', lambda d: is_attack_pair(d, dport=22)),
    ], ignore_index=True)
    df.to_csv(CACHE, index=False)
    print(f"[*] Đã lưu {len(df):,} luồng vào {CACHE}")
    return df


def with_true_flags(df):
    d = df.copy()
    for f in FLAG_COLS:
        d[f'{f} Flag Count'] = d[f'true_{f} Flag']
    return d


# ----------------------------------------------------------------------------- đánh giá
def calibrate_count(score_benign, m):
    """Ngưỡng nhỏ nhất sao cho không quá m luồng BENIGN có score >= τ."""
    s = np.sort(score_benign)[::-1]
    if m >= len(s):
        return 0.0
    return float(np.nextafter(np.float32(s[m]), np.float32(np.inf)))


def calibrate(score_benign):
    return calibrate_count(score_benign, int(np.floor(TARGET_FPR * len(score_benign))))


def metrics(y, proba, t, rule_pred=None):
    atk = y != 0
    pred = decide(proba, 0, t)
    if rule_pred is not None:
        pred = ids_rules.combine(pred, rule_pred)
    det = {c: float((pred[y == i] != 0).mean()) for c, i in LMAP.items() if i and (y == i).any()}
    return {'auc': float(roc_auc_score(atk, 1 - proba[:, 0])),
            'dr': float((pred[atk] != 0).mean()), 'fpr': float((pred[~atk] != 0).mean()),
            'dr_macro': float(np.mean(list(det.values()))), 'detect': det, 'pred': pred}


def stratified_halves(y, rng):
    cal = np.zeros(len(y), bool)
    for c in np.unique(y):
        idx = rng.permutation(np.flatnonzero(y == c))
        cal[idx[: len(idx) // 2]] = True
    return cal


def ci(a):
    a = np.asarray(a, dtype=float)
    return float(np.nanmedian(a)), float(np.nanpercentile(a, 2.5)), float(np.nanpercentile(a, 97.5))


def fmt_ci(a, pct=False, nd=4):
    m, lo, hi = ci(a)
    k = 100 if pct else 1
    return f"{m*k:.{nd}f} [{lo*k:.{nd}f}; {hi*k:.{nd}f}]"


def predict_all(df, bundles):
    """Xác suất cho mọi luồng; trả về (probs theo mô hình, mask hợp lệ chung)."""
    probs, valid = {}, np.ones(len(df), bool)
    for name, b in bundles.items():
        X, v = prepare_features(df, b['features'])
        p = np.zeros((len(X), len(CLASSES)), np.float32)
        pv = np.zeros((int(v.sum()), len(CLASSES)), np.float32)
        pv[:, b['model'].classes_] = b['model'].predict_proba(X[v])
        p[v] = pv
        probs[name], valid = p, valid & v
    return probs, valid


def new_rec():
    return {'auc': [], 'dr': [], 'drm': [], 'fpr': [], 'tau': [], 'det': {c: [] for c in ATTACKS}}


def push(r, m, t):
    r['auc'].append(m['auc']); r['dr'].append(m['dr']); r['drm'].append(m['dr_macro'])
    r['fpr'].append(m['fpr']); r['tau'].append(t)
    for c in ATTACKS:
        r['det'][c].append(m['detect'].get(c, np.nan))


def table(recs, label_col, extra=None):
    rows = []
    for name, r in recs.items():
        row = {label_col: name}
        if r['auc'] and not np.isnan(r['auc'][0]):
            row['AUC'] = fmt_ci(r['auc'])
        row.update({
            'τ* (trung vị)': f"{np.median(r['tau']):.4g}",
            'FPR (%)': fmt_ci(r['fpr'], pct=True, nd=2),
            'DR (%)': fmt_ci(r['dr'], pct=True, nd=2),
            'DR TB theo lớp (%)': fmt_ci(r['drm'], pct=True, nd=2),
            **{f'{c} (%)': f"{np.nanmedian(r['det'][c])*100:.2f}" for c in ATTACKS},
        })
        if extra:
            row.update(extra[name])
        rows.append(row)
    return pd.DataFrame(rows)


def run_splits(y, probs, stats=None):
    """Chạy N_SPLITS lần chia đôi. stats=None: chỉ mô hình; có stats: thêm hệ lai."""
    rng = np.random.default_rng(SEED)
    rec = {n: new_rec() for n in probs}
    hyb = {n: new_rec() for n in probs}
    rf_wins, thr, canonical = [], [], None
    for i in range(N_SPLITS):
        cal = stratified_halves(y, rng)
        ev = ~cal
        cal_b = cal & (y == 0)
        cur = {}
        if stats is not None:
            ps_min, bf_min = ids_rules.fit_thresholds(stats[cal_b])
            thr.append((ps_min, bf_min))
            rule = ids_rules.apply_rules(stats, ps_min, bf_min, CLASSES)
        for name, p in probs.items():
            t = calibrate(1 - p[cal_b, 0])
            m = metrics(y[ev], p[ev], t)
            push(rec[name], m, t)
            cur[name] = m
            if stats is not None:
                # Ngân sách FPR 1% tính trên toàn bộ BENIGN của nửa hiệu chỉnh, trừ phần luật đã báo
                budget = int(np.floor(TARGET_FPR * cal_b.sum())) - int((cal_b & (rule >= 0)).sum())
                th = calibrate_count(1 - p[cal_b & (rule < 0), 0], max(budget, 0))
                mh = metrics(y[ev], p[ev], th, rule[ev])
                mh['auc'] = np.nan
                push(hyb[name], mh, th)
                cur[name + ' + luật'] = mh
        d_auc = cur['RandomForest']['auc'] - cur['LightGBM']['auc']
        d_dr = (cur['RandomForest']['dr'] - cur['LightGBM']['dr']) * 100
        rf_wins.append((d_auc > 0.02) or (d_dr > 2.0))
        if i == 0:
            canonical = (ev, cur)
    return rec, hyb, rf_wins, np.array(thr), canonical


# ----------------------------------------------------------------------------- main
def main():
    print("=" * 80)
    print("KỊCH BẢN C — 3 mô hình cây (F_NOOS) trên pcap ngoài tập huấn luyện")
    print("=" * 80)
    df = load_flows()
    print("Số luồng sau gán nhãn:", df['Label'].value_counts().to_dict())

    bundles = {name: joblib.load(path) for name, path in MODELS}
    probs, valid = predict_all(df, bundles)

    sizes = {name: path.stat().st_size / 2**20 for name, path in MODELS}
    speed = {}
    Xb = prepare_features(df[valid].head(1000), bundles['LightGBM']['features'])[0]
    for name, b in bundles.items():
        b['model'].predict_proba(Xb)
        t0 = time.perf_counter()
        for _ in range(5):
            b['model'].predict_proba(Xb)
        speed[name] = (time.perf_counter() - t0) / 5 * 1000

    n_invalid = {k: int(v) for k, v in pd.Series(~valid).groupby(df['Label'].to_numpy()).sum().items()}
    print("Luồng bị loại (Flow Duration = 0 hoặc NaN/inf, như dữ liệu huấn luyện):", n_invalid)
    dfv = df[valid].reset_index(drop=True)
    y = dfv['Label'].map(LMAP).to_numpy()
    probs = {k: p[valid] for k, p in probs.items()}
    counts = dfv['Label'].value_counts()
    print("Số luồng đánh giá:", counts.to_dict())

    # Thống kê theo nguồn tính trên MỌI luồng (backend cũng thấy luồng 1 gói), rồi lấy phần hợp lệ
    t0 = time.perf_counter()
    stats = ids_rules.source_stats(df, group_cols=['Pcap'])[valid].reset_index(drop=True)
    rule_ms = (time.perf_counter() - t0) * 1000
    stat_max = stats.groupby(dfv['Label']).max().reindex(CLASSES)
    print(f"Thống kê theo nguồn: {rule_ms:.0f} ms. Giá trị lớn nhất theo nhãn:\n{stat_max.to_string()}")

    # 1) Tham chiếu: không hiệu chỉnh ngưỡng, toàn bộ dữ liệu
    ref = []
    for name, p in probs.items():
        b = bundles[name]
        for tag, t in [('argmax', None), (f"τ gốc = {b['threshold']:.2f}", b['threshold'])]:
            m = metrics(y, p, t)
            ref.append({'Mô hình': name, 'Luật': tag, 'AUC': round(m['auc'], 4),
                        'DR (%)': round(m['dr'] * 100, 2), 'FPR (%)': round(m['fpr'] * 100, 2),
                        **{f'{c} (%)': round(m['detect'].get(c, np.nan) * 100, 2) for c in ATTACKS}})
    ref = pd.DataFrame(ref)

    # 2) Chính: mô hình đơn lẻ + hệ lai
    rec, hyb, rf_wins, thr, (ev, cur) = run_splits(y, probs, stats)
    extra = {n: {'Dung lượng (MB)': round(sizes[n], 2), 'Dự đoán 1.000 luồng (ms)': round(speed[n], 1)}
             for n in probs}
    summary = table(rec, 'Mô hình', extra)
    hybrid = table({f"{n} + luật": h for n, h in hyb.items()}, 'Hệ')

    d_auc = np.array(rec['RandomForest']['auc']) - np.array(rec['LightGBM']['auc'])
    d_dr = (np.array(rec['RandomForest']['dr']) - np.array(rec['LightGBM']['dr'])) * 100
    d_drm = (np.array(rec['RandomForest']['drm']) - np.array(rec['LightGBM']['drm'])) * 100
    d_dr_h = (np.array(hyb['RandomForest']['dr']) - np.array(hyb['LightGBM']['dr'])) * 100
    rf_rate = float(np.mean(rf_wins))
    final = "RandomForest" if (np.median(d_auc) > 0.02 or np.median(d_dr) > 2.0) else "LightGBM"

    # 3) Độ nhạy: cờ TCP đếm đúng
    dft = with_true_flags(df)
    probs_t, _ = predict_all(dft, bundles)
    probs_t = {k: p[valid] for k, p in probs_t.items()}
    rec_t, _, _, _, _ = run_splits(y, probs_t)
    sens = table(rec_t, 'Mô hình (cờ đếm đúng)')

    cms = {}
    for name, m in cur.items():
        cm = pd.DataFrame(confusion_matrix(y[ev], m['pred'], labels=range(len(CLASSES))),
                          index=[f'Thực_tế_{c}' for c in CLASSES], columns=[f'Dự_đoán_{c}' for c in CLASSES])
        cms[name] = cm
        cm.to_csv(RESULTS_DIR / f"cm_lab_{name.replace(' + luật', '_he_lai')}.csv", encoding='utf-8-sig')

    summary.to_csv(RESULTS_DIR / "lab_3_models_summary.csv", index=False, encoding='utf-8-sig')
    hybrid.to_csv(RESULTS_DIR / "lab_he_lai_summary.csv", index=False, encoding='utf-8-sig')
    sens.to_csv(RESULTS_DIR / "lab_do_nhay_co_tcp.csv", index=False, encoding='utf-8-sig')
    ref.to_csv(RESULTS_DIR / "lab_khong_hieu_chinh.csv", index=False, encoding='utf-8-sig')

    print("\nMô hình đơn lẻ (sau hiệu chỉnh):\n" + summary.to_string(index=False))
    print("\nHệ lai:\n" + hybrid.to_string(index=False))
    print("\nĐộ nhạy — cờ TCP đếm đúng:\n" + sens.to_string(index=False))
    print("\nKhông hiệu chỉnh:\n" + ref.to_string(index=False))
    print(f"\nΔAUC(RF-LGBM) = {fmt_ci(d_auc)} | ΔDR = {fmt_ci(d_dr / 100, pct=True, nd=2)} điểm % "
          f"| ΔDR TB theo lớp = {fmt_ci(d_drm / 100, pct=True, nd=2)} | ΔDR hệ lai = {fmt_ci(d_dr_h / 100, pct=True, nd=2)}")
    print(f"RF thỏa điều kiện chuyển ở {rf_rate*100:.1f}% số lần chia ==> CHỐT: {final}")

    write_report(dict(
        counts=counts, n_invalid=n_invalid, summary=summary, hybrid=hybrid, sens=sens, ref=ref, cms=cms,
        d_auc=d_auc, d_dr=d_dr, d_drm=d_drm, d_dr_h=d_dr_h, rf_rate=rf_rate, final=final,
        thr=thr, stat_max=stat_max, rule_ms=rule_ms, n_flows=len(df)))


def write_report(r):
    def ci_s(a, nd):
        m, lo, hi = ci(a)
        return f"{m:+.{nd}f} [{lo:+.{nd}f}; {hi:+.{nd}f}]"

    thr = r['thr']
    ps_share = r['counts'].get('PortScan', 0) / r['counts'].drop('BENIGN', errors='ignore').sum()
    L = [
        "# BÁO CÁO KỊCH BẢN C — KIỂM THỬ TRÊN PCAP NGOÀI TẬP HUẤN LUYỆN",
        "",
        f"> Sinh tự động bởi `test_lab_3_models.py` lúc {time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"(scikit-learn {sklearn.__version__}). Bộ đặc trưng `F_NOOS` (56 cột).",
        "",
        "## 1. Dữ liệu",
        "",
        "Nhóm không có pcap thu riêng trong lab; cả 4 file là pcap mẫu. Kết quả là kiểm thử trên lưu lượng "
        "ngoài tập huấn luyện, không phải lưu lượng lab 3 VLAN/pfSense.",
        "",
        "| File | Nhãn | Cách gán nhãn | Ghi chú |",
        "|---|---|---|---|",
        "| `benign.pcap` | BENIGN | toàn bộ luồng | chủ yếu DNS và HTTPS, không có SSH |",
        "| `ddos.pcap` | DoS/DDoS | toàn bộ luồng | trùng từng byte `amp.UDP.memcached.ntp.cldap.pcap`: phản xạ UDP, "
        "không có SYN flood |",
        f"| `portscan.pcap` | PortScan | luồng {ATTACKER} → {VICTIM} | quét SYN 65.535 cổng |",
        f"| `bruteforce.pcap` | BruteForce | luồng {ATTACKER} → {VICTIM}:22 | hydra dò mật khẩu SSH |",
        "",
        "| Nhãn | Số luồng đánh giá | Bị loại (Flow Duration = 0) |",
        "|---|---:|---:|",
        *[f"| {c} | {int(r['counts'].get(c, 0)):,} | {r['n_invalid'].get(c, 0):,} |" for c in CLASSES],
        "",
        "## 2. Trích xuất đặc trưng khớp CICFlowMeter",
        "",
        "`pcap_flow_extractor.py` được đối chiếu với dữ liệu huấn luyện (`Data/data/processed/unified.parquet`):",
        "",
        "- Độ dài gói tính cả padding Ethernet (CIC-2017: gói ACK thuần dài 6 byte, gói SYN 58 byte dài 2 byte).",
        "- Header = độ dài header TCP thật (20/24/32/40) hoặc 8 với UDP; chỉ xử lý gói TCP/UDP.",
        "- Active chỉ được ghi khi luồng có khoảng Idle (> 5 s) — đúng ở 100% dòng huấn luyện.",
        "- **Cờ TCP trong dữ liệu huấn luyện là nhị phân và bị ghi lệch cột**: `SYN Flag Count` trùng 100% với "
        "`Fwd PSH Flags`, `RST Flag Count` trùng 100% với `ECE Flag Count`. Quy tắc suy ra (khớp 10 kiểu luồng phổ "
        "biến nhất của CIC-2017): PSH = gói đi đầu tiên có SYN; ACK = gói đi đầu tiên có ACK; FIN = gói đi đầu tiên "
        "có FIN; SYN = gói đi đầu tiên có PSH; URG = gói về đầu tiên chỉ có ACK; RST = 0.",
        "",
        "## 3. Phương pháp",
        "",
        f"Lặp {N_SPLITS} lần chia đôi theo tầng nhãn. Nửa hiệu chỉnh chọn τ* nhỏ nhất thỏa FPR(BENIGN) ≤ "
        f"{TARGET_FPR:.0%}; nửa đánh giá đo AUC (tấn công vs BENIGN), tỉ lệ phát hiện (DR), FPR và phát hiện theo "
        "lớp. Số liệu: trung vị [khoảng 95%]. Luật quyết định: tấn công nếu 1 − P(BENIGN) ≥ τ*.",
        "",
        "## 4. Kết quả mô hình đơn lẻ (sau hiệu chỉnh ngưỡng)",
        "",
        r['summary'].to_markdown(index=False),
        "",
        "## 5. Hệ lai: mô hình + tầng luật theo nguồn",
        "",
        "`ids_rules.py` gom luồng theo IP nguồn trong cửa sổ thời gian. Luật chỉ bổ sung cảnh báo cho luồng mà mô "
        "hình cho là BENIGN:",
        "",
        f"- **BruteForce:** ≥ M phiên TCP mới từ một nguồn tới cùng một cổng đăng nhập "
        f"({', '.join(map(str, sorted(ids_rules.AUTH_PORTS)))}) của cùng một đích trong "
        f"{ids_rules.BRUTEFORCE_WINDOW:.0f} s (sàn {ids_rules.BRUTEFORCE_FLOOR}).",
        f"- **PortScan (dự phòng):** ≥ N cổng khác nhau của cùng một đích trong {ids_rules.PORTSCAN_WINDOW:.0f} s "
        f"(sàn {ids_rules.PORTSCAN_FLOOR}).",
        f"- N, M = giá trị lớn nhất trên BENIGN của nửa hiệu chỉnh + 1, không thấp hơn mức sàn. Trung vị: "
        f"N = {int(np.median(thr[:, 0]))}, M = {int(np.median(thr[:, 1]))}. τ* hiệu chỉnh lại để FPR tổng ≤ 1%.",
        f"- Chi phí: {r['rule_ms']:.0f} ms cho {r['n_flows']:,} luồng (Python thuần).",
        "",
        "Giá trị lớn nhất của hai thống kê theo nhãn:",
        "",
        r['stat_max'].rename(columns={'ps_ports': f"Số cổng / {ids_rules.PORTSCAN_WINDOW:.0f} s",
                                      'bf_conns': f"Số phiên / {ids_rules.BRUTEFORCE_WINDOW:.0f} s"}).to_markdown(),
        "",
        r['hybrid'].to_markdown(index=False),
        "",
        "Ma trận nhầm lẫn (lần chia đầu tiên, nửa đánh giá):",
        "",
    ]
    for name, cm in r['cms'].items():
        L += [f"**{name}**", "", cm.to_markdown(), ""]
    L += [
        "## 6. Độ nhạy: nếu đếm cờ TCP đúng thay vì theo quy ước của dữ liệu huấn luyện",
        "",
        r['sens'].to_markdown(index=False),
        "",
        "## 7. Tham chiếu: không hiệu chỉnh ngưỡng (toàn bộ dữ liệu)",
        "",
        r['ref'].to_markdown(index=False),
        "",
        "## 8. Quy tắc chốt mô hình (mục 3.8.5)",
        "",
        "> Sau khi hiệu chỉnh ngưỡng với FPR ≤ 1%, nếu RF có AUC cao hơn LightGBM quá 0,02 hoặc tỉ lệ phát hiện "
        "cao hơn quá 2 điểm %, chuyển sang RF; ngược lại giữ LightGBM.",
        "",
        f"- ΔAUC (RF − LightGBM) = {ci_s(r['d_auc'], 4)}",
        f"- ΔDR (RF − LightGBM) = {ci_s(r['d_dr'], 2)} điểm %",
        f"- RF thỏa điều kiện chuyển ở {r['rf_rate']*100:.1f}% số lần chia.",
        f"- Tham khảo (ngoài quy tắc): ΔDR trung bình theo lớp = {ci_s(r['d_drm'], 2)} điểm % "
        f"(PortScan chiếm {ps_share:.0%} số luồng tấn công); ΔDR của hệ lai = {ci_s(r['d_dr_h'], 2)} điểm %.",
        "",
        f"**Kết quả theo quy tắc: {'chuyển sang Random Forest' if r['final'] == 'RandomForest' else 'giữ LightGBM'}.**",
        "",
        "## 9. Giới hạn",
        "",
        "- Không phải dữ liệu lab; `ddos.pcap` là mẫu công khai, không có SYN flood như mục 3.8.5 yêu cầu.",
        "- Quy tắc cờ TCP được suy ra từ dữ liệu huấn luyện (chủ yếu CIC-2017), chưa đối chiếu với mã nguồn "
        "CICFlowMeter; backend phải dùng đúng phiên bản CICFlowMeter tạo ra quy ước này.",
        "- `benign.pcap` không có SSH nên ngưỡng BruteForce chưa được kiểm tra báo động giả trên người dùng SSH thật; "
        "dò mật khẩu chậm hoặc phân tán qua nhiều IP sẽ lọt dưới ngưỡng.",
        "- τ* hiệu chỉnh trên khoảng một nửa số luồng BENIGN nên FPR ngoài mẫu dao động quanh 1%.",
        f"- Mô hình huấn luyện bằng scikit-learn 1.6.1, chạy kiểm thử bằng {sklearn.__version__}.",
    ]
    out = RESULTS_DIR / "Bao_Cao_Kich_Ban_C.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"[*] Đã ghi báo cáo: {out}")


if __name__ == "__main__":
    main()
