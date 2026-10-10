"""ids_common.py — phần dùng chung cho MỌI mô hình (RF, XGBoost, LightGBM, MLP, IF).

Mọi notebook huấn luyện import file này để:
  - đọc cùng một bộ dữ liệu, cùng cách chia fold (không ai tự chia lại),
  - đánh giá bằng cùng một hàm, cùng một bộ chỉ số,
  - ghi cùng một nhật ký thí nghiệm (experiments.csv),
  - đóng gói mô hình theo cùng một định dạng cho backend.
"""
import json, os, platform, time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support, roc_auc_score)

from ids_features import decide, prepare_features

WORK = Path('/kaggle/working') if Path('/kaggle/working').exists() else Path('.').resolve()
LOG_PATH = WORK / 'experiments.csv'
PROTOCOL = ('dedup vector trùng (F_ALL) + 5 fold theo nhóm (hash F_NOOS), '
            'phân tầng bộ dữ liệu×lớp, test = fold 0, seed 42')


# ----------------------------------------------------------------------------- dữ liệu
def load_data(data_dir=None):
    """Đọc parquet sạch + feature_sets.json. Tự tìm trong /kaggle/input nếu không truyền."""
    if data_dir is None:
        data_dir = os.environ.get('IDS_DATA_DIR')
    if data_dir is None:
        hits = sorted(Path('/kaggle/input').rglob('unified_clean.parquet'))
        assert len(hits) == 1, f'Cần đúng 1 file unified_clean.parquet, tìm thấy: {hits}'
        data_dir = hits[0].parent
    data_dir = Path(data_dir)
    df = pd.read_parquet(data_dir / 'unified_clean.parquet')
    fs = json.load(open(data_dir / 'feature_sets.json', encoding='utf-8'))
    sha = None
    rp = data_dir / 'clean_report.json'
    if rp.exists():
        sha = json.load(open(rp, encoding='utf-8')).get('ket_qua', {}).get('sha256')
    df['y'] = pd.Categorical(df['label'], categories=fs['classes']).codes.astype(np.int8)
    assert (df['y'] >= 0).all(), 'Có nhãn ngoài danh sách classes'
    for key in ('F_ALL', 'F_NOOS'):
        assert all(c in df.columns for c in fs[key]), f'Thiếu cột của {key}'
    print(f'Dữ liệu: {len(df):,} dòng | F_ALL={len(fs["F_ALL"])} | F_NOOS={len(fs["F_NOOS"])} '
          f'| sha256={str(sha)[:12]}')
    return df, fs, sha


def cap_sample(df, cap, benign_cap=None, seed=42):
    """Lấy mẫu theo từng ô (bộ dữ liệu × lớp), mỗi ô tối đa `cap` dòng (BENIGN: benign_cap)."""
    parts = []
    for (_, lab), g in df.groupby(['source_dataset', 'label'], observed=True):
        c = benign_cap if (lab == 'BENIGN' and benign_cap) else cap
        parts.append(g if len(g) <= c else g.sample(c, random_state=seed))
    return pd.concat(parts)


def frac_sample(df, frac, min_rows=300, seed=42):
    """Lấy mẫu một tỉ lệ ở mỗi ô nhưng giữ tối thiểu min_rows (dùng cho chế độ QUICK)."""
    parts = []
    for _, g in df.groupby(['source_dataset', 'label', 'fold'], observed=True):
        n = min(len(g), max(min_rows, int(len(g) * frac)))
        parts.append(g.sample(n, random_state=seed))
    return pd.concat(parts)


def xy(df, feats):
    return df[feats].to_numpy(np.float32), df['y'].to_numpy()


def full_proba(model, X, k):
    """predict_proba luôn trả đủ k cột, kể cả khi mô hình chỉ học một phần các lớp."""
    p = np.zeros((len(X), k), np.float32)
    p[:, model.classes_] = model.predict_proba(X)
    return p


# ----------------------------------------------------------------------------- đánh giá
def evaluate(y, proba, pred, classes, meta=None, weights=None):
    """Trả (chỉ số dạng số, các bảng chi tiết). Macro chỉ tính trên các lớp có trong y."""
    y, pred = np.asarray(y), np.asarray(pred)
    b = classes.index('BENIGN')
    present = [int(c) for c in np.unique(y)]
    s = {'n': int(len(y)),
         'macro_f1': f1_score(y, pred, labels=present, average='macro', zero_division=0)}
    if weights is not None:
        s['macro_f1_w_ndup'] = f1_score(y, pred, labels=present, average='macro',
                                        sample_weight=np.asarray(weights), zero_division=0)
    p, r, f, sup = precision_recall_fscore_support(y, pred, labels=present, zero_division=0)
    for i, c in enumerate(present):
        name = classes[c]
        s[f'precision_{name}'], s[f'recall_{name}'], s[f'f1_{name}'] = p[i], r[i], f[i]
        s[f'support_{name}'] = int(sup[i])
        yc = (y == c)
        if 0 < yc.sum() < len(y):
            s[f'auc_{name}'] = roc_auc_score(yc, proba[:, c])
            s[f'prauc_{name}'] = average_precision_score(yc, proba[:, c])
    aucs = [s[f'auc_{classes[c]}'] for c in present if f'auc_{classes[c]}' in s]
    s['auc_ovr_macro'] = float(np.mean(aucs)) if aucs else np.nan
    is_b = (y == b)
    s['fpr_benign'] = float((pred[is_b] != b).mean()) if is_b.any() else np.nan
    s['detection_rate'] = float((pred[~is_b] != b).mean()) if (~is_b).any() else np.nan
    if is_b.any() and (~is_b).any():
        s['auc_attack_vs_benign'] = roc_auc_score(~is_b, 1.0 - proba[:, b])
    s['accuracy_chi_tham_khao'] = float((pred == y).mean())

    t = {'confusion': pd.DataFrame(confusion_matrix(y, pred, labels=range(len(classes))),
                                   index=[f'that_{c}' for c in classes],
                                   columns=[f'du_doan_{c}' for c in classes])}
    if meta is not None:
        m = meta[['source_dataset', 'label', 'attack_subtype']].copy()
        m['dung'] = (pred == y)
        m['bao_tan_cong'] = (pred != b)
        t['theo_subtype'] = (m.groupby(['source_dataset', 'label', 'attack_subtype'], observed=True)
                             .agg(n=('dung', 'size'), ti_le_dung=('dung', 'mean'),
                                  ti_le_bao_tan_cong=('bao_tan_cong', 'mean'))
                             .round(4).reset_index())
    return {k: (round(float(v), 6) if isinstance(v, (float, np.floating)) else v)
            for k, v in s.items()}, t


def choose_threshold(y, proba, benign_index, classes, target_fpr=0.01):
    """Chọn ngưỡng trên VALIDATION: macro-F1 cao nhất với điều kiện FPR(BENIGN) <= target."""
    y = np.asarray(y)
    score = 1.0 - proba[:, benign_index]
    is_b = (y == benign_index)
    present = list(np.unique(y))
    cands = np.unique(np.concatenate([
        np.linspace(0.02, 0.98, 49),
        np.quantile(score[is_b], [0.99, 0.995, 0.999, 0.9995, 0.9999])]))
    rows = []
    for t in cands:
        pred = decide(proba, benign_index, t)
        rows.append({'threshold': float(t),
                     'fpr_benign': float((pred[is_b] != benign_index).mean()),
                     'macro_f1': f1_score(y, pred, labels=present, average='macro', zero_division=0)})
    tab = pd.DataFrame(rows)
    ok = tab[tab.fpr_benign <= target_fpr]
    if ok.empty:
        print(f'CẢNH BÁO: không ngưỡng nào đạt FPR <= {target_fpr}; chọn ngưỡng có FPR thấp nhất.')
        best = tab.sort_values(['fpr_benign', 'macro_f1'], ascending=[True, False]).iloc[0]
    else:
        best = ok.sort_values('macro_f1', ascending=False).iloc[0]
    return float(best.threshold), tab


def inference_time(model, X, batch=10_000, repeat=3):
    """Mili giây cho một lô `batch` flow và cho 1 flow đơn lẻ (trung vị của `repeat` lần)."""
    Xb = X[:batch]
    t_b, t_1 = [], []
    for _ in range(repeat):
        t0 = time.perf_counter(); model.predict_proba(Xb); t_b.append(time.perf_counter() - t0)
        t0 = time.perf_counter(); model.predict_proba(X[:1]); t_1.append(time.perf_counter() - t0)
    return {'ms_per_batch': round(1000 * float(np.median(t_b)), 1), 'batch_rows': len(Xb),
            'ms_per_1_flow': round(1000 * float(np.median(t_1)), 2)}


# ----------------------------------------------------------------------------- nhật ký
def versions():
    import scipy
    v = {'python': platform.python_version(), 'scikit-learn': sklearn.__version__,
         'numpy': np.__version__, 'pandas': pd.__version__, 'scipy': scipy.__version__,
         'joblib': joblib.__version__}
    for lib in ('xgboost', 'lightgbm'):       # chỉ ghi nếu notebook đã dùng thư viện đó
        import sys
        if lib in sys.modules:
            v[lib] = sys.modules[lib].__version__
    return v


def log_run(run_id, model_name, fset, stage, scores, params=None, sha=None, extra=None):
    """Thêm một dòng vào experiments.csv. Mỗi dòng = một lần đánh giá."""
    row = {'run_id': run_id, 'thoi_gian': time.strftime('%Y-%m-%d %H:%M:%S'),
           'mo_hinh': model_name, 'bo_dac_trung': fset, 'giai_doan': stage,
           'giao_thuc_chia': PROTOCOL, 'data_sha256': sha,
           'tham_so': json.dumps(params, ensure_ascii=False, default=str) if params else '',
           **scores, **(extra or {})}
    new = pd.DataFrame([row])
    old = pd.read_csv(LOG_PATH) if LOG_PATH.exists() else pd.DataFrame()
    pd.concat([old, new], ignore_index=True).to_csv(LOG_PATH, index=False, encoding='utf-8')
    keys = ['macro_f1', 'fpr_benign', 'detection_rate', 'auc_ovr_macro']
    print(f'  [{stage}] ' + ' | '.join(f'{k}={scores[k]:.4f}' for k in keys
                                         if k in scores and scores[k] == scores[k]))


def save_tables(run_dir, stage, tables):
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, t in tables.items():
        t.to_csv(run_dir / f'{stage}_{name}.csv', encoding='utf-8')


# ----------------------------------------------------------------------------- đóng gói
def save_bundle(path, model, features, fset, classes, threshold, target_fpr,
                params, run_id, sha, test_scores, model_name):
    """Lưu MỘT file .joblib chứa đủ mọi thứ backend cần. Chỉ chứa đối tượng sklearn + dict,
    không có class tự viết, nên backend chỉ cần cài đúng phiên bản thư viện là load được."""
    bundle = {
        'model': model, 'model_name': model_name,
        'features': list(features), 'feature_set': fset,
        'classes': list(classes), 'benign_index': classes.index('BENIGN'),
        'threshold': threshold, 'target_fpr': target_fpr,
        'decision_rule': 'tấn công nếu 1-P(BENIGN) >= threshold; lớp = argmax các lớp tấn công',
        'preprocessing': 'ids_features.prepare_features (không scale)',
        'params': params, 'run_id': run_id, 'data_sha256': sha, 'split_protocol': PROTOCOL,
        'test_scores': test_scores, 'versions': versions(),
        'created': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    card = {k: v for k, v in bundle.items() if k != 'model'}
    json.dump(card, open(path.with_suffix('.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2, default=str)
    v = bundle['versions']
    (path.parent / f'requirements_backend_{path.stem}.txt').write_text(
        '\n'.join(f'{k}=={val}' for k, val in v.items() if k != 'python') + '\n',
        encoding='utf-8')
    return bundle


def evaluate_external(bundle, csv_path, label_col, label_map):
    """Đánh giá mô hình đã đóng gói trên CSV do CICFlowMeter xuất ra (dữ liệu lab)."""
    raw = pd.read_csv(csv_path)
    X, valid = prepare_features(raw, bundle['features'])
    lab = raw[label_col].astype(str).str.strip().map(label_map)
    unknown = sorted(raw.loc[lab.isna(), label_col].astype(str).unique())
    assert not unknown, f'Nhãn lab chưa có trong label_map: {unknown}'
    classes = bundle['classes']
    y = lab.map({c: i for i, c in enumerate(classes)}).to_numpy()
    print(f'Lab: {len(raw):,} dòng, loại {int((~valid).sum()):,} dòng không hợp lệ (NaN/inf/thời lượng 0)')
    model = bundle['model']
    p = full_proba(model, X[valid], len(classes))
    pred = decide(p, bundle['benign_index'], bundle['threshold'])
    return evaluate(y[valid], p, pred, classes)
