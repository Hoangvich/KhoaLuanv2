"""ids_runner.py — quy trình huấn luyện/đánh giá CHUNG cho XGBoost, LightGBM, MLP.

Các giai đoạn và tên dòng trong experiments.csv giống hệt notebook Random Forest
(tune_cv4_mau, cv_fold{k}, cv4_trung_binh, test_argmax, test_nguong, cheo_test{bộ}, lab),
nên notebook so sánh đọc được kết quả của mọi mô hình như nhau.

Khác RF ở một điểm: các mô hình này cần early stopping. Tập early stopping là 10% NHÓM
(theo group_id) của phần huấn luyện, tách khỏi fold đang đánh giá, nên điểm CV và điểm
test không bị lạc quan do chọn số vòng/epoch trên chính tập được chấm điểm.

Mỗi mô hình chỉ cần cung cấp một "adapter":
    adapter.name                      tên mô hình (ghi vào log)
    adapter.short                     tên ngắn cho file (xgb, lgbm, mlp)
    adapter.fit(params, Xtr, ytr, Xes, yes, seed) -> (model, info)
        model có predict_proba() và classes_ (nhãn gốc); info có 'iters', 'complexity'
    adapter.finalize(model) -> model  (việc cần làm trước khi đóng gói, vd XGBoost về CPU)
"""
import json, time, warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, make_scorer
from sklearn.model_selection import ParameterSampler

from ids_features import decide, predict_frame
from ids_common import (WORK, cap_sample, choose_threshold, evaluate, evaluate_external,
                        frac_sample, full_proba, inference_time, load_data, log_run,
                        save_bundle, save_tables, xy)

ES_MOD = 10   # nhóm có group_id % 10 == 0 -> tập early stopping (~10%)


class Remapped:
    """Chỉ dùng NỘI BỘ khi mô hình được học trên một phần các lớp (Bảng B).
    Không bao giờ được đóng gói vào bundle."""

    def __init__(self, model, present):
        self.model, self.classes_ = model, np.asarray(present)

    def predict_proba(self, X):
        return self.model.predict_proba(X)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(axis=1)]


def split_es(frame):
    es = (frame['group_id'].to_numpy() % ES_MOD) == 0
    return frame[~es], frame[es]


def fit_frame(adapter, params, frame, feats, seed):
    tr, es = split_es(frame)
    Xtr, ytr = xy(tr, feats)
    Xes, yes = xy(es, feats)
    t0 = time.time()
    model, info = adapter.fit(params, Xtr, ytr, Xes, yes, seed)
    info['fit_giay'] = round(time.time() - t0, 1)
    return model, info


def run(adapter, C):
    """C: dict cấu hình (xem cell cấu hình trong notebook)."""
    warnings.filterwarnings('ignore', category=UserWarning)
    T0 = time.time()
    el = lambda: f'{(time.time() - T0) / 60:.1f} phút'
    run_id = time.strftime('%Y%m%d-%H%M%S') + f'-{adapter.short}' + ('-quick' if C['QUICK'] else '')
    run_dir = WORK / 'runs' / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    SEED, MODEL = C['SEED'], adapter.name

    # ---------------------------------------------------------------- 1. dữ liệu
    df, fs, SHA = load_data()
    if C['QUICK']:
        df = frac_sample(df, 0.03, seed=SEED).reset_index(drop=True)
        print(f'QUICK: dùng {len(df):,} dòng')
    CLASSES = fs['classes']
    K, B = len(CLASSES), CLASSES.index('BENIGN')
    train_pool = df[df['fold'] != 0]
    test = df[df['fold'] == 0]          # chỉ chạm tới ở bước 4
    print(f'train (fold 1-4): {len(train_pool):,} | test (fold 0): {len(test):,}')

    # ---------------------------------------------------------------- 2. tinh chỉnh
    feats = fs[C['TUNE_FSET']]
    tune = cap_sample(train_pool, C['TUNE_CAP'], C['TUNE_BENIGN_CAP'], SEED)
    print(f'\nTinh chỉnh trên {len(tune):,} dòng, {C["N_ITER"]} cấu hình × 4 fold | {el()}')
    configs = list(ParameterSampler(C['SPACE'], n_iter=C['N_ITER'], random_state=SEED))
    rows = []
    for i, p in enumerate(configs):
        t0, scores, cx, its = time.time(), [], [], []
        for k in (1, 2, 3, 4):
            m, info = fit_frame(adapter, p, tune[tune.fold != k], feats, SEED)
            va = tune[tune.fold == k]
            Xva, yva = xy(va, feats)
            pred = decide(full_proba(m, Xva, K), B, None)
            scores.append(f1_score(yva, pred, labels=np.unique(yva), average='macro'))
            cx.append(info['complexity']); its.append(info['iters'])
        rows.append({'cfg': i, **{k: str(v) for k, v in p.items()},
                     'cv_macro_f1_mean': np.mean(scores), 'cv_macro_f1_std': np.std(scores),
                     'do_phuc_tap': float(np.mean(cx)), 'vong_hoac_epoch': float(np.mean(its)),
                     'giay': round(time.time() - t0, 1)})
        print(f'  cfg {i + 1}/{C["N_ITER"]}: macro-F1 {np.mean(scores):.4f} ± {np.std(scores):.4f}'
              f' | {np.mean(its):.0f} vòng/epoch | {time.time() - t0:.0f}s | {el()}')
    tune_df = pd.DataFrame(rows).sort_values('cv_macro_f1_mean', ascending=False)
    tune_df.to_csv(run_dir / 'tuning.csv', index=False, encoding='utf-8')
    # Quy tắc 1 độ lệch chuẩn: trong nhóm gần tốt nhất, chọn cấu hình ít phức tạp nhất.
    top = tune_df.iloc[0]
    near = tune_df[tune_df.cv_macro_f1_mean >= top.cv_macro_f1_mean - top.cv_macro_f1_std]
    best_row = near.sort_values('do_phuc_tap').iloc[0]
    BEST = configs[int(best_row.cfg)]
    print(f'\nChọn cfg {int(best_row.cfg)}: {BEST}')
    log_run(run_id, MODEL, C['TUNE_FSET'], 'tune_cv4_mau',
            {'macro_f1': round(float(best_row.cv_macro_f1_mean), 6),
             'macro_f1_std': round(float(best_row.cv_macro_f1_std), 6), 'n': len(tune)},
            params=BEST, sha=SHA)

    summary = {}
    for fset in C['FSETS']:
        feats = fs[fset]
        print(f'\n================ {fset} ({len(feats)} đặc trưng) | {el()} ================')
        assert 1 in C['FULL_CV'][fset], 'fold 1 phải có để chọn ngưỡng'

        # ------------------------------------------------------------ 3. CV đầy đủ
        cv_scores, thr = [], None
        for k in C['FULL_CV'][fset]:
            m, info = fit_frame(adapter, BEST, train_pool[train_pool.fold != k], feats, SEED)
            va = train_pool[train_pool.fold == k]
            P = full_proba(m, xy(va, feats)[0], K)
            sc, _ = evaluate(va['y'], P, decide(P, B, None), CLASSES, va, va['n_dup'])
            cv_scores.append(sc)
            log_run(run_id, MODEL, fset, f'cv_fold{k}', sc, BEST, SHA,
                    {'fit_giay': info['fit_giay'], 'vong_hoac_epoch': info['iters']})
            if k == 1:
                thr, thr_tab = choose_threshold(va['y'].to_numpy(), P, B, CLASSES, C['TARGET_FPR'])
                thr_tab.to_csv(run_dir / f'{fset}_nguong_validation.csv', index=False)
                print(f'  Ngưỡng chọn trên fold 1 (FPR <= {C["TARGET_FPR"]:.0%}): {thr:.4f}')
            del m, P
        if len(cv_scores) > 1:
            keys = [k for k in cv_scores[0] if isinstance(cv_scores[0][k], float)]
            agg = {k: round(float(np.mean([s[k] for s in cv_scores])), 6) for k in keys}
            agg.update({f'{k}_std': round(float(np.std([s[k] for s in cv_scores])), 6)
                        for k in ('macro_f1', 'fpr_benign', 'detection_rate')})
            log_run(run_id, MODEL, fset, f'cv{len(cv_scores)}_trung_binh', agg, BEST, SHA)

        # ------------------------------------------------------------ 4. mô hình cuối + test
        final, info = fit_frame(adapter, BEST, train_pool, feats, SEED)
        final = adapter.finalize(final)                # trước khi dự đoán, để test = triển khai
        Xte = xy(test, feats)[0]
        Pte = full_proba(final, Xte, K)
        timing = inference_time(final, Xte)
        extra = {'fit_giay': info['fit_giay'], 'vong_hoac_epoch': info['iters'], **timing}
        test_scores = None
        for stage, t in (('test_argmax', None), ('test_nguong', thr)):
            sc, tb = evaluate(test['y'], Pte, decide(Pte, B, t), CLASSES, test, test['n_dup'])
            log_run(run_id, MODEL, fset, stage, sc, {**BEST, 'threshold': t}, SHA, extra)
            save_tables(run_dir, f'{fset}_{stage}', tb)
            if stage == 'test_nguong':
                test_scores = sc
                print(tb['confusion'].to_string())
        pd.DataFrame(Pte, columns=[f'p_{c}' for c in CLASSES]).assign(
            y=test['y'].to_numpy(), row=test.index.to_numpy()).to_parquet(
            run_dir / f'{fset}_test_proba.parquet', index=False)

        # ------------------------------------------------------------ 5. mức quan trọng
        imp = pd.DataFrame({'dac_trung': feats})
        native = getattr(final, 'feature_importances_', None)
        if native is not None:
            imp['native_gain'] = native
        ps = cap_sample(test, C['PERM_CAP'], C['PERM_CAP'], SEED)
        Xp, yp = xy(ps, feats)
        pi = permutation_importance(final, Xp, yp, scoring=make_scorer(f1_score, average='macro'),
                                    n_repeats=3, random_state=SEED, n_jobs=1)
        imp['permutation_mean'], imp['permutation_std'] = pi.importances_mean, pi.importances_std
        imp = imp.sort_values('permutation_mean', ascending=False)
        imp.to_csv(run_dir / f'{fset}_feature_importance.csv', index=False, encoding='utf-8')
        print('  Top 10 permutation importance:\n', imp.head(10).to_string(index=False))

        # ------------------------------------------------------------ 6. đóng gói + kiểm tra
        path = WORK / 'models' / f'{adapter.short}_{fset}.joblib'
        save_bundle(path, final, feats, fset, CLASSES, thr, C['TARGET_FPR'], BEST, run_id, SHA,
                    test_scores, MODEL)
        mb = round(path.stat().st_size / 2**20, 2)
        re = joblib.load(path)
        out = predict_frame(re, test.head(2000)[feats])
        ref = np.asarray(CLASSES, dtype=object)[decide(Pte[:2000], B, thr)]
        assert (out['label'].to_numpy() == ref).all(), 'Bundle load lại cho kết quả khác!'
        print(f'  Đã lưu {path.name} ({mb} MB), load lại khớp 100%')
        summary[fset] = {'macro_f1': test_scores['macro_f1'],
                         'fpr_benign': test_scores['fpr_benign'], 'model_mb': mb, **timing}
        del final, Pte, Xte, re

        # ------------------------------------------------------------ 7. Bảng B
        if C['RUN_CROSS_DATASET']:
            for test_ds in ('2017', '2018', '2019'):
                tr = df[df.source_dataset != test_ds]
                te = df[df.source_dataset == test_ds]
                te = te[~te.group_id.isin(tr.group_id.unique())]
                te = te[te.y.isin(tr.y.unique())]
                tr = cap_sample(tr, C['CROSS_CAP'], C['CROSS_CAP'], SEED)
                m, info = fit_frame(adapter, BEST, tr, feats, SEED)
                P = full_proba(m, xy(te, feats)[0], K)
                sc, tb = evaluate(te['y'], P, decide(P, B, None), CLASSES, te)
                log_run(run_id, MODEL, fset, f'cheo_test{test_ds}', sc, BEST, SHA,
                        {'train_bo': '+'.join(sorted({'2017', '2018', '2019'} - {test_ds}))})
                save_tables(run_dir, f'{fset}_cheo_test{test_ds}', tb)
                del m, P

        # ------------------------------------------------------------ 8. Bảng C (lab)
        if C.get('LAB_CSV'):
            sc, tb = evaluate_external(joblib.load(path), C['LAB_CSV'], C['LAB_LABEL_COL'],
                                       C['LAB_LABEL_MAP'])
            log_run(run_id, MODEL, fset, 'lab', sc, BEST, SHA)
            save_tables(run_dir, f'{fset}_lab', tb)

    json.dump({'run_id': run_id, 'best_params': BEST, 'summary': summary, 'quick': C['QUICK'],
               'thoi_gian_phut': round((time.time() - T0) / 60, 1)},
              open(run_dir / 'summary.json', 'w', encoding='utf-8'), ensure_ascii=False,
              indent=2, default=str)
    print(f'\nXONG sau {el()}.')
    print(pd.DataFrame(summary).T)
    print(f'Kết quả: {WORK / "experiments.csv"}, {run_dir}, {WORK / "models"}')
    return run_id
