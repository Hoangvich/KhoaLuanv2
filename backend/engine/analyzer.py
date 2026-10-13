"""analyzer.py — gán nhãn một lô luồng: mô hình phân loại từng luồng + tầng luật theo nguồn.

Analyzer giữ trạng thái giữa các lô (bộ đệm luồng gần đây) vì một lượt quét cổng hay dò mật khẩu
thường trải qua nhiều chu kỳ 5 s.
"""
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from engine import ids_rules
from engine.cic_compat import prepare_input
from engine.ids_features import decide, prepare_features

ATTACK_LABELS = ['DoS/DDoS', 'PortScan', 'BruteForce']
RULE_COLS = ['Timestamp', 'Src IP', 'Dst IP', 'Destination Port', 'Protocol',
             'Total Fwd Packets', 'Total Backward Packets']
OUT_COLS = ['ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'duration_us',
            'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes', 'valid', 'label', 'attack_score',
            'source', 'rule_detail']


@dataclass
class RuntimeConfig:
    tau: float
    ps_min: int = ids_rules.PORTSCAN_FLOOR
    bf_min: int = ids_rules.BRUTEFORCE_FLOOR


class Analyzer:
    def __init__(self, model_path, flag_mode='auto', tz='Asia/Ho_Chi_Minh', n_jobs=1):
        self.model_path = Path(model_path)
        self.bundle = joblib.load(self.model_path)
        model = self.bundle['model']
        if hasattr(model, 'n_jobs'):
            # Lô nhỏ: khởi động xử lý song song tốn hơn lợi (RF n_jobs=-1 mất ~47 ms cho 1 luồng)
            model.n_jobs = n_jobs
        self.classes = list(self.bundle['classes'])
        self.benign_index = int(self.bundle['benign_index'])
        self.flag_mode = flag_mode
        self.tz = tz
        self.config = RuntimeConfig(tau=float(self.bundle['threshold']))
        self._ps_buf = pd.DataFrame(columns=RULE_COLS)
        self._bf_buf = pd.DataFrame(columns=RULE_COLS)
        self.last_flag_mode = None

    # ------------------------------------------------------------------ thông tin
    @property
    def info(self) -> dict:
        b = self.bundle
        scores = b.get('test_scores', {})
        return {
            'model_name': b.get('model_name'), 'run_id': b.get('run_id'), 'feature_set': b.get('feature_set'),
            'n_features': len(b['features']), 'classes': self.classes,
            'bundle_threshold': float(b['threshold']), 'tau': self.config.tau,
            'created': str(b.get('created')), 'versions': b.get('versions'),
            'macro_f1_test': scores.get('macro_f1'), 'file': self.model_path.name,
            'file_size_mb': round(self.model_path.stat().st_size / 2**20, 2),
        }

    def update_config(self, tau=None, ps_min=None, bf_min=None):
        if tau is not None:
            self.config.tau = float(tau)
        if ps_min is not None:
            self.config.ps_min = int(ps_min)
        if bf_min is not None:
            self.config.bf_min = int(bf_min)

    def reset_state(self):
        self._ps_buf = self._ps_buf.iloc[0:0]
        self._bf_buf = self._bf_buf.iloc[0:0]

    # ------------------------------------------------------------------ mô hình
    def _model_predict(self, df):
        n = len(df)
        X, valid = prepare_features(df, self.bundle['features'])
        pred = np.full(n, -1, dtype=np.int64)
        score = np.full(n, np.nan)
        if valid.any():
            p = np.zeros((int(valid.sum()), len(self.classes)), np.float32)
            p[:, self.bundle['model'].classes_] = self.bundle['model'].predict_proba(X[valid])
            pred[valid] = decide(p, self.benign_index, self.config.tau)
            score[valid] = 1.0 - p[:, self.benign_index]
        return valid, pred, score

    # ------------------------------------------------------------------ tầng luật
    def _rules(self, df):
        cur = df[RULE_COLS].copy()
        cur['_cur'] = True
        t_max = float(cur['Timestamp'].max())

        ps_frame = pd.concat([self._ps_buf.assign(_cur=False), cur], ignore_index=True) if len(self._ps_buf) \
            else cur.reset_index(drop=True)
        ps = ids_rules.source_stats(ps_frame)['ps_ports'].to_numpy()[ps_frame['_cur'].to_numpy(bool)]

        auth = (cur['Protocol'] == 6) & cur['Destination Port'].isin(ids_rules.AUTH_PORTS)
        bf_frame = pd.concat([self._bf_buf.assign(_cur=False), cur[auth]], ignore_index=True) if len(self._bf_buf) \
            else cur[auth].reset_index(drop=True)
        bf = np.zeros(len(cur), dtype=np.int64)
        if len(bf_frame):
            bf_all = ids_rules.source_stats(bf_frame)['bf_conns'].to_numpy()
            bf[auth.to_numpy()] = bf_all[bf_frame['_cur'].to_numpy(bool)]

        # Cập nhật bộ đệm: chỉ giữ phần còn nằm trong cửa sổ
        self._ps_buf = ps_frame.loc[ps_frame['Timestamp'] > t_max - ids_rules.PORTSCAN_WINDOW, RULE_COLS]
        self._bf_buf = bf_frame.loc[bf_frame['Timestamp'] > t_max - ids_rules.BRUTEFORCE_WINDOW, RULE_COLS]

        stats = pd.DataFrame({'ps_ports': ps, 'bf_conns': bf})
        rule_pred = ids_rules.apply_rules(stats, self.config.ps_min, self.config.bf_min, self.classes)
        detail = np.full(len(cur), None, dtype=object)
        i_ps, i_bf = self.classes.index('PortScan'), self.classes.index('BruteForce')
        m = rule_pred == i_ps
        detail[m] = [f'{v} cổng / {ids_rules.PORTSCAN_WINDOW:.0f} s (ngưỡng {self.config.ps_min})' for v in ps[m]]
        m = rule_pred == i_bf
        ports = cur['Destination Port'].to_numpy()
        detail[m] = [f'{v} phiên tới cổng {p} / {ids_rules.BRUTEFORCE_WINDOW:.0f} s (ngưỡng {self.config.bf_min})'
                     for v, p in zip(bf[m], ports[m])]
        return rule_pred, detail

    # ------------------------------------------------------------------ API chính
    def analyze(self, df_raw: pd.DataFrame) -> pd.DataFrame:
        """Gán nhãn một lô luồng thô từ CICFlowMeter. Trả về DataFrame theo OUT_COLS."""
        if df_raw is None or len(df_raw) == 0:
            return pd.DataFrame(columns=OUT_COLS)
        df, self.last_flag_mode = prepare_input(df_raw, self.flag_mode, self.tz)
        ts = df['Timestamp'].to_numpy(np.float64)
        ts = np.where(np.isnan(ts), time.time(), ts)
        df['Timestamp'] = ts

        valid, model_pred, score = self._model_predict(df)
        rule_pred, detail = self._rules(df)

        # Luật chỉ bổ sung: áp cho luồng mô hình cho là BENIGN và luồng mô hình không chấm được (1 gói)
        from_rule = (rule_pred >= 0) & ((model_pred == self.benign_index) | ~valid)
        final = np.where(from_rule, rule_pred, model_pred)

        labels = np.array(self.classes + [None], dtype=object)[np.where(final >= 0, final, len(self.classes))]
        is_attack = np.isin(labels, ATTACK_LABELS)
        source = np.where(is_attack, np.where(from_rule, 'rule', 'model'), None)

        num = lambda c: pd.to_numeric(df[c], errors='coerce').to_numpy()  # noqa: E731
        return pd.DataFrame({
            'ts': ts,
            'src_ip': df['Src IP'].to_numpy(), 'src_port': df['Src Port'].to_numpy(),
            'dst_ip': df['Dst IP'].to_numpy(), 'dst_port': df['Destination Port'].to_numpy(),
            'protocol': df['Protocol'].to_numpy(),
            'duration_us': num('Flow Duration'),
            'fwd_pkts': num('Total Fwd Packets'), 'bwd_pkts': num('Total Backward Packets'),
            'fwd_bytes': num('Total Length of Fwd Packets'), 'bwd_bytes': num('Total Length of Bwd Packets'),
            'valid': valid, 'label': labels, 'attack_score': score,
            'source': source, 'rule_detail': np.where(source == 'rule', detail, None),
        })[OUT_COLS]
