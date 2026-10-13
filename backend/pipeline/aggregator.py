"""Gom các luồng tấn công thành cảnh báo (CN4: mỗi lượt tấn công sinh ít cảnh báo).

Khoá gom:
    DoS/DDoS   : (nhãn, IP đích)              — nhiều nguồn dồn về một đích
    PortScan   : (nhãn, IP nguồn, IP đích)
    BruteForce : (nhãn, IP nguồn, IP đích, cổng)
Cảnh báo được cập nhật khi luồng mới cùng khoá đến trong vòng `idle` giây kể từ luồng cuối, và tự đóng khi
quá `idle` giây không có luồng mới. "Thời điểm hiện tại" tính theo thời gian luồng (để phát lại pcap cũ vẫn
đúng) cộng thêm thời gian thực đã trôi qua.
"""
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.models import Alert

SEVERITY = {'DoS/DDoS': 'high', 'BruteForce': 'high', 'PortScan': 'medium'}
ATTACKS = list(SEVERITY)


def to_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)


def group_keys(out: pd.DataFrame) -> pd.Series:
    lab, src, dst, port = out['label'], out['src_ip'], out['dst_ip'], out['dst_port'].astype(str)
    return pd.Series(np.select(
        [lab == 'DoS/DDoS', lab == 'PortScan'],
        [lab + '|*|' + dst + '|*', lab + '|' + src + '|' + dst + '|*'],
        lab + '|' + src + '|' + dst + '|' + port), index=out.index)


class AlertAggregator:
    def __init__(self):
        self._ref_flow_ts = None
        self._ref_wall = None
        self._sources: dict[int, set] = {}     # IP nguồn của cảnh báo đang mở (đếm src_count cho DDoS)

    def now_ref(self) -> float:
        if self._ref_flow_ts is None:
            return time.time()
        return self._ref_flow_ts + (time.time() - self._ref_wall)

    def update(self, db: Session, out: pd.DataFrame, idle: float):
        """Trả về (cảnh báo mới, số cảnh báo được cập nhật, mảng alert_id theo từng dòng của out)."""
        alert_ids = np.full(len(out), None, dtype=object)
        if len(out):
            t_max = float(np.nanmax(out['ts']))
            if self._ref_flow_ts is None or t_max > self.now_ref():
                self._ref_flow_ts, self._ref_wall = t_max, time.time()
        atk = out[out['label'].isin(ATTACKS)]
        if atk.empty:
            return [], 0, alert_ids

        new, updated = [], 0
        keys = group_keys(atk)
        for key, g in atk.groupby(keys, sort=False):
            first, last = float(g['ts'].min()), float(g['ts'].max())
            score = float(np.nanmax(g['attack_score'])) if g['attack_score'].notna().any() else None
            srcs = set(g['src_ip'])
            source = '+'.join(sorted(set(g['source'].dropna()))) or 'model'
            detail = g['rule_detail'].dropna()
            detail = detail.iloc[-1] if len(detail) else None
            r0 = g.iloc[0]

            a = (db.query(Alert).filter(Alert.group_key == key, Alert.status != 'closed')
                 .order_by(Alert.last_seen.desc()).first())
            if a is not None and first - a.last_seen.timestamp() <= idle:
                a.last_seen = max(a.last_seen, to_dt(last))
                a.flow_count += len(g)
                if score is not None:
                    a.max_score = max(a.max_score or 0.0, score)
                a.source = '+'.join(sorted(set(a.source.split('+')) | set(source.split('+'))))
                a.rule_detail = detail or a.rule_detail
                s = self._sources.setdefault(a.id, set())
                s |= srcs
                a.src_count = max(a.src_count, len(s))
                updated += 1
            else:
                lab = r0['label']
                a = Alert(group_key=key, label=lab, severity=SEVERITY[lab],
                          src_ip=None if lab == 'DoS/DDoS' else r0['src_ip'], dst_ip=r0['dst_ip'],
                          dst_port=int(r0['dst_port']) if lab == 'BruteForce' else None,
                          first_seen=to_dt(first), last_seen=to_dt(last), flow_count=len(g),
                          src_count=len(srcs), max_score=score, source=source, rule_detail=detail,
                          status='open')
                db.add(a)
                db.flush()
                self._sources[a.id] = srcs
                new.append(a)
            alert_ids[out.index.get_indexer(g.index)] = a.id
        return new, updated, alert_ids

    def close_stale(self, db: Session, idle: float) -> int:
        cutoff = to_dt(self.now_ref() - idle)
        stale = db.query(Alert).filter(Alert.status.in_(['open', 'ack']), Alert.last_seen < cutoff).all()
        for a in stale:
            a.status, a.closed_at = 'closed', datetime.now(timezone.utc)
            self._sources.pop(a.id, None)
        return len(stale)
