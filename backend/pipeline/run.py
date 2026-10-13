"""Pipeline batch: mỗi PIPELINE_INTERVAL giây đọc CSV mới của CICFlowMeter, gán nhãn, ghi CSDL, gom cảnh báo,
gửi thông báo.

    python -m pipeline.run            # chạy liên tục
    python -m pipeline.run --once     # chạy một chu kỳ rồi thoát (kiểm thử)
"""
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import runtime_settings
from app.config import get_settings
from app.db import SessionLocal
from app.models import Flow, PipelineRun, TrafficMinute
from engine.analyzer import Analyzer
from pipeline import notifier
from pipeline.aggregator import AlertAggregator
from pipeline.ingest import CsvIngestor

log = logging.getLogger('pipeline')
FLOW_COLS = ['ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'duration_us', 'fwd_pkts', 'bwd_pkts',
             'fwd_bytes', 'bwd_bytes', 'valid', 'label', 'attack_score', 'source', 'rule_detail', 'alert_id',
             'run_id']


def _clean(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, np.generic):
        return v.item()
    return v


def write_flows(db: Session, out: pd.DataFrame):
    """Ghi luồng bằng COPY (nhanh hơn INSERT nhiều lần khi một lượt quét cổng sinh hàng chục nghìn luồng)."""
    d = out.copy()
    d['ts'] = pd.to_datetime(d['ts'], unit='s', utc=True)
    for c in ['fwd_pkts', 'bwd_pkts']:
        d[c] = d[c].astype('Int64')
    raw = db.connection().connection.driver_connection
    with raw.cursor() as cur:
        with cur.copy(f"COPY flows ({', '.join(FLOW_COLS)}) FROM STDIN") as cp:
            for row in d[FLOW_COLS].itertuples(index=False, name=None):
                cp.write_row([None if pd.isna(v) else _clean(v) for v in row])


def upsert_minutes(db: Session, out: pd.DataFrame):
    m = pd.DataFrame({'minute': pd.to_datetime(out['ts'], unit='s', utc=True).dt.floor('min'),
                      'label': out['label'].fillna('INVALID')})
    agg = m.groupby(['minute', 'label']).size().reset_index(name='flows')
    if agg.empty:
        return
    stmt = pg_insert(TrafficMinute).values(agg.to_dict('records'))
    stmt = stmt.on_conflict_do_update(index_elements=['minute', 'label'],
                                      set_={'flows': TrafficMinute.flows + stmt.excluded.flows})
    db.execute(stmt)


class Pipeline:
    def __init__(self):
        s = get_settings()
        self.settings = s
        self.analyzer = Analyzer(s.path(s.model_path), flag_mode=s.flag_mode, tz=s.sensor_timezone)
        self.ingestor = CsvIngestor(s.path(s.incoming_dir))
        self.aggregator = AlertAggregator()
        self._last_cleanup = 0.0
        log.info('Mô hình: %s (%s), thư mục vào: %s', self.analyzer.info['model_name'],
                 self.analyzer.info['file'], self.ingestor.dir)

    def cycle(self):
        t0 = time.perf_counter()
        with SessionLocal() as db:
            cfg = runtime_settings.load(db)
            self.analyzer.update_config(cfg['tau'], cfg['ps_min'], cfg['bf_min'])
            run = PipelineRun(started_at=datetime.now(timezone.utc), tau=cfg['tau'])
            db.add(run)
            db.flush()
            try:
                df, pending = self.ingestor.poll(db)
                if len(df):
                    run.files = ', '.join(sorted(df['__file'].unique()))
                    out = self.analyzer.analyze(df.drop(columns='__file'))
                    new, n_upd, ids = self.aggregator.update(db, out, cfg['alert_idle_seconds'])
                    out['alert_id'], out['run_id'] = ids, run.id
                    write_flows(db, out)
                    upsert_minutes(db, out)
                    notifier.enqueue(db, new, cfg)
                    run.rows_in, run.rows_valid = len(out), int(out['valid'].sum())
                    run.rows_attack = int(out['label'].isin(['DoS/DDoS', 'PortScan', 'BruteForce']).sum())
                    run.alerts_new, run.alerts_updated = len(new), n_upd
                    run.flag_mode = self.analyzer.last_flag_mode
                    for a in new:
                        log.warning('CẢNH BÁO #%s %s %s -> %s:%s (%s luồng, %s)', a.id, a.label, a.src_ip or '*',
                                    a.dst_ip, a.dst_port or '*', a.flow_count, a.source)
                self.aggregator.close_stale(db, cfg['alert_idle_seconds'])
                self.ingestor.commit(db, pending)
            except Exception as e:
                db.rollback()
                log.exception('Chu kỳ lỗi')
                run = PipelineRun(started_at=run.started_at, tau=cfg['tau'], error=str(e)[:2000])
                db.add(run)
            run.finished_at = datetime.now(timezone.utc)
            run.ms = (time.perf_counter() - t0) * 1000
            db.commit()
            if run.rows_in:
                log.info('Chu kỳ #%s: %s luồng, %s tấn công, %s cảnh báo mới, %.0f ms', run.id, run.rows_in,
                         run.rows_attack, run.alerts_new, run.ms)
            notifier.send_pending(db, cfg)
            self.cleanup(db)

    def cleanup(self, db: Session):
        if time.time() - self._last_cleanup < 3600:
            return
        self._last_cleanup = time.time()
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.settings.flow_retention_days)
        db.execute(delete(Flow).where(Flow.ts < cutoff))
        db.execute(delete(PipelineRun).where(PipelineRun.started_at < cutoff - timedelta(days=23)))
        db.commit()

    def forever(self):
        interval = self.settings.pipeline_interval
        log.info('Pipeline chạy mỗi %.0f s. Ctrl+C để dừng.', interval)
        while True:
            t = time.monotonic()
            try:
                self.cycle()
            except Exception:
                log.exception('Lỗi ngoài chu kỳ (mất kết nối CSDL?)')
            time.sleep(max(0.0, interval - (time.monotonic() - t)))


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    p = Pipeline()
    if '--once' in sys.argv:
        p.cycle()
    else:
        try:
            p.forever()
        except KeyboardInterrupt:
            log.info('Đã dừng.')


if __name__ == '__main__':
    main()
