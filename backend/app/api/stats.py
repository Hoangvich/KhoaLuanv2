"""Số liệu cho trang Tổng quan."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app import runtime_settings
from app.config import get_settings
from app.db import get_db
from app.deps import current_user, get_analyzer
from app.models import Alert, PipelineRun, TrafficMinute

router = APIRouter(prefix='/api/stats', tags=['Thống kê'], dependencies=[Depends(current_user)])
ATTACKS = ('DoS/DDoS', 'PortScan', 'BruteForce')


def _since(minutes: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def pipeline_status(db: Session) -> dict:
    last = db.query(PipelineRun).order_by(PipelineRun.id.desc()).first()
    interval = get_settings().pipeline_interval
    if last is None:
        return {'state': 'never', 'last_run': None}
    age = (datetime.now(timezone.utc) - last.started_at).total_seconds()
    since = datetime.now(timezone.utc) - timedelta(minutes=10)
    runs = db.query(func.count(PipelineRun.id), func.count(PipelineRun.error), func.avg(PipelineRun.ms)) \
        .filter(PipelineRun.started_at >= since).one()
    return {
        'state': 'running' if age <= 3 * interval else 'stopped',
        'last_run': last.started_at, 'last_run_age_s': round(age, 1), 'last_error': last.error,
        'interval_s': interval, 'runs_10min': runs[0], 'errors_10min': runs[1],
        'avg_ms_10min': round(runs[2], 1) if runs[2] is not None else None,
        'expected_runs_10min': int(600 / interval),
    }


@router.get('/overview')
def overview(minutes: int = Query(60, ge=1, le=60 * 24 * 7), db: Session = Depends(get_db)):
    since = _since(minutes)
    by_label = dict(db.query(TrafficMinute.label, func.sum(TrafficMinute.flows))
                    .filter(TrafficMinute.minute >= since).group_by(TrafficMinute.label).all())
    by_label = {k: int(v) for k, v in by_label.items()}
    total = sum(by_label.values())
    attack = sum(v for k, v in by_label.items() if k in ATTACKS)
    alerts_open = dict(db.query(Alert.severity, func.count(Alert.id))
                       .filter(Alert.status.in_(['open', 'ack'])).group_by(Alert.severity).all())
    alerts_window = dict(db.query(Alert.label, func.count(Alert.id))
                         .filter(Alert.last_seen >= since).group_by(Alert.label).all())
    cfg = runtime_settings.load(db)
    info = get_analyzer().info
    return {
        'minutes': minutes,
        'flows_total': total, 'flows_attack': attack,
        'attack_ratio': attack / total if total else 0.0,
        'flows_by_label': by_label,
        'alerts_open': sum(alerts_open.values()), 'alerts_open_by_severity': alerts_open,
        'alerts_by_label': alerts_window,
        'pipeline': pipeline_status(db),
        'model': {'name': info['model_name'], 'feature_set': info['feature_set'], 'tau': cfg['tau']},
    }


@router.get('/timeseries')
def timeseries(minutes: int = Query(60, ge=1, le=60 * 24 * 7), db: Session = Depends(get_db)):
    """Số luồng theo phút × nhãn, và số cảnh báo mới theo phút."""
    since = _since(minutes)
    rows = db.query(TrafficMinute.minute, TrafficMinute.label, TrafficMinute.flows) \
        .filter(TrafficMinute.minute >= since).order_by(TrafficMinute.minute).all()
    alerts = db.execute(text(
        "SELECT date_trunc('minute', first_seen) AS m, label, count(*) FROM alerts "
        "WHERE first_seen >= :s GROUP BY 1, 2 ORDER BY 1"), {'s': since}).all()
    return {
        'flows': [{'minute': m, 'label': lab, 'flows': n} for m, lab, n in rows],
        'alerts': [{'minute': m, 'label': lab, 'alerts': n} for m, lab, n in alerts],
    }


@router.get('/top')
def top(minutes: int = Query(60, ge=1, le=60 * 24 * 7), limit: int = Query(10, ge=1, le=50),
        db: Session = Depends(get_db)):
    """IP nguồn và IP đích có nhiều luồng tấn công nhất."""
    since = _since(minutes)
    q = ("SELECT {col} AS ip, label, count(*) AS flows, max(ts) AS last_seen FROM flows "
         "WHERE ts >= :s AND label IN ('DoS/DDoS', 'PortScan', 'BruteForce') "
         "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT :n")
    src = db.execute(text(q.format(col='src_ip')), {'s': since, 'n': limit}).mappings().all()
    dst = db.execute(text(q.format(col='dst_ip')), {'s': since, 'n': limit}).mappings().all()
    return {'sources': [dict(r) for r in src], 'targets': [dict(r) for r in dst]}
