from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import current_user
from app.models import Alert, Flow, Notification, User
from app.schemas import AlertAction, AlertDetail, AlertOut, AlertPage, FlowOut, NotificationOut

router = APIRouter(prefix='/api', tags=['Cảnh báo'])


@router.get('/alerts', response_model=AlertPage, dependencies=[Depends(current_user)])
def list_alerts(status: str | None = Query(None, description='open | ack | closed | active (= open + ack)'),
                label: str | None = None, severity: str | None = None,
                q: str | None = Query(None, description='Tìm theo IP'),
                since: datetime | None = None, until: datetime | None = None,
                page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
                db: Session = Depends(get_db)):
    query = db.query(Alert)
    if status == 'active':
        query = query.filter(Alert.status.in_(['open', 'ack']))
    elif status:
        query = query.filter(Alert.status == status)
    if label:
        query = query.filter(Alert.label == label)
    if severity:
        query = query.filter(Alert.severity == severity)
    if q:
        like = f'%{q.strip()}%'
        query = query.filter(or_(Alert.src_ip.ilike(like), Alert.dst_ip.ilike(like)))
    if since:
        query = query.filter(Alert.last_seen >= since)
    if until:
        query = query.filter(Alert.first_seen <= until)
    total = query.count()
    items = query.order_by(Alert.last_seen.desc()).offset((page - 1) * size).limit(size).all()
    return AlertPage(items=items, total=total, page=page, size=size)


@router.get('/alerts/{alert_id}', response_model=AlertDetail, dependencies=[Depends(current_user)])
def get_alert(alert_id: int, flows_limit: int = Query(200, ge=1, le=2000), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, 'Không tìm thấy cảnh báo')
    flows = db.query(Flow).filter(Flow.alert_id == alert_id).order_by(Flow.ts.desc()).limit(flows_limit).all()
    notes = db.query(Notification).filter(Notification.alert_id == alert_id).order_by(Notification.id).all()
    top = db.execute(text('SELECT src_ip AS ip, count(*) AS flows FROM flows WHERE alert_id = :a '
                          'GROUP BY 1 ORDER BY 2 DESC LIMIT 10'), {'a': alert_id}).mappings().all()
    return AlertDetail(alert=AlertOut.model_validate(a), flows=[FlowOut.model_validate(f) for f in flows],
                       notifications=[NotificationOut.model_validate(n) for n in notes],
                       top_sources=[dict(r) for r in top])


def _act(alert_id: int, db: Session, user: User, body: AlertAction, status: str) -> Alert:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, 'Không tìm thấy cảnh báo')
    now = datetime.now(timezone.utc)
    if status == 'ack':
        if a.status == 'closed':
            raise HTTPException(400, 'Cảnh báo đã đóng')
        a.ack_by, a.ack_at = user.username, now
    elif status == 'closed':
        a.closed_at = now
        a.ack_by = a.ack_by or user.username
    a.status = status
    if body.note:
        a.note = body.note
    db.commit()
    return a


@router.post('/alerts/{alert_id}/ack', response_model=AlertOut)
def ack_alert(alert_id: int, body: AlertAction = AlertAction(), user: User = Depends(current_user),
              db: Session = Depends(get_db)):
    return _act(alert_id, db, user, body, 'ack')


@router.post('/alerts/{alert_id}/close', response_model=AlertOut)
def close_alert(alert_id: int, body: AlertAction = AlertAction(), user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    return _act(alert_id, db, user, body, 'closed')


@router.get('/flows', response_model=list[FlowOut], dependencies=[Depends(current_user)])
def list_flows(label: str | None = None, ip: str | None = None, alert_id: int | None = None,
               attacks_only: bool = False, limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    query = db.query(Flow)
    if label:
        query = query.filter(Flow.label == label)
    if attacks_only:
        query = query.filter(Flow.label.in_(['DoS/DDoS', 'PortScan', 'BruteForce']))
    if ip:
        query = query.filter(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if alert_id:
        query = query.filter(Flow.alert_id == alert_id)
    return query.order_by(Flow.id.desc()).limit(limit).all()
