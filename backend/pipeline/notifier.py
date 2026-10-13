"""Gửi thông báo cảnh báo qua Telegram và email (CN6).

Người nhận: tài khoản đang hoạt động có bật `notify`; Telegram cần telegram_chat_id, email cần email.
Mỗi lần gửi ghi một dòng `notifications` kèm latency_ms tính từ lúc cảnh báo được tạo.
"""
import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

import httpx
from sqlalchemy.orm import Session

from app.models import Alert, Notification, User

log = logging.getLogger(__name__)
SEV_RANK = {'low': 0, 'medium': 1, 'high': 2}
LABEL_VI = {'DoS/DDoS': 'Tấn công từ chối dịch vụ (DoS/DDoS)', 'PortScan': 'Quét cổng (PortScan)',
            'BruteForce': 'Dò mật khẩu (BruteForce)'}


def format_message(a: Alert) -> tuple[str, str]:
    subject = f"[IDS] {LABEL_VI.get(a.label, a.label)} — mức {a.severity}"
    src = a.src_ip or f'{a.src_count} nguồn'
    dst = f'{a.dst_ip}:{a.dst_port}' if a.dst_port else a.dst_ip
    lines = [
        subject,
        f'Nguồn: {src}  →  Đích: {dst}',
        f"Bắt đầu: {a.first_seen.astimezone().strftime('%H:%M:%S %d/%m/%Y')}",
        f'Số luồng: {a.flow_count}',
        f'Phát hiện bởi: {"luật theo nguồn" if a.source == "rule" else "mô hình" if a.source == "model" else a.source}',
    ]
    if a.max_score is not None:
        lines.append(f'Điểm tấn công cao nhất: {a.max_score:.2f}')
    if a.rule_detail:
        lines.append(f'Chi tiết luật: {a.rule_detail}')
    lines.append(f'Mã cảnh báo: #{a.id}')
    return subject, '\n'.join(lines)


def send_telegram(token: str, chat_id: str, text: str):
    r = httpx.post(f'https://api.telegram.org/bot{token}/sendMessage',
                   json={'chat_id': chat_id, 'text': text}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f'Telegram {r.status_code}: {r.text[:200]}')


def send_email(cfg: dict, to: str, subject: str, body: str):
    msg = EmailMessage()
    msg['Subject'], msg['From'], msg['To'] = subject, cfg['smtp_from'] or cfg['smtp_user'], to
    msg.set_content(body)
    with smtplib.SMTP(cfg['smtp_host'], int(cfg['smtp_port']), timeout=10) as s:
        if cfg.get('smtp_starttls', True):
            s.starttls()
        if cfg.get('smtp_user'):
            s.login(cfg['smtp_user'], cfg['smtp_password'])
        s.send_message(msg)


def recipients(db: Session, cfg: dict) -> list[tuple[str, str]]:
    out = []
    users = db.query(User).filter(User.is_active.is_(True), User.notify.is_(True)).all()
    for u in users:
        if cfg.get('telegram_enabled') and cfg.get('telegram_bot_token') and u.telegram_chat_id:
            out.append(('telegram', u.telegram_chat_id))
        if cfg.get('email_enabled') and cfg.get('smtp_host') and u.email:
            out.append(('email', u.email))
    return out


def enqueue(db: Session, alerts: list[Alert], cfg: dict) -> int:
    min_rank = SEV_RANK.get(cfg.get('notify_min_severity', 'medium'), 1)
    targets = recipients(db, cfg)
    n = 0
    for a in alerts:
        if SEV_RANK.get(a.severity, 0) < min_rank:
            continue
        for channel, to in targets:
            db.add(Notification(alert_id=a.id, channel=channel, recipient=to, status='pending'))
            n += 1
    return n


def deliver(cfg: dict, channel: str, to: str, subject: str, body: str):
    if channel == 'telegram':
        send_telegram(cfg['telegram_bot_token'], to, body)
    elif channel == 'email':
        send_email(cfg, to, subject, body)
    else:
        raise ValueError(channel)


def send_pending(db: Session, cfg: dict, limit: int = 50) -> int:
    rows = (db.query(Notification).filter(Notification.status == 'pending')
            .order_by(Notification.id).limit(limit).all())
    for n in rows:
        a = db.get(Alert, n.alert_id)
        try:
            subject, body = format_message(a)
            deliver(cfg, n.channel, n.recipient, subject, body)
            n.status = 'sent'
        except Exception as e:  # noqa: BLE001 — ghi lỗi, không làm dừng pipeline
            n.status, n.error = 'failed', str(e)[:500]
            log.warning('Gửi %s tới %s lỗi: %s', n.channel, n.recipient, e)
        n.sent_at = datetime.now(timezone.utc)
        n.latency_ms = (n.sent_at - a.created_at).total_seconds() * 1000 if a and a.created_at else None
    db.commit()
    return len(rows)
