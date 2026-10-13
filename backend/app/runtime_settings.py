"""Cấu hình đổi được lúc chạy, lưu ở bảng `settings` (JSON). Pipeline đọc lại mỗi chu kỳ."""
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Setting
from engine import ids_rules

SECRET_KEYS = {'telegram_bot_token', 'smtp_password'}


def defaults() -> dict:
    return {
        'tau': get_settings().default_tau,
        'ps_min': ids_rules.PORTSCAN_FLOOR,
        'bf_min': ids_rules.BRUTEFORCE_FLOOR,
        'alert_idle_seconds': 120,
        'telegram_enabled': False,
        'telegram_bot_token': '',
        'email_enabled': False,
        'smtp_host': '',
        'smtp_port': 587,
        'smtp_user': '',
        'smtp_password': '',
        'smtp_from': '',
        'smtp_starttls': True,
        'notify_min_severity': 'medium',   # low | medium | high
    }


def load(db: Session) -> dict:
    out = defaults()
    for s in db.query(Setting).all():
        out[s.key] = s.value
    return out


def save(db: Session, values: dict, user: str) -> dict:
    known = defaults()
    for k, v in values.items():
        if k not in known:
            raise KeyError(k)
        row = db.get(Setting, k)
        if row is None:
            db.add(Setting(key=k, value=v, updated_by=user))
        else:
            row.value, row.updated_by = v, user
    db.commit()
    return load(db)


def masked(values: dict) -> dict:
    return {k: ('******' if k in SECRET_KEYS and v else v) for k, v in values.items()}
