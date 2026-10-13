from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ xác thực, người dùng
class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(ORM):
    id: int
    username: str
    role: str
    full_name: str | None = None
    email: str | None = None
    telegram_chat_id: str | None = None
    notify: bool
    is_active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    user: UserOut


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r'^[A-Za-z0-9_.-]+$')
    password: str = Field(min_length=6, max_length=100)
    role: Literal['admin', 'viewer'] = 'viewer'
    full_name: str | None = None
    email: str | None = None
    telegram_chat_id: str | None = None
    notify: bool = False


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=6, max_length=100)
    role: Literal['admin', 'viewer'] | None = None
    full_name: str | None = None
    email: str | None = None
    telegram_chat_id: str | None = None
    notify: bool | None = None
    is_active: bool | None = None


class ProfileUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    telegram_chat_id: str | None = None
    notify: bool | None = None
    current_password: str | None = None
    new_password: str | None = Field(default=None, min_length=6, max_length=100)


# ------------------------------------------------------------------ cảnh báo, luồng
class AlertOut(ORM):
    id: int
    label: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    first_seen: datetime
    last_seen: datetime
    flow_count: int
    src_count: int
    max_score: float | None
    source: str
    rule_detail: str | None
    status: str
    note: str | None
    ack_by: str | None
    ack_at: datetime | None
    closed_at: datetime | None
    created_at: datetime


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    size: int


class AlertAction(BaseModel):
    note: str | None = None


class FlowOut(ORM):
    id: int
    ts: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    duration_us: float | None
    fwd_pkts: int | None
    bwd_pkts: int | None
    fwd_bytes: float | None
    bwd_bytes: float | None
    valid: bool
    label: str | None
    attack_score: float | None
    source: str | None
    rule_detail: str | None
    alert_id: int | None


class NotificationOut(ORM):
    id: int
    channel: str
    recipient: str
    status: str
    error: str | None
    created_at: datetime
    sent_at: datetime | None
    latency_ms: float | None


class AlertDetail(BaseModel):
    alert: AlertOut
    flows: list[FlowOut]
    notifications: list[NotificationOut]
    top_sources: list[dict]


class PipelineRunOut(ORM):
    id: int
    started_at: datetime
    finished_at: datetime | None
    files: str | None
    rows_in: int
    rows_valid: int
    rows_attack: int
    alerts_new: int
    alerts_updated: int
    flag_mode: str | None
    tau: float | None
    ms: float | None
    error: str | None


class SettingsUpdate(BaseModel):
    tau: float | None = Field(default=None, gt=0, lt=1)
    ps_min: int | None = Field(default=None, ge=2, le=100000)
    bf_min: int | None = Field(default=None, ge=2, le=10000)
    alert_idle_seconds: int | None = Field(default=None, ge=10, le=3600)
    telegram_enabled: bool | None = None
    telegram_bot_token: str | None = None
    email_enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_starttls: bool | None = None
    notify_min_severity: Literal['low', 'medium', 'high'] | None = None


class TestNotificationIn(BaseModel):
    channel: Literal['telegram', 'email']
    recipient: str | None = None   # để trống: gửi tới chat id / email của chính người đang đăng nhập
