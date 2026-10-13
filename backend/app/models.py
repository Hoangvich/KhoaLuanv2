"""Lược đồ CSDL (PostgreSQL). Tạo bảng bằng `python -m app.seed`."""
from datetime import datetime

from sqlalchemy import (BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, SmallInteger, String,
                        Text, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(10), default='viewer')          # admin | viewer
    full_name: Mapped[str | None] = mapped_column(String(100))
    email: Mapped[str | None] = mapped_column(String(120))
    telegram_chat_id: Mapped[str | None] = mapped_column(String(40))
    notify: Mapped[bool] = mapped_column(Boolean, default=False)              # nhận thông báo cảnh báo
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Setting(Base):
    """Cấu hình đổi được lúc chạy; pipeline đọc lại mỗi chu kỳ (CN7)."""
    __tablename__ = 'settings'
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[object] = mapped_column(JSONB)
    updated_by: Mapped[str | None] = mapped_column(String(50))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())


class PipelineRun(Base):
    """Một chu kỳ pipeline — bằng chứng cho CN1 (không mất chu kỳ)."""
    __tablename__ = 'pipeline_runs'
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    files: Mapped[str | None] = mapped_column(Text)
    rows_in: Mapped[int] = mapped_column(Integer, default=0)
    rows_valid: Mapped[int] = mapped_column(Integer, default=0)
    rows_attack: Mapped[int] = mapped_column(Integer, default=0)
    alerts_new: Mapped[int] = mapped_column(Integer, default=0)
    alerts_updated: Mapped[int] = mapped_column(Integer, default=0)
    flag_mode: Mapped[str | None] = mapped_column(String(10))
    tau: Mapped[float | None] = mapped_column(Float)
    ms: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)


class Alert(Base):
    """Một lượt tấn công = một cảnh báo (gom theo khoá nguồn – đích, CN4)."""
    __tablename__ = 'alerts'
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    group_key: Mapped[str] = mapped_column(String(200), index=True)
    label: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[str] = mapped_column(String(10))                        # high | medium | low
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))   # theo thời gian luồng
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    src_count: Mapped[int] = mapped_column(Integer, default=1)              # số IP nguồn (DDoS)
    max_score: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(12))                         # model | rule | model+rule
    rule_detail: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), default='open', index=True)  # open | ack | closed
    note: Mapped[str | None] = mapped_column(Text)
    ack_by: Mapped[str | None] = mapped_column(String(50))
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())


class Flow(Base):
    __tablename__ = 'flows'
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(SmallInteger)
    duration_us: Mapped[float | None] = mapped_column(Float)
    fwd_pkts: Mapped[int | None] = mapped_column(Integer)
    bwd_pkts: Mapped[int | None] = mapped_column(Integer)
    fwd_bytes: Mapped[float | None] = mapped_column(Float)
    bwd_bytes: Mapped[float | None] = mapped_column(Float)
    valid: Mapped[bool] = mapped_column(Boolean)
    label: Mapped[str | None] = mapped_column(String(20))                   # NULL: luồng không hợp lệ
    attack_score: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str | None] = mapped_column(String(10))                  # model | rule
    rule_detail: Mapped[str | None] = mapped_column(Text)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey('alerts.id', ondelete='SET NULL'))
    run_id: Mapped[int | None] = mapped_column(ForeignKey('pipeline_runs.id', ondelete='SET NULL'))

    __table_args__ = (
        Index('ix_flows_ts', 'ts'),
        Index('ix_flows_label_ts', 'label', 'ts'),
        Index('ix_flows_alert', 'alert_id'),
        Index('ix_flows_src_ts', 'src_ip', 'ts'),
    )


class TrafficMinute(Base):
    """Số luồng theo phút × nhãn — để trang Tổng quan không phải quét bảng flows."""
    __tablename__ = 'traffic_minute'
    minute: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    label: Mapped[str] = mapped_column(String(20), primary_key=True)        # BENIGN, ..., INVALID
    flows: Mapped[int] = mapped_column(Integer, default=0)


class Notification(Base):
    __tablename__ = 'notifications'
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey('alerts.id', ondelete='CASCADE'), index=True)
    channel: Mapped[str] = mapped_column(String(10))                        # telegram | email
    recipient: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(10), default='pending', index=True)  # pending|sent|failed
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latency_ms: Mapped[float | None] = mapped_column(Float)                 # từ lúc tạo cảnh báo (CN6)


class IngestOffset(Base):
    """Vị trí đã đọc trong mỗi file CSV của CICFlowMeter."""
    __tablename__ = 'ingest_offsets'
    path: Mapped[str] = mapped_column(String(500), primary_key=True)
    offset: Mapped[int] = mapped_column(BigInteger, default=0)
    header: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())
