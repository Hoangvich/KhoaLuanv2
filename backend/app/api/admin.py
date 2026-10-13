"""Trang Quản trị: cấu hình lúc chạy (CN7), người dùng và phân quyền, thử gửi thông báo."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import runtime_settings
from app.db import get_db
from app.deps import admin_user
from app.models import User
from app.schemas import SettingsUpdate, TestNotificationIn, UserCreate, UserOut, UserUpdate
from app.security import hash_password
from pipeline import notifier

router = APIRouter(prefix='/api', tags=['Quản trị'])


@router.get('/settings')
def get_settings_(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    return runtime_settings.masked(runtime_settings.load(db))


@router.put('/settings')
def put_settings(body: SettingsUpdate, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    data = body.model_dump(exclude_unset=True)
    for k in runtime_settings.SECRET_KEYS:
        if data.get(k) == '******':      # giá trị bị che từ GET: giữ nguyên
            data.pop(k)
    return runtime_settings.masked(runtime_settings.save(db, data, user.username))


@router.post('/settings/test-notification')
def test_notification(body: TestNotificationIn, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    cfg = runtime_settings.load(db)
    to = body.recipient or (user.telegram_chat_id if body.channel == 'telegram' else user.email)
    if not to:
        raise HTTPException(400, 'Chưa có người nhận: nhập chat id / email hoặc cập nhật hồ sơ của bạn')
    if body.channel == 'telegram' and not cfg.get('telegram_bot_token'):
        raise HTTPException(400, 'Chưa cấu hình Telegram bot token')
    if body.channel == 'email' and not cfg.get('smtp_host'):
        raise HTTPException(400, 'Chưa cấu hình máy chủ SMTP')
    try:
        notifier.deliver(cfg, body.channel, to, '[IDS] Thông báo thử',
                         f'Thông báo thử từ hệ thống IDS, gửi bởi {user.username}.')
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f'Gửi thất bại: {e}')
    return {'ok': True, 'recipient': to}


@router.get('/users', response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    return db.query(User).order_by(User.id).all()


@router.post('/users', response_model=UserOut, status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), _: User = Depends(admin_user)):
    if db.query(User).filter_by(username=body.username).first():
        raise HTTPException(409, 'Tên đăng nhập đã tồn tại')
    data = body.model_dump()
    u = User(password_hash=hash_password(data.pop('password')), **data)
    db.add(u)
    db.commit()
    return u


def _other_active_admins(db: Session, user_id: int) -> int:
    return db.query(User).filter(User.role == 'admin', User.is_active.is_(True), User.id != user_id).count()


@router.put('/users/{user_id}', response_model=UserOut)
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db), me: User = Depends(admin_user)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, 'Không tìm thấy người dùng')
    data = body.model_dump(exclude_unset=True)
    demote = data.get('role') == 'viewer' or data.get('is_active') is False
    if u.role == 'admin' and demote and _other_active_admins(db, u.id) == 0:
        raise HTTPException(400, 'Phải còn ít nhất một quản trị viên đang hoạt động')
    if 'password' in data:
        pw = data.pop('password')
        if pw:
            u.password_hash = hash_password(pw)
    for k, v in data.items():
        setattr(u, k, v)
    db.commit()
    return u


@router.delete('/users/{user_id}', status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), me: User = Depends(admin_user)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, 'Không tìm thấy người dùng')
    if u.id == me.id:
        raise HTTPException(400, 'Không thể tự xoá tài khoản của mình')
    if u.role == 'admin' and _other_active_admins(db, u.id) == 0:
        raise HTTPException(400, 'Phải còn ít nhất một quản trị viên đang hoạt động')
    db.delete(u)
    db.commit()
