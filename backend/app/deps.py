from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security import decode_token
from engine.analyzer import Analyzer

bearer = HTTPBearer(auto_error=False)


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Chưa đăng nhập')
    try:
        payload = decode_token(cred.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn')
    user = db.get(User, int(payload['sub']))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'Tài khoản không tồn tại hoặc đã bị khoá')
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != 'admin':
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'Chỉ quản trị viên được thực hiện thao tác này')
    return user


@lru_cache
def get_analyzer() -> Analyzer:
    """Bản Analyzer riêng của API (thông tin mô hình, /api/analyze). Pipeline có bản của nó."""
    s = get_settings()
    return Analyzer(s.path(s.model_path), flag_mode=s.flag_mode, tz=s.sensor_timezone)
