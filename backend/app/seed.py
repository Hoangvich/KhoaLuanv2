"""Tạo bảng, cấu hình mặc định và tài khoản admin đầu tiên.

    python -m app.seed            # tạo nếu chưa có
    python -m app.seed --reset    # XOÁ toàn bộ bảng rồi tạo lại (chỉ dùng khi phát triển)
"""
import sys

from app import models  # noqa: F401  (đăng ký bảng)
from app import runtime_settings
from app.config import get_settings
from app.db import Base, SessionLocal, engine
from app.models import Setting, User
from app.security import hash_password


def main(reset: bool = False):
    if reset:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    s = get_settings()
    with SessionLocal() as db:
        for k, v in runtime_settings.defaults().items():
            if db.get(Setting, k) is None:
                db.add(Setting(key=k, value=v, updated_by='seed'))
        if db.query(User).filter_by(username=s.admin_username).first() is None:
            db.add(User(username=s.admin_username, password_hash=hash_password(s.admin_password),
                        role='admin', full_name='Quản trị viên'))
            print(f"Đã tạo tài khoản admin '{s.admin_username}'.")
        db.commit()
    print('Đã tạo bảng:', ', '.join(sorted(Base.metadata.tables)))


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    main(reset='--reset' in sys.argv)
