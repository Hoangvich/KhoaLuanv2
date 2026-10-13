"""Cấu hình tĩnh, đọc từ biến môi trường hoặc backend/.env.

Cấu hình thay đổi lúc chạy (ngưỡng τ, ngưỡng luật, kênh thông báo) nằm trong bảng `settings`
của CSDL để trang Quản trị chỉnh được — xem app/runtime_settings.py.
"""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / '.env', env_file_encoding='utf-8', extra='ignore',
                                      protected_namespaces=('settings_',))

    database_url: str = 'postgresql+psycopg://ids_app:ids_app_dev@localhost:5432/ids'
    jwt_secret: str = 'doi-chuoi-nay-khi-trien-khai'
    jwt_expire_minutes: int = 720

    model_path: str = '../Model Train/RF/models/rf_F_NOOS.joblib'
    default_tau: float = 0.48          # τ* hiệu chỉnh ở kịch bản C (FPR ≤ 1%); τ trong gói RF là 0,36
    flag_mode: str = 'auto'            # auto | cic2017 | standard (xem engine/cic_compat.py)
    sensor_timezone: str = 'Asia/Ho_Chi_Minh'

    incoming_dir: str = 'data/incoming'
    pipeline_interval: float = 5.0
    flow_retention_days: int = 7

    admin_username: str = 'admin'
    admin_password: str = 'admin123'
    cors_origins: str = 'http://localhost:5173,http://127.0.0.1:5173'

    def path(self, p: str) -> Path:
        q = Path(p)
        return q if q.is_absolute() else (BACKEND_DIR / q).resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()
