"""FastAPI — API cho dashboard.

    uvicorn app.main:app --reload --port 8000
Tài liệu OpenAPI: http://localhost:8000/docs
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin, alerts, auth, stats, system
from app.config import get_settings
from app.deps import get_analyzer


@asynccontextmanager
async def lifespan(_app):
    get_analyzer()   # nạp mô hình một lần khi khởi động
    yield


app = FastAPI(lifespan=lifespan, title='IDS — Hệ thống phát hiện bất thường mạng', version='0.1.0',
              description='API cho dashboard: thống kê, cảnh báo, cấu hình và người dùng.')

app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in get_settings().cors_origins.split(',')],
                   allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

for r in (auth, stats, alerts, admin, system):
    app.include_router(r.router)
