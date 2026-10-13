"""Đọc phần mới của các file CSV mà CICFlowMeter ghi vào thư mục incoming.

CICFlowMeter ghi nối tiếp vào file CSV khi luồng kết thúc. Mỗi chu kỳ ta đọc từ vị trí đã đọc tới dòng hoàn
chỉnh cuối cùng; vị trí lưu ở bảng ingest_offsets và chỉ được cập nhật cùng giao dịch ghi luồng, nên không
mất hay đọc trùng dòng khi pipeline khởi động lại.
"""
import io
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sqlalchemy.orm import Session

from app.models import IngestOffset

MAX_BYTES_PER_CYCLE = 64 * 2**20


@dataclass
class PendingOffset:
    path: str
    offset: int
    header: str


class CsvIngestor:
    def __init__(self, incoming_dir: Path):
        self.dir = Path(incoming_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def poll(self, db: Session) -> tuple[pd.DataFrame, list[PendingOffset]]:
        frames, pending = [], []
        budget = MAX_BYTES_PER_CYCLE
        for f in sorted(self.dir.glob('*.csv'), key=lambda p: p.stat().st_mtime):
            key = str(f.resolve())
            row = db.get(IngestOffset, key)
            offset, header = (row.offset, row.header) if row else (0, None)
            size = f.stat().st_size
            if size < offset:            # file bị ghi đè hoặc cắt ngắn: đọc lại từ đầu
                offset, header = 0, None
            if size == offset or budget <= 0:
                continue
            with open(f, 'rb') as fh:
                fh.seek(offset)
                chunk = fh.read(min(size - offset, budget))
            end = chunk.rfind(b'\n')
            if end < 0:                  # chưa có dòng hoàn chỉnh
                continue
            chunk = chunk[:end + 1]
            text = chunk.decode('utf-8', errors='replace')
            new_offset = offset + len(chunk)
            if header is None:
                header, _, text = text.partition('\n')
                header = header.strip('\r﻿')
            budget -= len(chunk)
            pending.append(PendingOffset(key, new_offset, header))
            if text.strip():
                df = pd.read_csv(io.StringIO(header + '\n' + text), low_memory=False)
                df['__file'] = f.name
                frames.append(df)
        df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        return df, pending

    @staticmethod
    def commit(db: Session, pending: list[PendingOffset]):
        for p in pending:
            row = db.get(IngestOffset, p.path)
            if row is None:
                db.add(IngestOffset(path=p.path, offset=p.offset, header=p.header))
            else:
                row.offset, row.header = p.offset, p.header
