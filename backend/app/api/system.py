import io

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import runtime_settings
from app.db import get_db
from app.deps import admin_user, current_user, get_analyzer
from app.models import PipelineRun
from app.schemas import PipelineRunOut
from app.api.stats import pipeline_status

router = APIRouter(prefix='/api', tags=['Hệ thống'])


@router.get('/health')
def health(db: Session = Depends(get_db)):
    db.execute(text('SELECT 1'))
    return {'status': 'ok', 'db': 'ok', 'model': get_analyzer().info['model_name']}


@router.get('/model', dependencies=[Depends(current_user)])
def model_info(db: Session = Depends(get_db)):
    info = dict(get_analyzer().info)
    info['tau'] = runtime_settings.load(db)['tau']
    return info


@router.get('/pipeline/status', dependencies=[Depends(current_user)])
def status(db: Session = Depends(get_db)):
    return pipeline_status(db)


@router.get('/pipeline/runs', response_model=list[PipelineRunOut], dependencies=[Depends(current_user)])
def runs(limit: int = Query(50, ge=1, le=500), only_data: bool = False, db: Session = Depends(get_db)):
    q = db.query(PipelineRun)
    if only_data:
        q = q.filter((PipelineRun.rows_in > 0) | PipelineRun.error.isnot(None))
    return q.order_by(PipelineRun.id.desc()).limit(limit).all()


@router.post('/analyze', dependencies=[Depends(admin_user)])
def analyze(file: UploadFile = File(..., description='CSV đầu ra của CICFlowMeter'),
            preview: int = Query(200, ge=0, le=5000), db: Session = Depends(get_db)):
    """Gán nhãn một file CSV luồng mà không ghi vào CSDL (dùng để kiểm thử mô hình)."""
    try:
        df = pd.read_csv(io.BytesIO(file.file.read()), low_memory=False)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f'Không đọc được CSV: {e}')
    a = get_analyzer()
    cfg = runtime_settings.load(db)
    a.update_config(cfg['tau'], cfg['ps_min'], cfg['bf_min'])
    a.reset_state()
    try:
        out = a.analyze(df.sort_values('Timestamp') if 'Timestamp' in df.columns else df)
    except KeyError as e:
        raise HTTPException(400, str(e))
    finally:
        a.reset_state()
    counts = out['label'].fillna('INVALID').value_counts().to_dict()
    sample = out.head(preview).astype(object).where(out.head(preview).notna(), None).to_dict('records')
    return {'rows': len(out), 'flag_mode': a.last_flag_mode, 'tau': cfg['tau'], 'counts': counts, 'preview': sample}
