import os
import sys
from pathlib import Path

# Dùng database kiểm thử riêng; phải đặt trước khi import app
os.environ['DATABASE_URL'] = os.environ.get('TEST_DATABASE_URL',
                                            'postgresql+psycopg://ids_app:ids_app_dev@localhost:5432/ids_test')
os.environ['ADMIN_PASSWORD'] = 'admin123'
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pandas as pd  # noqa: E402
import pytest  # noqa: E402

LAB_CSV = BACKEND.parent / 'Test_Kich_Ban_C' / 'data' / 'lab_flows_cic.csv'


@pytest.fixture(scope='session')
def lab_flows() -> pd.DataFrame:
    if not LAB_CSV.exists():
        pytest.skip('Chưa có Test_Kich_Ban_C/data/lab_flows_cic.csv (chạy test_lab_3_models.py trước)')
    return pd.read_csv(LAB_CSV)


@pytest.fixture(scope='session')
def analyzer():
    from app.config import get_settings
    from engine.analyzer import Analyzer
    s = get_settings()
    a = Analyzer(s.path(s.model_path))
    a.update_config(tau=0.48)
    return a


@pytest.fixture()
def db_reset():
    from app import seed
    seed.main(reset=True)
    yield
