"""Pipeline + API trên database kiểm thử: CSV -> cảnh báo -> API."""
import time

import pandas as pd
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def pipeline(db_reset, tmp_path, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), 'incoming_dir', str(tmp_path))
    from pipeline.run import Pipeline
    return Pipeline()


@pytest.fixture()
def client(db_reset):
    from app.main import app
    with TestClient(app) as c:
        tok = c.post('/api/auth/login', json={'username': 'admin', 'password': 'admin123'}).json()['access_token']
        c.headers['Authorization'] = f'Bearer {tok}'
        yield c


def write_csv(path, flows: pd.DataFrame):
    """Ghi CSV như sensor, dời thời gian luồng về hiện tại (pcap gốc là năm 2021)."""
    d = flows.drop(columns=['Label', 'Pcap']).copy()
    d['Timestamp'] = d['Timestamp'] - d['Timestamp'].min() + time.time() - 60
    d.to_csv(path, index=False)


def test_pipeline_creates_one_alert_per_attack(pipeline, lab_flows, tmp_path):
    from app.db import SessionLocal
    from app.models import Alert, Flow, IngestOffset, PipelineRun
    attacks = lab_flows[lab_flows['Pcap'].isin(['portscan.pcap', 'bruteforce.pcap'])]
    write_csv(tmp_path / 'a.csv', attacks)
    pipeline.cycle()
    pipeline.cycle()                                   # chu kỳ 2 không được đọc lại dòng cũ
    with SessionLocal() as db:
        assert db.query(Flow).count() == len(attacks)
        alerts = {(a.label, a.src_ip, a.dst_ip) for a in db.query(Alert).all()}
        assert ('PortScan', '192.168.1.149', '192.168.1.4') in alerts
        assert ('BruteForce', '192.168.1.149', '192.168.1.4') in alerts
        assert db.query(Alert).filter_by(label='PortScan').count() <= 3      # CN4
        assert db.query(PipelineRun).count() == 2
        assert db.query(IngestOffset).count() == 1


def test_incremental_append(pipeline, lab_flows, tmp_path):
    from app.db import SessionLocal
    from app.models import Flow
    d = lab_flows[lab_flows['Pcap'] == 'benign.pcap'].drop(columns=['Label', 'Pcap']).copy()
    d['Timestamp'] = d['Timestamp'] - d['Timestamp'].min() + time.time() - 60   # tránh bị dọn (giữ 7 ngày)
    f = tmp_path / 'live.csv'
    d.iloc[:100].to_csv(f, index=False)
    pipeline.cycle()
    with open(f, 'a', encoding='utf-8', newline='') as fh:     # CICFlowMeter ghi nối tiếp
        d.iloc[100:250].to_csv(fh, index=False, header=False)
        fh.write('dòng chưa ghi xong,1,2')                    # dòng dở dang: phải chờ chu kỳ sau
    pipeline.cycle()
    with SessionLocal() as db:
        assert db.query(Flow).count() == 250


def test_api_flow(client, pipeline, lab_flows, tmp_path):
    write_csv(tmp_path / 'b.csv', lab_flows[lab_flows['Pcap'] == 'bruteforce.pcap'])
    pipeline.cycle()
    ov = client.get('/api/stats/overview', params={'minutes': 60}).json()
    assert ov['flows_total'] > 0
    page = client.get('/api/alerts', params={'label': 'BruteForce'}).json()
    assert page['total'] >= 1
    aid = page['items'][0]['id']
    detail = client.get(f'/api/alerts/{aid}').json()
    assert detail['alert']['source'] == 'rule' and len(detail['flows']) > 0
    assert client.post(f'/api/alerts/{aid}/ack', json={'note': 'ok'}).json()['status'] == 'ack'


def test_auth_and_roles(client):
    assert client.get('/api/settings').status_code == 200
    assert client.post('/api/users', json={'username': 'v1', 'password': 'secret1'}).status_code == 422  # tên quá ngắn
    assert client.post('/api/users', json={'username': 'viewer1', 'password': 'secret1'}).status_code == 201
    from app.main import app
    with TestClient(app) as anon:
        assert anon.get('/api/stats/overview').status_code == 401
        tok = anon.post('/api/auth/login', json={'username': 'viewer1', 'password': 'secret1'}).json()['access_token']
        anon.headers['Authorization'] = f'Bearer {tok}'
        assert anon.get('/api/stats/overview').status_code == 200
        assert anon.get('/api/settings').status_code == 403
    assert client.delete('/api/users/1').status_code == 400       # không tự xoá / xoá admin cuối


def test_settings_validation(client):
    assert client.put('/api/settings', json={'tau': 0.6}).json()['tau'] == 0.6
    assert client.put('/api/settings', json={'tau': 2}).status_code == 422
    r = client.put('/api/settings', json={'telegram_bot_token': 'abc'}).json()
    assert r['telegram_bot_token'] == '******'
