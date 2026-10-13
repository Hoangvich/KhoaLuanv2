"""Engine phải cho kết quả khớp kịch bản C (Test_Kich_Ban_C/results) khi chạy theo lô 5 s như pipeline."""
import numpy as np
import pandas as pd

from engine.cic_compat import detect_flag_mode, standard_to_cic2017


def replay(analyzer, flows, step=5.0):
    out = []
    for _, g in flows.groupby('Pcap'):
        analyzer.reset_state()
        g = g.sort_values('Timestamp')
        for _, b in g.groupby(g['Timestamp'] // step):
            o = analyzer.analyze(b.drop(columns=['Label', 'Pcap']))
            o['truth'] = b['Label'].to_numpy()
            out.append(o)
    analyzer.reset_state()
    return pd.concat(out, ignore_index=True)


def test_detection_matches_scenario_c(analyzer, lab_flows):
    r = replay(analyzer, lab_flows)
    r = r[r['valid'] | r['label'].notna()]
    hit = r['label'].isin(['DoS/DDoS', 'PortScan', 'BruteForce'])
    rate = hit.groupby(r['truth']).mean()
    assert rate['PortScan'] > 0.99
    assert rate['DoS/DDoS'] > 0.90
    assert rate['BruteForce'] > 0.95          # nhờ tầng luật
    assert rate['BENIGN'] < 0.02              # FPR
    bf = r[(r['truth'] == 'BruteForce') & hit]
    assert (bf['source'] == 'rule').all()


def test_output_schema(analyzer, lab_flows):
    o = analyzer.analyze(lab_flows.head(50).drop(columns=['Label', 'Pcap']))
    assert len(o) == 50
    assert {'ts', 'src_ip', 'label', 'attack_score', 'source', 'valid'} <= set(o.columns)
    analyzer.reset_state()


def test_rules_span_batches(analyzer, lab_flows):
    """Một phiên brute force trải qua nhiều lô: bộ đệm 60 s phải nối được các lô."""
    bf = lab_flows[lab_flows['Pcap'] == 'bruteforce.pcap'].sort_values('Timestamp')
    analyzer.reset_state()
    labels = []
    for _, row in bf.iterrows():                 # mỗi luồng một lô — trường hợp xấu nhất
        labels.append(analyzer.analyze(row.to_frame().T.drop(columns=['Label', 'Pcap']).infer_objects())['label'].iloc[0])
    analyzer.reset_state()
    assert sum(lab == 'BruteForce' for lab in labels) > 400


def test_flag_mode_detection():
    cic = pd.DataFrame({'FIN Flag Count': [0, 1], 'SYN Flag Count': [0, 0], 'RST Flag Count': [0, 0],
                        'PSH Flag Count': [1, 0], 'ACK Flag Count': [0, 1], 'URG Flag Count': [0, 0]})
    std = cic.assign(**{'SYN Flag Count': [1, 1], 'RST Flag Count': [1, 0], 'ACK Flag Count': [1, 9]})
    assert detect_flag_mode(cic) == 'cic2017'
    assert detect_flag_mode(std) == 'standard'


def test_standard_to_cic2017_portscan():
    """Luồng quét SYN đếm theo chuẩn (SYN=1, RST=1, ACK=1) -> quy ước CIC-2017 (chỉ PSH=1)."""
    std = pd.DataFrame({'FIN Flag Count': [0], 'SYN Flag Count': [1], 'RST Flag Count': [1],
                        'PSH Flag Count': [0], 'ACK Flag Count': [1], 'URG Flag Count': [0], 'Fwd PSH Flags': [0]})
    c = standard_to_cic2017(std).iloc[0]
    assert (c['PSH Flag Count'], c['SYN Flag Count'], c['RST Flag Count'], c['ACK Flag Count']) == (1, 0, 0, 0)


def test_timestamp_string_parsing(analyzer, lab_flows):
    d = lab_flows.head(5).drop(columns=['Label', 'Pcap']).copy()
    d['Timestamp'] = ['13/10/2026 02:15:01 PM'] * 5       # định dạng CICFlowMeter-V4, giờ Việt Nam
    o = analyzer.analyze(d)
    analyzer.reset_state()
    assert np.allclose(o['ts'], pd.Timestamp('2026-10-13 07:15:01', tz='UTC').timestamp())
