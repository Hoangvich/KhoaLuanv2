"""pcap_flow_extractor.py
Trích xuất đặc trưng luồng mạng từ file PCAP theo chuẩn CICFlowMeter / CIC-IDS.
Lưu độc lập trong Test_Kich_Ban_C để không ảnh hưởng cấu trúc project.
"""
import sys
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP

class Flow:
    def __init__(self, fwd_src, fwd_dst, fwd_sport, fwd_dport, proto):
        self.fwd_src = fwd_src
        self.fwd_dst = fwd_dst
        self.fwd_sport = fwd_sport
        self.fwd_dport = fwd_dport
        self.proto = proto
        
        self.fwd_packets = [] # (timestamp, length, tcp_flags, header_len, payload_len, win_size)
        self.bwd_packets = []
        self.start_time = None
        self.last_time = None

    def add_packet(self, is_fwd, ts, pkt_len, flags, header_len, payload_len, win_size):
        if self.start_time is None:
            self.start_time = ts
        self.last_time = ts
        item = (ts, pkt_len, flags, header_len, payload_len, win_size)
        if is_fwd:
            self.fwd_packets.append(item)
        else:
            self.bwd_packets.append(item)

def calculate_flow_stats(flow, flow_timeout=120.0):
    all_packets = [(p[0], p[1], p[2], p[3], p[4], p[5], True) for p in flow.fwd_packets] + \
                  [(p[0], p[1], p[2], p[3], p[4], p[5], False) for p in flow.bwd_packets]
    all_packets.sort(key=lambda x: x[0])
    
    if len(all_packets) == 0:
        return None
        
    duration_sec = all_packets[-1][0] - all_packets[0][0]
    duration_us = max(1.0, duration_sec * 1_000_000.0)
    
    fwd_lens = [p[1] for p in flow.fwd_packets]
    bwd_lens = [p[1] for p in flow.bwd_packets]
    all_lens = [p[1] for p in all_packets]
    
    tot_fwd_pkts = len(flow.fwd_packets)
    tot_bwd_pkts = len(flow.bwd_packets)
    tot_fwd_bytes = sum(fwd_lens)
    tot_bwd_bytes = sum(bwd_lens)
    tot_bytes = tot_fwd_bytes + tot_bwd_bytes
    tot_pkts = len(all_packets)
    
    flow_bytes_s = (tot_bytes / duration_sec) if duration_sec > 0 else 0.0
    flow_pkts_s = (tot_pkts / duration_sec) if duration_sec > 0 else 0.0
    fwd_pkts_s = (tot_fwd_pkts / duration_sec) if duration_sec > 0 else 0.0
    bwd_pkts_s = (tot_bwd_pkts / duration_sec) if duration_sec > 0 else 0.0
    
    def iats(pkts):
        if len(pkts) < 2:
            return [0.0]
        ts_list = [p[0] for p in pkts]
        diffs = [max(0.0, (ts_list[i] - ts_list[i-1]) * 1_000_000.0) for i in range(1, len(ts_list))]
        return diffs if diffs else [0.0]
        
    flow_iat = iats(all_packets)
    fwd_iat = iats(flow.fwd_packets)
    bwd_iat = iats(flow.bwd_packets)
    
    # Flags count
    fin_cnt = sum(1 for p in all_packets if p[2] & 0x01)
    syn_cnt = sum(1 for p in all_packets if p[2] & 0x02)
    rst_cnt = sum(1 for p in all_packets if p[2] & 0x04)
    psh_cnt = sum(1 for p in all_packets if p[2] & 0x08)
    ack_cnt = sum(1 for p in all_packets if p[2] & 0x10)
    urg_cnt = sum(1 for p in all_packets if p[2] & 0x20)
    
    fwd_hdr_len = sum(p[3] for p in flow.fwd_packets)
    bwd_hdr_len = sum(p[3] for p in flow.bwd_packets)
    
    down_up_ratio = (tot_bwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0.0
    avg_pkt_size = np.mean(all_lens) if all_lens else 0.0
    
    act_data_pkt_fwd = sum(1 for p in flow.fwd_packets if p[4] > 0)
    
    init_win_fwd = flow.fwd_packets[0][5] if flow.fwd_packets else 0
    init_win_bwd = flow.bwd_packets[0][5] if flow.bwd_packets else 0
    
    min_seg_size_fwd = min([p[3] for p in flow.fwd_packets]) if flow.fwd_packets else 20
    
    # Active / Idle
    idle_thresh = 5_000_000.0 # 5s in us
    idles = [x for x in flow_iat if x > idle_thresh]
    if not idles:
        idle_mean, idle_std, idle_max, idle_min = 0.0, 0.0, 0.0, 0.0
        active_mean, active_std, active_max, active_min = 0.0, 0.0, 0.0, 0.0
    else:
        idle_mean, idle_std, idle_max, idle_min = np.mean(idles), np.std(idles), np.max(idles), np.min(idles)
        actives = [x for x in flow_iat if x <= idle_thresh and x > 0]
        if actives:
            active_mean, active_std, active_max, active_min = np.mean(actives), np.std(actives), np.max(actives), np.min(actives)
        else:
            active_mean, active_std, active_max, active_min = 0.0, 0.0, 0.0, 0.0

    dport = flow.fwd_dport
    dst_port_class = 0.0 if dport < 1024 else (1.0 if dport < 49152 else 2.0)

    res = {
        'Destination Port': dport,
        'dst_port_class': dst_port_class,
        'Flow Duration': duration_us,
        'Total Fwd Packets': tot_fwd_pkts,
        'Total Backward Packets': tot_bwd_pkts,
        'Total Length of Fwd Packets': tot_fwd_bytes,
        'Total Length of Bwd Packets': tot_bwd_bytes,
        'Fwd Packet Length Max': max(fwd_lens) if fwd_lens else 0.0,
        'Fwd Packet Length Min': min(fwd_lens) if fwd_lens else 0.0,
        'Fwd Packet Length Mean': np.mean(fwd_lens) if fwd_lens else 0.0,
        'Fwd Packet Length Std': np.std(fwd_lens) if fwd_lens else 0.0,
        'Bwd Packet Length Max': max(bwd_lens) if bwd_lens else 0.0,
        'Bwd Packet Length Min': min(bwd_lens) if bwd_lens else 0.0,
        'Bwd Packet Length Mean': np.mean(bwd_lens) if bwd_lens else 0.0,
        'Bwd Packet Length Std': np.std(bwd_lens) if bwd_lens else 0.0,
        'Flow Bytes/s': flow_bytes_s,
        'Flow Packets/s': flow_pkts_s,
        'Flow IAT Mean': np.mean(flow_iat),
        'Flow IAT Std': np.std(flow_iat),
        'Flow IAT Max': np.max(flow_iat),
        'Flow IAT Min': np.min(flow_iat),
        'Fwd IAT Total': sum(fwd_iat),
        'Fwd IAT Mean': np.mean(fwd_iat),
        'Fwd IAT Std': np.std(fwd_iat),
        'Fwd IAT Max': np.max(fwd_iat),
        'Fwd IAT Min': np.min(fwd_iat),
        'Bwd IAT Total': sum(bwd_iat),
        'Bwd IAT Mean': np.mean(bwd_iat),
        'Bwd IAT Std': np.std(bwd_iat),
        'Bwd IAT Max': np.max(bwd_iat),
        'Bwd IAT Min': np.min(bwd_iat),
        'Fwd Header Length': fwd_hdr_len,
        'Bwd Header Length': bwd_hdr_len,
        'Fwd Packets/s': fwd_pkts_s,
        'Bwd Packets/s': bwd_pkts_s,
        'Min Packet Length': min(all_lens) if all_lens else 0.0,
        'Max Packet Length': max(all_lens) if all_lens else 0.0,
        'Packet Length Mean': np.mean(all_lens) if all_lens else 0.0,
        'Packet Length Std': np.std(all_lens) if all_lens else 0.0,
        'Packet Length Variance': np.var(all_lens) if all_lens else 0.0,
        'FIN Flag Count': fin_cnt,
        'SYN Flag Count': syn_cnt,
        'RST Flag Count': rst_cnt,
        'PSH Flag Count': psh_cnt,
        'ACK Flag Count': ack_cnt,
        'URG Flag Count': urg_cnt,
        'Down/Up Ratio': down_up_ratio,
        'Average Packet Size': avg_pkt_size,
        'Init_Win_bytes_forward': init_win_fwd,
        'Init_Win_bytes_backward': init_win_bwd,
        'act_data_pkt_fwd': act_data_pkt_fwd,
        'min_seg_size_forward': min_seg_size_fwd,
        'Active Mean': active_mean,
        'Active Std': active_std,
        'Active Max': active_max,
        'Active Min': active_min,
        'Idle Mean': idle_mean,
        'Idle Std': idle_std,
        'Idle Max': idle_max,
        'Idle Min': idle_min
    }
    return res

def extract_pcap_to_df(pcap_path, label, max_packets=50000, flow_timeout=120.0):
    flows = {}
    print(f"Reading pcap: {pcap_path} (max_packets={max_packets})...")
    
    count = 0
    try:
        with PcapReader(str(pcap_path)) as pcap_reader:
            for pkt in pcap_reader:
                count += 1
                if count > max_packets:
                    break
                if not pkt.haslayer(IP):
                    continue
                    
                ip = pkt[IP]
                proto = ip.proto
                src_ip = ip.src
                dst_ip = ip.dst
                ts = float(pkt.time)
                pkt_len = len(pkt)
                
                sport, dport = 0, 0
                flags = 0
                hdr_len = 20
                payload_len = 0
                win_size = 0
                
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    sport = tcp.sport
                    dport = tcp.dport
                    flags = int(tcp.flags)
                    hdr_len = (tcp.dataofs or 5) * 4
                    payload_len = len(tcp.payload)
                    win_size = tcp.window
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    sport = udp.sport
                    dport = udp.dport
                    hdr_len = 8
                    payload_len = len(udp.payload)
                    
                fwd_key = (src_ip, dst_ip, sport, dport, proto)
                bwd_key = (dst_ip, src_ip, dport, sport, proto)
                
                if fwd_key in flows:
                    flows[fwd_key].add_packet(True, ts, pkt_len, flags, hdr_len, payload_len, win_size)
                elif bwd_key in flows:
                    flows[bwd_key].add_packet(False, ts, pkt_len, flags, hdr_len, payload_len, win_size)
                else:
                    new_flow = Flow(src_ip, dst_ip, sport, dport, proto)
                    new_flow.add_packet(True, ts, pkt_len, flags, hdr_len, payload_len, win_size)
                    flows[fwd_key] = new_flow
    except Exception as e:
        print(f"Lỗi đọc file pcap {pcap_path}: {e}")
        
    print(f"  Processed {count:,} packets -> {len(flows):,} flows.")
    records = []
    for fl in flows.values():
        st = calculate_flow_stats(fl, flow_timeout=flow_timeout)
        if st is not None:
            st['Label'] = label
            records.append(st)
            
    df = pd.DataFrame(records)
    print(f"  Extracted {len(df):,} valid flow records for Label='{label}'")
    return df
