# flow_aggregator_online.py
import csv, time, threading, os
from collections import deque
import statistics

INPUT_CSV = 'flows.csv'
OUTPUT_CSV = 'flows_features.csv'
INACTIVE_TIMEOUT = 60.0   # expire flow after 60s of no packets
ACTIVE_TIMEOUT = 300.0    # max flow lifetime
PURGE_INTERVAL = 2.0

flows = {}
file_pos = 0
lock = threading.Lock()

# create output CSV header if not exists
if not os.path.exists(OUTPUT_CSV):
    with open(OUTPUT_CSV,'w',newline='') as f:
        csv.writer(f).writerow([
            'start','end','duration','src','dst','sport','dport','proto',
            'pkt_count','byte_count','avg_pkt_size','packet_rate',
            'syn_count','fin_count','rst_count',
            'src_to_dst_pkts','dst_to_src_pkts','src_to_dst_bytes','dst_to_src_bytes',
            'unique_dst_ports','inter_arrival_mean','inter_arrival_std'
        ])

def make_flow_initial(ts, src, dst, sport, dport, proto, length, flags, direction):
    return {
        'start': ts, 'last': ts,
        'pkt_count': 1, 'byte_count': length,
        'syn_count': 1 if flags and 'S' in flags else 0,
        'fin_count': 1 if flags and 'F' in flags else 0,
        'rst_count': 1 if flags and 'R' in flags else 0,
        'src_to_dst_pkts': 1 if direction == 'forward' else 0,
        'dst_to_src_pkts': 1 if direction == 'reverse' else 0,
        'src_to_dst_bytes': length if direction == 'forward' else 0,
        'dst_to_src_bytes': length if direction == 'reverse' else 0,
        'inter_arrivals': deque(maxlen=1000),
        'last_pkt_ts': ts,
        'unique_dst_ports': set([dport])
    }

def update_flow(flow, ts, length, flags, direction, dport):
    ia = ts - flow['last_pkt_ts']
    if ia >= 0:
        flow['inter_arrivals'].append(ia)
    flow['last_pkt_ts'] = ts
    flow['last'] = ts
    flow['pkt_count'] += 1
    flow['byte_count'] += length
    if flags:
        if 'S' in flags: flow['syn_count'] += 1
        if 'F' in flags: flow['fin_count'] += 1
        if 'R' in flags: flow['rst_count'] += 1
    if direction == 'forward':
        flow['src_to_dst_pkts'] += 1
        flow['src_to_dst_bytes'] += length
    else:
        flow['dst_to_src_pkts'] += 1
        flow['dst_to_src_bytes'] += length
    flow['unique_dst_ports'].add(dport)

def finalize_flow(key, flow):
    start = flow['start']; end = flow['last']
    duration = max(0.0001, end - start)
    pkt_count = flow['pkt_count']; byte_count = flow['byte_count']
    avg_pkt_size = byte_count / pkt_count if pkt_count else 0
    packet_rate = pkt_count / duration
    ia_mean = statistics.mean(flow['inter_arrivals']) if flow['inter_arrivals'] else 0
    ia_std = statistics.pstdev(flow['inter_arrivals']) if flow['inter_arrivals'] else 0
    return [
        start, end, duration, key[0], key[1], key[2], key[3], key[4],
        pkt_count, byte_count, avg_pkt_size, packet_rate,
        flow['syn_count'], flow['fin_count'], flow['rst_count'],
        flow['src_to_dst_pkts'], flow['dst_to_src_pkts'],
        flow['src_to_dst_bytes'], flow['dst_to_src_bytes'],
        len(flow['unique_dst_ports']), ia_mean, ia_std
    ]

def purge_thread():
    while True:
        time.sleep(PURGE_INTERVAL)
        now = time.time()
        expired = []
        with lock:
            for key, flow in list(flows.items()):
                inactive = now - flow['last']
                active_time = now - flow['start']
                if inactive > INACTIVE_TIMEOUT or active_time > ACTIVE_TIMEOUT:
                    expired.append((key, flow))
                    del flows[key]
        if expired:
            with open(OUTPUT_CSV,'a',newline='') as f:
                w = csv.writer(f)
                for key, flow in expired:
                    w.writerow(finalize_flow(key, flow))

def tail_input():
    global file_pos
    while True:
        if not os.path.exists(INPUT_CSV):
            time.sleep(1); continue
        with open(INPUT_CSV,'r') as f:
            f.seek(file_pos)
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].lower().startswith('ts'): continue
                try:
                    ts = float(row[0]); src = row[1]; dst = row[2]
                    sport = int(row[3]) if row[3] else 0
                    dport = int(row[4]) if row[4] else 0
                    proto = int(row[5]) if row[5] else 0
                    length = int(row[6]) if row[6] else 0
                    flags = row[7] if len(row) > 7 else None
                except Exception:
                    continue
                # direction: forward if same tuple; reverse is (dst,src,dport,sport,proto)
                forward_key = (src,dst,sport,dport,proto)
                reverse_key = (dst,src,dport,sport,proto)
                with lock:
                    if forward_key in flows:
                        update_flow(flows[forward_key], ts, length, flags, 'forward', dport)
                    elif reverse_key in flows:
                        update_flow(flows[reverse_key], ts, length, flags, 'reverse', dport)
                    else:
                        # new flow, create forward_key
                        flows[forward_key] = make_flow_initial(ts, src, dst, sport, dport, proto, length, flags, 'forward')
            file_pos = f.tell()
        time.sleep(0.3)

if __name__ == '__main__':
    t = threading.Thread(target=purge_thread, daemon=True)
    t.start()
    print("Aggregator watching", INPUT_CSV, " -> writing", OUTPUT_CSV)
    tail_input()
