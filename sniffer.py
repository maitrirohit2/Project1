# sniffer.py
# Simple packet sniffer that writes one CSV line per packet
from scapy.all import sniff, IP, TCP, UDP
import csv, time, os

OUTFILE = 'flows.csv'

# create header if not exists
if not os.path.exists(OUTFILE):
    with open(OUTFILE,'w',newline='') as f:
        csv.writer(f).writerow(['ts','src','dst','sport','dport','proto','length','flags'])

def packet_to_row(pkt):
    ts = time.time()
    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        length = len(pkt)
        sport = ''
        dport = ''
        flags = ''
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].sprintf('%flags%')
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        return [ts, src, dst, sport, dport, proto, length, flags]
    return None

def handle_packet(pkt):
    row = packet_to_row(pkt)
    if row:
        with open(OUTFILE,'a',newline='') as f:
            csv.writer(f).writerow(row)

if __name__ == '__main__':
    print("Starting sniff (CTRL-C to stop)...")
    sniff(prn=handle_packet, store=False)
