from collections import defaultdict
from scapy.layers.inet import IP, TCP
import time
import threading

connection_log = defaultdict(list)
THRESHOLD = 20  # packets to different ports/IPs in short time
TIME_WINDOW = 5  # seconds
connection_lock = threading.Lock()

def detect_port_scan(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return False

    ip = packet[IP].src
    port = packet[TCP].dport
    now = time.time()

    with connection_lock:
        connection_log[ip].append((port, now))
        # Clean up old entries for this IP
        connection_log[ip] = [(p, t) for p, t in connection_log[ip] if now - t < TIME_WINDOW]

        ports_accessed = set(p for p, _ in connection_log[ip])
        return len(ports_accessed) > THRESHOLD
