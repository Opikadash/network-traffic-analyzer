from collections import defaultdict
from threading import Lock
from scapy.packet import Packet
from datetime import datetime

class StatsTracker:
    def __init__(self):
        self.total = 0
        self.anomalies = 0
        self.protocol_counts = defaultdict(int)
        self.lock = Lock()
        self.time_series = defaultdict(lambda: defaultdict(int))  # time_bucket -> protocol -> count

    def update(self, packet: Packet, is_anomaly: bool):
        with self.lock:
            self.total += 1
            if is_anomaly:
                self.anomalies += 1

            proto = self.get_protocol(packet)
            self.protocol_counts[proto] += 1

            # Use full ISO timestamp
            timestamp = datetime.now().isoformat()
            self.time_series[proto][timestamp] += 1
            self.time_series["ALL"][timestamp] += 1

    def get_protocol(self, packet: Packet) -> str:
        if packet.haslayer("TCP"): return "TCP"
        elif packet.haslayer("UDP"): return "UDP"
        elif packet.haslayer("ICMP"): return "ICMP"
        elif packet.haslayer("DNS"): return "DNS"
        else: return "OTHER"

    def report(self, proto_filter=None) -> dict:
        with self.lock:
            if proto_filter is None:
                total = self.total
                anomalies = self.anomalies
            else:
                total = self.protocol_counts.get(proto_filter, 0)
                # We don't track per-protocol anomalies, use global
                anomalies = self.anomalies

            result = {
                "Total Packets": total,
                "Anomalies Detected": anomalies,
                "Anomaly Rate (%)": round((anomalies / total) * 100, 2) if total else 0
            }
            if proto_filter:
                result[f"{proto_filter} Packets"] = self.protocol_counts.get(proto_filter, 0)
            else:
                # Add all protocols
                for proto, count in self.protocol_counts.items():
                    result[f"{proto} Packets"] = count
            return result

    def get_time_series(self, proto=None):
        proto = proto if proto else "ALL"
        with self.lock:
            # Return sorted by time
            sorted_data = dict(sorted(self.time_series[proto].items(), key=lambda x: x[0]))
            return sorted_data
