# analyzer/filter_ai.py
from scapy.packet import Packet

def is_anomalous(packet: Packet, size_threshold: int = 1000) -> bool:
    """
    Simple anomaly detection: marks packets above a size threshold.
    """
    return len(packet) > size_threshold
