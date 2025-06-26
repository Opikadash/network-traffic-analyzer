from scapy.packet import Packet

def extract_features(packet: Packet) -> dict:
    return {
        "length": len(packet),
        "is_tcp": int(packet.haslayer("TCP")),
        "is_udp": int(packet.haslayer("UDP")),
        "is_icmp": int(packet.haslayer("ICMP")),
        "is_dns": int(packet.haslayer("DNS")),
    }
