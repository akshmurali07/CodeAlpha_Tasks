from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime

def parse_packet(packet):
    packet_info = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": "",
        "destination": "",
        "protocol": "OTHER",
        "size": len(packet),
        "info": ""
    }

    if IP in packet:
        packet_info["source"] = packet[IP].src
        packet_info["destination"] = packet[IP].dst

        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["info"] = f"Port {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["info"] = f"Port {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["info"] = "Ping packet"

    elif ARP in packet:
        packet_info["source"] = packet[ARP].psrc
        packet_info["destination"] = packet[ARP].pdst
        packet_info["protocol"] = "ARP"
        packet_info["info"] = "ARP Request/Reply"

    return packet_info


def start_sniffing(socketio):
    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0, "bytes": 0}

    def handle_packet(packet):
        info = parse_packet(packet)
        stats["total"] += 1
        stats["bytes"] += info["size"]
        proto = info["protocol"].lower()
        if proto in stats:
            stats[proto] += 1
        else:
            stats["other"] += 1
        socketio.emit("packet", info, namespace='/')
        socketio.emit("stats", stats, namespace='/')

    sniff(prn=handle_packet, store=False, count=0)