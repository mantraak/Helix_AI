from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import requests
from datetime import datetime

# 🔹 Global counters
packet_count = 0
last_time = time.time()

# 🔹 Track suspicious IPs
ip_tracker = {}

# 🔹 Detect protocol
def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"

# 🔹 Detect threat level
def detect_threat(src_ip):
    global ip_tracker

    ip_tracker[src_ip] = ip_tracker.get(src_ip, 0) + 1

    if ip_tracker[src_ip] > 100:
        return "HIGH"
    elif ip_tracker[src_ip] > 50:
        return "MEDIUM"
    else:
        return "LOW"

# 🔹 Process each packet
def process_packet(packet):
    global packet_count, last_time

    packet_count += 1

    # Extract IP info
    src_ip = "unknown"
    dst_ip = "unknown"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    protocol = get_protocol(packet)
    risk = detect_threat(src_ip)

    status = "allowed"
    if risk == "HIGH":
        status = "blocked"

    # ⏱ Send every 1 second
    if time.time() - last_time >= 1:
        try:
            requests.post("http://127.0.0.1:8000/packet", json={
                "ts": datetime.now().strftime("%H:%M:%S"),
                "pkts": packet_count,
                "proto": protocol,
                "src": src_ip,
                "dst": dst_ip,
                "risk": risk,
                "status": status
            })
        except Exception as e:
            print("⚠️ Error sending data:", e)

        # 🔄 Reset counter
        packet_count = 0
        last_time = time.time()

# 🔹 Start sniffing
def start_sniffing():
    print("🚀 IDS Engine Started... Capturing real network traffic...")
    sniff(prn=process_packet, store=0)

# 🔹 Run
if __name__ == "__main__":
    start_sniffing()
