from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
import requests
from datetime import datetime
from collections import defaultdict
import time
import threading

API_URL = "http://127.0.0.1:8000/packet"

# Per-IP tracking
ip_count    = defaultdict(int)
ip_first_ts = defaultdict(float)
ip_ports    = defaultdict(set)
last_reset  = time.time()
WINDOW      = 10  # seconds

# Prevent duplicate healing for same IP
healing_in_progress = set()
healing_lock        = threading.Lock()


def reset_if_needed():
    global last_reset
    now = time.time()
    if now - last_reset > WINDOW:
        ip_count.clear()
        ip_first_ts.clear()
        ip_ports.clear()
        last_reset = now


def get_risk(proto, src, dst, packet):
    reset_if_needed()
    now = time.time()

    if src != "UNKNOWN":
        ip_count[src] += 1
        if src not in ip_first_ts:
            ip_first_ts[src] = now

    count    = ip_count.get(src, 1)
    duration = max(1, now - ip_first_ts.get(src, now))
    rate     = count / duration

    if proto == "TCP":
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else "?"
        src_port = packet[TCP].sport if packet.haslayer(TCP) else "?"
        flags    = packet[TCP].flags if packet.haslayer(TCP) else 0
        syn_only = (flags == 0x002)

        if src != "UNKNOWN":
            ip_ports[src].add(dst_port)
        port_count = len(ip_ports.get(src, set()))

        if count > 80:
            return ("HIGH", "TCP SYN Flood",
                    f"TCP flood: {count} packets from {src} in {WINDOW}s — rate {rate:.1f}pkt/s — port {dst_port}")
        if port_count > 10:
            return ("HIGH", "Port Scan",
                    f"Port scan: {src} contacted {port_count} different ports")
        if syn_only and count > 30:
            return ("HIGH", "TCP SYN Flood",
                    f"SYN flood: {count} SYN-only packets from {src} → port {dst_port}")
        if count > 30:
            return ("MEDIUM", "Elevated TCP Traffic",
                    f"Elevated TCP: {count} connections from {src} in {WINDOW}s → port {dst_port}")
        if port_count > 5:
            return ("MEDIUM", "TCP Port Sweep",
                    f"Port sweep: {src} scanning {port_count} ports")
        return ("LOW", "Normal TCP", f"Normal TCP {src}:{src_port} → {dst}:{dst_port}")

    if proto == "UDP":
        dst_port = packet[UDP].dport if packet.haslayer(UDP) else "?"
        pkt_size = len(packet)

        if count > 50:
            return ("HIGH", "UDP Flood",
                    f"UDP flood: {count} datagrams from {src} in {WINDOW}s → port {dst_port}")
        if dst_port == 53 and pkt_size > 512:
            return ("MEDIUM", "DNS Amplification",
                    f"Large DNS packet ({pkt_size}B) from {src}")
        if count > 20:
            return ("MEDIUM", "Elevated UDP Traffic",
                    f"Elevated UDP: {count} packets from {src} → port {dst_port}")
        return ("LOW", "Normal UDP", f"Normal UDP {src} → port {dst_port}")

    if proto == "ICMP":
        icmp_type = packet[ICMP].type if packet.haslayer(ICMP) else "?"
        if count > 30:
            return ("HIGH", "ICMP Flood",
                    f"ICMP flood: {count} pings from {src} in {WINDOW}s — rate {rate:.1f}pkt/s")
        if count > 10:
            return ("MEDIUM", "ICMP Ping Sweep",
                    f"Ping sweep: {count} ICMP type-{icmp_type} from {src} in {WINDOW}s")
        return ("LOW", "Normal ICMP", f"Normal ICMP type-{icmp_type} from {src}")

    if proto == "ARP":
        if count > 15:
            return ("HIGH", "ARP Spoofing",
                    f"ARP flood: {count} ARP packets from {src} — possible spoofing")
        if count > 5:
            return ("MEDIUM", "ARP Sweep",
                    f"ARP sweep: {count} requests from {src}")
        return ("LOW", "Normal ARP", f"Normal ARP from {src}")

    pkt_size = len(packet)
    if pkt_size > 1400:
        return ("MEDIUM", "Oversized Packet",
                f"Oversized {proto} packet ({pkt_size}B) from {src}")

    return ("LOW", "Normal Traffic", f"Normal {proto} from {src}")


def trigger_healing(src, attack_type, risk, reason, pkts):
    """
    Call llm_engine.handle_attack() in background thread.
    Prevents duplicate healing for same IP.
    """
    with healing_lock:
        if src in healing_in_progress:
            return
        healing_in_progress.add(src)

    def _heal():
        try:
            from llm_engine import handle_attack
            handle_attack(src, attack_type, risk, reason, pkts)
        except Exception as e:
            print(f"❌ Healing error: {e}")
        finally:
            time.sleep(30)
            with healing_lock:
                healing_in_progress.discard(src)

    t = threading.Thread(target=_heal, daemon=True)
    t.start()


def process_packet(packet):
    try:
        proto = "OTHER"
        src   = "UNKNOWN"
        dst   = "UNKNOWN"

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(ARP):
            src   = packet[ARP].psrc
            dst   = packet[ARP].pdst
            proto = "ARP"
        elif packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        # Skip loopback
        if src in ("127.0.0.1", "::1") or dst in ("127.0.0.1", "::1"):
            return

        pkts = len(packet)
        risk, attack_type, reason = get_risk(proto, src, dst, packet)
        status = "blocked" if risk == "HIGH" else "allowed"

        # Send to FastAPI
        data = {
            "ts":     str(datetime.now()),
            "pkts":   pkts,
            "proto":  proto,
            "src":    src,
            "dst":    dst,
            "risk":   risk,
            "status": status,
            "reason": f"{attack_type} — {reason}"
        }

        try:
            requests.post(API_URL, json=data, timeout=2)
        except Exception as e:
            print(f"❌ API error: {e}")

        # ── Trigger LLM healing for HIGH and MEDIUM ──
        if risk in ("HIGH", "MEDIUM"):
            icon = "🔴" if risk == "HIGH" else "🟡"
            print(f"\n{icon} {risk} DETECTED")
            print(f"   Type   : {attack_type}")
            print(f"   From   : {src}")
            print(f"   Reason : {reason}")
            print(f"   ➡ Sending to TinyLLaMA for healing decision...")
            trigger_healing(src, attack_type, risk, reason, pkts)

    except Exception as e:
        print(f"❌ Packet error: {e}")


def start_sniffing():
    print("🚀 Helix IDS Engine — TinyLLaMA Healing Active\n")
    print("🔍 Interface  : eth0")
    print("🕐 Window     : 10s per-IP tracking")
    print("🤖 LLM        : TinyLLaMA via Ollama :11434")
    print("📊 Logging    : HIGH + MEDIUM → DB + iptables")
    print("─" * 55)

    try:
        sniff(iface="eth0", prn=process_packet, store=False)
    except Exception as e:
        print(f"❌ eth0 failed: {e} — trying lo...")
        sniff(iface="lo", prn=process_packet, store=False)


if __name__ == "__main__":
    start_sniffing()
