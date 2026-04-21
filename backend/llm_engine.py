"""
llm_engine.py
=============
Connected to Ollama TinyLLaMA on port 11434
Called directly by ids_engine.py when attack detected
"""

import psycopg2
import subprocess
import requests
import json
import time
import re
import threading
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
import numpy as np

# =========================
# CONFIG
# =========================
DB_CONFIG = {
    "dbname": "john_db",
    "user":   "postgres",
    "password": "1234",
    "host":   "localhost",
    "port":   5432
}

# ✅ Updated to Ollama port
OLLAMA_API = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "tinyllama"
SYSTEM_ID = "P1"
MONITOR_INTERVAL = 10

# =========================
# DATABASE CONNECTION
# =========================
def db():
    return psycopg2.connect(**DB_CONFIG)

# =========================
# ASK TINYLLAMA via OLLAMA
# =========================
def ask_llm(attack_type, confidence, src_ip, reason):
    prompt = f"""You are a cybersecurity self-healing AI.

Attack detected:
- Type: {attack_type}
- Source IP: {src_ip}
- Reason: {reason}
- Confidence: {confidence}

Choose ONE strategy:
1. Permanent Block
2. Temporary Block 15min
3. Rate Limit
4. Alert Only
5. Drop Packets

Reply ONLY with this JSON, nothing else:
{{
  "chosen_strategy": "Temporary Block 15min",
  "reasoning": "one sentence why",
  "strategy_confidence": 0.95
}}"""

    try:
        response = requests.post(
            OLLAMA_API,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            },
            timeout=30
        )

        if response.status_code == 200:
            raw = response.json().get("response", "")
            raw = raw.replace("```json", "").replace("```", "").strip()
            result = json.loads(raw)
            print(f"🤖 TinyLLaMA decided: {result['chosen_strategy']}")
            print(f"   Reasoning: {result['reasoning']}")
            return result
        else:
            print(f"⚠ Ollama error {response.status_code} — using rule-based fallback")
            return rule_based_decision(attack_type, src_ip)

    except Exception as e:
        print(f"⚠ TinyLLaMA unavailable ({e}) — using rule-based fallback")
        return rule_based_decision(attack_type, src_ip)


# =========================
# RULE-BASED FALLBACK
# =========================
def rule_based_decision(attack_type, src_ip):
    attack = attack_type.upper()

    if "SYN FLOOD" in attack or "TCP" in attack:
        return {
            "chosen_strategy": "Temporary Block 15min",
            "reasoning": "SYN/TCP flood — temporary block applied for 15 minutes",
            "strategy_confidence": 0.95
        }
    elif "PORT SCAN" in attack:
        return {
            "chosen_strategy": "Temporary Block 15min",
            "reasoning": "Port scan detected — blocking scanner IP temporarily",
            "strategy_confidence": 0.90
        }
    elif "ICMP" in attack:
        return {
            "chosen_strategy": "Drop Packets",
            "reasoning": "ICMP flood — dropping all ICMP from attacker",
            "strategy_confidence": 0.92
        }
    elif "UDP" in attack:
        return {
            "chosen_strategy": "Rate Limit",
            "reasoning": "UDP flood — rate limiting to reduce impact",
            "strategy_confidence": 0.88
        }
    elif "ARP" in attack:
        return {
            "chosen_strategy": "Alert Only",
            "reasoning": "ARP spoofing — logged and monitoring",
            "strategy_confidence": 0.75
        }
    else:
        return {
            "chosen_strategy": "Alert Only",
            "reasoning": f"Unknown attack type — logging and monitoring {src_ip}",
            "strategy_confidence": 0.70
        }


# =========================
# HEALING ACTIONS
# =========================
def block_ip(ip):
    if not ip or ip in ("UNKNOWN", "Unresolved", "127.0.0.1"):
        return False
    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    print(f"🔒 Permanently blocked {ip}")
    return result.returncode == 0


def temp_block_ip(ip):
    if not ip or ip in ("UNKNOWN", "Unresolved", "127.0.0.1"):
        return False

    def _unblock():
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        print(f"🔒 Temp blocked {ip} — auto-unblock in 15 min")
        time.sleep(900)
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        print(f"🔓 Auto-unblocked {ip} after 15 min")
        # Update DB
        try:
            conn = db()
            cur  = conn.cursor()
            cur.execute("""
                UPDATE blocked_ips SET unblocked_at = NOW()
                WHERE ip_address = %s AND unblocked_at IS NULL
            """, (ip,))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"DB unblock error: {e}")

    t = threading.Thread(target=_unblock, daemon=True)
    t.start()
    return True


def rate_limit_ip(ip):
    if not ip or ip in ("UNKNOWN", "Unresolved", "127.0.0.1"):
        return False
    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip,
         "-m", "limit", "--limit", "10/s", "--limit-burst", "20", "-j", "ACCEPT"],
        capture_output=True, text=True
    )
    print(f"⚡ Rate limited {ip} to 10pkt/s")
    return result.returncode == 0


def drop_icmp(ip):
    if not ip or ip in ("UNKNOWN", "Unresolved", "127.0.0.1"):
        return False
    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "icmp", "-j", "DROP"],
        capture_output=True, text=True
    )
    print(f"🚫 Dropped ICMP from {ip}")
    return result.returncode == 0


def alert_only(message):
    print(f"📢 ALERT: {message}")


# =========================
# STORE TO DB
# =========================
def store_event(ip, attack_type, confidence, decision):
    conn = db()
    cur  = conn.cursor()
    try:
        # Save to alerts
        cur.execute("""
            INSERT INTO alerts
                (timestamp, anomaly_type, severity, confidence_score, affected_asset)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING alert_id
        """, (datetime.now(), attack_type, "high", confidence, ip))
        alert_id = cur.fetchone()[0]

        # Save LLM decision
        cur.execute("""
            INSERT INTO llm_decisions
                (alert_id, llm_prompt, llm_reasoning, chosen_strategy,
                 strategy_confidence, model_version, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            alert_id,
            f"Attack: {attack_type} from {ip}",
            decision.get("reasoning", "Rule-based"),
            decision.get("chosen_strategy", "Alert Only"),
            decision.get("strategy_confidence", 0.8),
            "TinyLLaMA-Ollama",
            datetime.now()
        ))

        # Save to blocked_ips if blocked
        strategy = decision.get("chosen_strategy", "")
        if "Block" in strategy or "Drop" in strategy:
            if ip and ip not in ("UNKNOWN", "Unresolved", "127.0.0.1"):
                unblock_at = None
                if "15min" in strategy or "Temporary" in strategy:
                    unblock_at = datetime.now() + timedelta(minutes=15)

                cur.execute("""
                    INSERT INTO blocked_ips
                        (ip_address, reason, blocked_at, unblocked_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        reason = EXCLUDED.reason,
                        blocked_at = EXCLUDED.blocked_at,
                        unblocked_at = EXCLUDED.unblocked_at
                """, (ip, attack_type, datetime.now(), unblock_at))

        conn.commit()
        print(f"✅ Event saved to DB — alert_id: {alert_id}")

    except Exception as e:
        conn.rollback()
        print(f"❌ DB error: {e}")
    finally:
        cur.close()
        conn.close()


# =========================
# MAIN HANDLE FUNCTION
# Called by ids_engine.py
# =========================
def handle_attack(src_ip, attack_type, severity, reason, packet_count=0):
    """
    Full healing pipeline:
    1. Ask TinyLLaMA for strategy
    2. Execute real action
    3. Log to DB
    """
    print(f"\n{'='*50}")
    print(f"🚨 HEALING TRIGGERED")
    print(f"   IP       : {src_ip}")
    print(f"   Attack   : {attack_type}")
    print(f"   Severity : {severity}")
    print(f"   Reason   : {reason}")
    print(f"{'='*50}")

    # Skip internal IPs
    if src_ip in ("UNKNOWN", "Unresolved", "127.0.0.1", "::1"):
        print(f"⏭ Skipping internal IP: {src_ip}")
        return

    confidence = 0.95 if severity == "HIGH" else 0.75

    # Step 1 — Ask TinyLLaMA
    decision = ask_llm(attack_type, confidence, src_ip, reason)
    strategy = decision.get("chosen_strategy", "Alert Only")

    print(f"📋 Strategy: {strategy}")

    # Step 2 — Execute real action
    if "Permanent" in strategy:
        block_ip(src_ip)
        action = f"Permanently blocked {src_ip} via iptables"

    elif "Temporary" in strategy or "15min" in strategy:
        temp_block_ip(src_ip)
        action = f"Temporarily blocked {src_ip} — auto-unblock in 15 min"

    elif "Rate" in strategy:
        rate_limit_ip(src_ip)
        action = f"Rate limited {src_ip} to 10 packets/sec"

    elif "Drop" in strategy:
        drop_icmp(src_ip)
        action = f"Dropped packets from {src_ip}"

    else:
        alert_only(f"{attack_type} from {src_ip} — {reason}")
        action = f"Alert logged — monitoring {src_ip}"

    print(f"✅ Action taken: {action}")

    # Step 3 — Save to DB
    store_event(src_ip, attack_type, confidence, decision)

    print(f"{'='*50}\n")


# =========================
# STANDALONE MODE
# (original loop — still works)
# =========================
def collect_logs():
    return subprocess.getoutput("journalctl -n 100")

def extract_features(logs):
    return [len(logs), logs.count("Failed"), logs.count("SYN"), logs.count("error")]

def extract_ip(logs):
    match = re.search(r'\d+\.\d+\.\d+\.\d+', logs)
    return match.group() if match else None

def rule_engine(logs):
    if logs.count("Failed password") > 5:
        return "Brute Force", 0.9
    if logs.count("SYN") > 50:
        return "SYN Flood", 0.95
    if "segfault" in logs or "OOM" in logs:
        return "System Fault", 0.8
    return None, 0

def anomaly_engine(features):
    baseline = np.array([[1000,1,5,0],[1200,2,4,0],[900,1,3,0]])
    model = IsolationForest(contamination=0.1)
    model.fit(baseline)
    prediction = model.predict([features])
    if prediction[0] == -1:
        return "Zero-Day Anomaly", 0.7
    return None, 0

def main():
    print("[+] LLM Engine Started — Standalone Mode")
    while True:
        logs     = collect_logs()
        ip       = extract_ip(logs)
        features = extract_features(logs)

        alert_type, confidence = rule_engine(logs)
        if not alert_type:
            alert_type, confidence = anomaly_engine(features)

        if not alert_type:
            print("[✓] System Normal")
            time.sleep(MONITOR_INTERVAL)
            continue

        print(f"[!] Detected: {alert_type}")
        handle_attack(ip or "UNKNOWN", alert_type, "HIGH", alert_type, 0)
        time.sleep(MONITOR_INTERVAL)


if __name__ == "__main__":
    main()
