
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from db import get_connection

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PacketData(BaseModel):
    ts:     str
    pkts:   int
    proto:  str
    src:    str
    dst:    str
    risk:   str
    status: str
    reason: Optional[str] = "Unknown"


@app.get("/")
def home():
    return {"message": "Helix Backend Running 🚀"}


@app.post("/packet")
def receive_packet(data: PacketData):
    conn = get_connection()
    cur  = conn.cursor()
    try:
        risk = data.risk.upper()

        if risk in ("HIGH", "MEDIUM"):
            cur.execute("""
                INSERT INTO attack_logs
                    (source_ip, attack_type, severity, packet_count, action_taken)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data.src,
                data.reason or "Unknown Attack",
                risk,
                data.pkts,
                "blocked" if risk == "HIGH" else "Alert Only"
            ))

        cur.execute("""
            INSERT INTO system_stats (id, packets, attacks, healing, suspicious)
            VALUES (1, %s, 0, 0, 0)
            ON CONFLICT (id) DO UPDATE SET
                packets    = system_stats.packets + EXCLUDED.packets,
                attacks    = system_stats.attacks +
                             CASE WHEN %s = 'HIGH' THEN 1 ELSE 0 END,
                healing    = system_stats.healing +
                             CASE WHEN %s = 'HIGH' THEN 1 ELSE 0 END,
                suspicious = system_stats.suspicious +
                             CASE WHEN %s != 'LOW' THEN 1 ELSE 0 END
        """, (data.pkts, risk, risk, risk))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("❌ DB Error:", e)
        return {"status": "error", "message": str(e)}
    finally:
        cur.close()
        conn.close()

    return {"status": "ok"}


@app.get("/dashboard")
def dashboard():
    conn = get_connection()
    cur  = conn.cursor()

    try:
        cur.execute("SELECT * FROM system_stats WHERE id = 1 LIMIT 1;")
        stats = cur.fetchone()

        cur.execute("""
            SELECT source_ip, attack_type, severity, packet_count, action_taken, timestamp
            FROM attack_logs
            WHERE severity IN ('HIGH', 'MEDIUM')
            ORDER BY timestamp DESC
            LIMIT 50;
        """)
        rows = cur.fetchall()

        cur.execute("""
            SELECT source_ip, attack_type, severity, packet_count, action_taken, timestamp
            FROM attack_logs
            ORDER BY timestamp DESC
            LIMIT 50;
        """)
        live_raw = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    if not stats:
        return {
            "packets": 0, "attacks": 0, "healing": 0, "suspicious": 0,
            "logRows": [], "liveRows": []
        }

    logRows  = []
    liveRows = []

    for r in rows:
        ts  = str(r[5]).split('.')[0]
        sev = r[2].lower() if r[2] else "medium"
        logRows.append({
            "ts":     ts,
            "ip":     r[0] if r[0] and r[0] not in ("UNKNOWN", "Unresolved") else "Internal",
            "type":   r[1],
            "sev":    sev,
            "pkts":   r[3],
            "action": r[4]
        })

    for r in live_raw:
        ts  = str(r[5]).split('.')[0]
        sev = r[2].lower() if r[2] else "low"
        liveRows.append({
            "ts":     ts,
            "src":    r[0] if r[0] and r[0] not in ("UNKNOWN", "Unresolved") else "Internal",
            "dst":    "SERVER",
            "proto":  "TCP",
            "pkts":   r[3],
            "risk":   sev,
            "status": r[4]
        })

    return {
        "packets":    stats[1],
        "attacks":    stats[2],
        "healing":    stats[3],
        "suspicious": stats[4],
        "logRows":    logRows,
        "liveRows":   liveRows
    }


@app.get("/healing")
def get_healing():
    """
    Returns all healing decisions made by Claude AI / Rule Engine
    """
    conn = get_connection()
    cur  = conn.cursor()

    try:
        cur.execute("""
            SELECT
                a.timestamp,
                a.affected_asset,
                a.anomaly_type,
                a.severity,
                a.confidence_score,
                d.chosen_strategy,
                d.llm_reasoning,
                d.strategy_confidence,
                d.model_version
            FROM alerts a
            LEFT JOIN llm_decisions d ON a.alert_id = d.alert_id
            ORDER BY a.timestamp DESC
            LIMIT 50;
        """)
        rows = cur.fetchall()

        # Blocked IPs
        cur.execute("""
            SELECT ip_address, reason, blocked_at, unblocked_at
            FROM blocked_ips
            ORDER BY blocked_at DESC
            LIMIT 20;
        """)
        blocked = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    healing_rows = []
    for r in rows:
        ts = str(r[0]).split('.')[0] if r[0] else "--"
        healing_rows.append({
            "ts":           ts,
            "ip":           r[1] or "Unknown",
            "attack_type":  r[2] or "Unknown",
            "severity":     r[3] or "medium",
            "confidence":   round(float(r[4] or 0), 2),
            "strategy":     r[5] or "Alert Only",
            "reasoning":    r[6] or "Rule-based decision",
            "model":        r[8] or "Rule Engine"
        })

    blocked_rows = []
    for b in blocked:
        blocked_rows.append({
            "ip":          b[0],
            "reason":      b[1],
            "blocked_at":  str(b[2]).split('.')[0] if b[2] else "--",
            "unblocked_at": str(b[3]).split('.')[0] if b[3] else "Active"
        })

    return {
        "total_healing_events": len(healing_rows),
        "total_blocked_ips":    len(blocked_rows),
        "healing_events":       healing_rows,
        "blocked_ips":          blocked_rows
    }
