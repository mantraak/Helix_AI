from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import get_connection

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "Helix Backend Running 🚀"}


@app.get("/dashboard")
def dashboard():
    conn = get_connection()
    cur = conn.cursor()

    # system stats
    cur.execute("SELECT * FROM system_stats LIMIT 1;")
    stats = cur.fetchone()

    # latest attack logs
    cur.execute("""
        SELECT source_ip, attack_type, severity, packet_count, action_taken, timestamp
        FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 20;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    # default
    if not stats:
        return {
            "packets": 0,
            "attacks": 0,
            "healing": 0,
            "suspicious": 0,
            "logRows": [],
            "liveRows": []
        }

    logRows = []
    liveRows = []

    for r in rows:
        ts = str(r[5]).split('.')[0]

        logRows.append({
            "ts": ts,
            "ip": r[0],
            "type": r[1],
            "sev": r[2].lower(),
            "pkts": r[3],
            "action": r[4]
        })

        liveRows.append({
            "ts": ts,
            "src": r[0],
            "dst": "SERVER",
            "proto": "TCP",
            "pkts": r[3],
            "risk": r[2].lower(),
            "status": "blocked"
        })

    return {
        "packets": stats[1],
        "attacks": stats[2],
        "healing": stats[3],
        "suspicious": stats[4],
        "logRows": logRows,
        "liveRows": liveRows
    }
