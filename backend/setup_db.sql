CREATE TABLE IF NOT EXISTS attack_logs (
    id           SERIAL PRIMARY KEY,
    source_ip    VARCHAR(50),
    attack_type  VARCHAR(100),
    severity     VARCHAR(20),
    packet_count INTEGER DEFAULT 0,
    action_taken VARCHAR(100),
    timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_stats (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    packets    BIGINT  DEFAULT 0,
    attacks    INTEGER DEFAULT 0,
    healing    INTEGER DEFAULT 0,
    suspicious INTEGER DEFAULT 0
);

INSERT INTO system_stats (id, packets, attacks, healing, suspicious)
VALUES (1, 0, 0, 0, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id         SERIAL PRIMARY KEY,
    timestamp        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    anomaly_type     VARCHAR(100),
    severity         VARCHAR(20),
    confidence_score FLOAT,
    affected_asset   VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS llm_decisions (
    decision_id         SERIAL PRIMARY KEY,
    alert_id            INTEGER REFERENCES alerts(alert_id),
    llm_prompt          TEXT,
    llm_reasoning       TEXT,
    chosen_strategy     VARCHAR(100),
    strategy_confidence FLOAT,
    model_version       VARCHAR(50),
    timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS global_threat_intel (
    ip_address           VARCHAR(50) PRIMARY KEY,
    first_seen           TIMESTAMP,
    last_seen            TIMESTAMP,
    reason               VARCHAR(200),
    risk_score           FLOAT DEFAULT 0.0,
    blocked_by_system_id VARCHAR(20),
    block_count          INTEGER DEFAULT 1
);

SELECT 'Database setup complete!' AS status;
