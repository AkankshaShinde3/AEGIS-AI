import csv
import io
import random
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

import database
from database import get_db
from detection import detect, worst_severity
from models import AlertUpdate, TrafficIn

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ALERT_STATUSES = {"NEW", "INVESTIGATING", "INVESTIGATED", "FALSE_POSITIVE"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    if _traffic_count() == 0:
        seed_sample_data()
    yield


app = FastAPI(title="AEGIS AI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- helpers ----------

def _traffic_count():
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) AS c FROM traffic").fetchone()["c"]
    conn.close()
    return n


def _history_for(src_ip):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM traffic WHERE src_ip = ? ORDER BY id", (src_ip,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _insert_traffic(rec: dict):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO traffic
           (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size,
            detection, severity, reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rec["timestamp"], rec["src_ip"], rec["dst_ip"], rec["protocol"],
            rec["src_port"], rec["dst_port"], rec["packet_size"],
            rec["detection"], rec["severity"], rec["reason"],
        ),
    )
    traffic_id = cur.lastrowid
    conn.commit()
    conn.close()
    return traffic_id


def _insert_alert(traffic_id, rec):
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO alerts
           (traffic_id, attack_type, src_ip, severity, timestamp, reason, status)
           VALUES (?, ?, ?, ?, ?, ?, 'NEW')""",
        (
            traffic_id, rec["detection"], rec["src_ip"], rec["severity"],
            rec["timestamp"], rec["reason"],
        ),
    )
    alert_id = cur.lastrowid
    conn.commit()
    conn.close()
    return alert_id


def _process_record(rec: dict):
    """Run detection on one record, store it, and create an alert if malicious."""
    history = _history_for(rec["src_ip"])
    result = detect(rec, history)
    rec.update(result)
    traffic_id = _insert_traffic(rec)
    alert_id = None
    if rec["detection"] != "BENIGN":
        alert_id = _insert_alert(traffic_id, rec)
    return {"traffic_id": traffic_id, "alert_id": alert_id, **rec}


# ---------- data generation ----------

BENIGN_SRCS = ["192.168.1.10", "192.168.1.11", "10.0.0.5", "172.16.0.20", "192.168.1.15"]
ATTACK_SRCS = ["45.155.204.12", "103.75.190.28", "185.220.101.4", "91.240.118.50"]
INTERNAL_DSTS = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.1"]
WEB_PORTS = [80, 443, 8080, 8443]

def _ts(offset_minutes=0):
    return (datetime.utcnow() - timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _benign_record(i):
    return {
        "timestamp": _ts(random.randint(0, 120)),
        "src_ip": random.choice(BENIGN_SRCS),
        "dst_ip": random.choice(INTERNAL_DSTS),
        "protocol": random.choice(["TCP", "TCP", "UDP"]),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(WEB_PORTS + [53, 123]),
        "packet_size": random.randint(200, 1500),
    }


def _burst(src_ip, dst_port, n, packet_size_range, dst_ip=None):
    return [{
        "timestamp": _ts(random.randint(0, 20)),
        "src_ip": src_ip,
        "dst_ip": dst_ip or random.choice(INTERNAL_DSTS),
        "protocol": "TCP",
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "packet_size": random.randint(*packet_size_range),
    } for _ in range(n)]


def _attack_records():
    """Generate one batch of 5-10 records in a single scenario."""
    scenario = random.choice(["benign", "port_scan", "brute_force", "ddos", "suspicious"])
    src = random.choice(ATTACK_SRCS) if scenario != "benign" else random.choice(BENIGN_SRCS)

    if scenario == "benign":
        return [_benign_record(i) for i in range(random.randint(5, 10))]
    if scenario == "port_scan":
        return _burst_scan(src, random.randint(7, 10))
    if scenario == "brute_force":
        return [_burst(src, random.choice([22, 21, 23]), 1, (100, 400))[0]
                for _ in range(random.randint(6, 8))]
    if scenario == "ddos":
        return [_burst(src, random.choice(WEB_PORTS), 1, (15000, 30000))[0]
                for _ in range(random.randint(6, 8))]
    # suspicious
    return [
        r for port in random.sample([80, 443, 8080, 21, 23], 4)
        for r in [_burst(src, port, 1, (2500, 4000))[0]]
    ] + [_benign_record(i) for i in range(random.randint(1, 3))]


def _burst_scan(src_ip, n):
    return [{
        "timestamp": _ts(random.randint(0, 20)),
        "src_ip": src_ip,
        "dst_ip": random.choice(INTERNAL_DSTS),
        "protocol": "TCP",
        "src_port": random.randint(1024, 65535),
        "dst_port": port,
        "packet_size": random.randint(40, 100),
    } for port in random.sample(range(1, 1024), n)]


def seed_sample_data():
    # Generate every scenario a few times so the dashboard has data
    for _ in range(2):
        for scenario_records in (
            [_benign_record(i) for i in range(8)],
            _burst_scan(scan_src := random.choice(ATTACK_SRCS), 8),
            [_burst(bf_src := random.choice(ATTACK_SRCS), random.choice([22, 21]), 1, (100, 400))[0]
             for _ in range(7)],
            [_burst(ddos_src := random.choice(ATTACK_SRCS), random.choice(WEB_PORTS), 1, (15000, 30000))[0]
             for _ in range(7)],
            [_burst(sus_src := random.choice(ATTACK_SRCS), port, 1, (2500, 4000))[0]
             for port in [80, 443, 8080, 21]],
        ):
            for rec in scenario_records:
                _process_record(rec)


# ---------- endpoints ----------

@app.get("/api/dashboard")
def dashboard():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) AS c FROM traffic").fetchone()["c"]
    threats = conn.execute(
        "SELECT COUNT(*) AS c FROM traffic WHERE detection != 'BENIGN'"
    ).fetchone()["c"]
    critical = conn.execute(
        "SELECT COUNT(*) AS c FROM alerts WHERE severity = 'CRITICAL'"
    ).fetchone()["c"]
    suspicious_ips = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) AS c FROM traffic WHERE detection != 'BENIGN'"
    ).fetchone()["c"]

    # Normal vs malicious over time (grouped by hour bucket of timestamp)
    rows = conn.execute(
        """SELECT substr(timestamp, 1, 13) AS bucket,
                  SUM(CASE WHEN detection = 'BENIGN' THEN 1 ELSE 0 END) AS benign,
                  SUM(CASE WHEN detection != 'BENIGN' THEN 1 ELSE 0 END) AS malicious
           FROM traffic GROUP BY bucket ORDER BY bucket"""
    ).fetchall()
    traffic_chart = [dict(r) for r in rows]

    # Attack category distribution
    rows = conn.execute(
        """SELECT attack_type AS name, COUNT(*) AS value FROM alerts
           WHERE attack_type != 'BENIGN' GROUP BY attack_type"""
    ).fetchall()
    attack_chart = [dict(r) for r in rows]

    recent = conn.execute(
        """SELECT a.id, a.attack_type, a.src_ip, a.severity, a.timestamp,
                  a.status, a.reason
           FROM alerts a ORDER BY a.id DESC LIMIT 8"""
    ).fetchall()

    conn.close()
    return {
        "total_traffic": total,
        "total_threats": threats,
        "critical_threats": critical,
        "suspicious_ips": suspicious_ips,
        "traffic_chart": traffic_chart,
        "attack_chart": attack_chart,
        "recent_alerts": [dict(r) for r in recent],
        "status": "MONITORING",
    }


@app.get("/api/traffic")
def get_traffic(limit: int = 200):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM traffic ORDER BY id DESC LIMIT ?", (min(limit, 500),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/simulate")
def simulate():
    records = _attack_records()
    results = [_process_record(r) for r in records]
    alerts = [r for r in results if r["alert_id"]]
    return {
        "generated": len(results),
        "alerts_created": len(alerts),
        "detections": {
            d: sum(1 for r in results if r["detection"] == d)
            for d in {r["detection"] for r in results}
        },
    }


@app.post("/api/upload")
async def upload_csv(file: UploadFile):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a valid .csv file")

    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not valid UTF-8 text")

    reader = csv.DictReader(io.StringIO(text))
    required = {"src_ip", "dst_ip", "protocol", "dst_port", "packet_size"}
    if not reader.fieldnames or not required.issubset({f.strip().lower() for f in reader.fieldnames}):
        raise HTTPException(
            status_code=400,
            detail="CSV must contain columns: src_ip, dst_ip, protocol, dst_port, packet_size",
        )

    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=400, detail="CSV file is empty")

    preview = rows[:10]
    results = []
    for row in rows[:100]:
        norm = {k.strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        try:
            rec = {
                "timestamp": norm.get("timestamp") or _ts(random.randint(0, 60)),
                "src_ip": norm["src_ip"],
                "dst_ip": norm["dst_ip"],
                "protocol": norm.get("protocol", "TCP") or "TCP",
                "src_port": int(norm["src_port"]) if norm.get("src_port") else None,
                "dst_port": int(norm["dst_port"]) if norm.get("dst_port") else None,
                "packet_size": int(norm["packet_size"]) if norm.get("packet_size") else None,
            }
        except (ValueError, KeyError):
            raise HTTPException(status_code=400, detail=f"Invalid row data: {row}")
        results.append(_process_record(rec))

    alerts = [r for r in results if r["alert_id"]]
    return {
        "preview": preview,
        "processed": len(results),
        "total_rows": len(rows),
        "skipped": max(0, len(rows) - 100),
        "alerts_created": len(alerts),
        "detections": [
            {
                "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "protocol": r["protocol"],
                "dst_port": r["dst_port"], "packet_size": r["packet_size"],
                "detection": r["detection"], "severity": r["severity"], "reason": r["reason"],
            }
            for r in results
        ],
    }


@app.get("/api/alerts")
def get_alerts(status: str | None = None):
    conn = get_db()
    if status and status.upper() in ALERT_STATUSES:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY id DESC", (status.upper(),)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate):
    conn = get_db()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    status = update.status.upper() if update.status else alert["status"]
    if status not in ALERT_STATUSES:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Invalid status. Use one of {sorted(ALERT_STATUSES)}")
    notes = update.notes if update.notes is not None else alert["notes"]

    conn.execute(
        "UPDATE alerts SET status = ?, notes = ? WHERE id = ?",
        (status, notes, alert_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return dict(row)
