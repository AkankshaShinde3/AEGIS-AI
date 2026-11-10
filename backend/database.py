import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "database.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            packet_size INTEGER,
            detection TEXT,
            severity TEXT,
            reason TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_id INTEGER NOT NULL,
            attack_type TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'NEW',
            notes TEXT,
            FOREIGN KEY (traffic_id) REFERENCES traffic(id)
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic(src_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        """
    )
    conn.commit()
    conn.close()
