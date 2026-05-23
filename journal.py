"""
NetGuard v3 — Журнал событий (SQLite)
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

DB_PATH = Path("/data/netguard.db")
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT    NOT NULL,
                type     TEXT    NOT NULL,
                src_ip   TEXT,
                dst_ip   TEXT,
                dst_port TEXT,
                proto    TEXT,
                descr    TEXT,
                blocked  INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT    UNIQUE NOT NULL,
                reason     TEXT,
                blocked_at TEXT    NOT NULL,
                auto       INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        """)


def log_event(type_: str, src_ip: str, dst_ip: str, dst_port: str,
              proto: str, descr: str, blocked: bool = False) -> int:
    with _lock, _conn() as conn:
        cur = conn.execute(
            "INSERT INTO events (ts,type,src_ip,dst_ip,dst_port,proto,descr,blocked) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now().isoformat(), type_, src_ip, dst_ip,
             dst_port, proto, descr, int(blocked))
        )
        return cur.lastrowid


def get_recent_events(limit: int = 10) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT ts,type,src_ip,dst_ip,dst_port,proto,descr,blocked "
            "FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    keys = ["ts", "type", "src_ip", "dst_ip", "dst_port", "proto", "descr", "blocked"]
    return [dict(zip(keys, r)) for r in rows]


def get_stats() -> dict:
    with _conn() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        snort   = conn.execute("SELECT COUNT(*) FROM events WHERE type='snort'").fetchone()[0]
        ipt     = conn.execute("SELECT COUNT(*) FROM events WHERE type='iptables'").fetchone()[0]
        manual  = conn.execute("SELECT COUNT(*) FROM events WHERE type='manual'").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        today   = conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts >= date('now')"
        ).fetchone()[0]
    return {
        "total": total, "snort": snort, "iptables": ipt,
        "manual": manual, "blocked_ips": blocked, "today": today
    }


def get_blocked_ips() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT ip, reason, blocked_at, auto FROM blocked_ips ORDER BY id DESC"
        ).fetchall()
    return [dict(zip(["ip", "reason", "blocked_at", "auto"], r)) for r in rows]


def add_blocked_ip(ip: str, reason: str, auto: bool = False):
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip,reason,blocked_at,auto) VALUES (?,?,?,?)",
            (ip, reason, datetime.now().isoformat(), int(auto))
        )


def remove_blocked_ip(ip: str):
    with _lock, _conn() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))


def is_blocked(ip: str) -> bool:
    with _conn() as conn:
        return conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)
        ).fetchone() is not None


def get_ip_event_count(ip: str, window_sec: int = 300) -> int:
    with _conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM events WHERE src_ip=? "
            "AND ts >= datetime('now', ? || ' seconds')",
            (ip, f"-{window_sec}")
        ).fetchone()[0]
