"""
database.py - SQLite storage layer for Password Spray Sentinel.

Only synthetic data is ever stored. Passwords are never stored or handled.
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).resolve().parent / "data" / "password_sentinel.db"
TS_FMT = "%Y-%m-%d %H:%M:%S"

DEFAULT_SETTINGS = {
    # detection thresholds
    "window_minutes": 5,
    "min_accounts": 5,
    "failed_threshold": 10,
    "high_threshold": 60,
    "critical_threshold": 80,
    # prevention controls (1 = on, 0 = off)
    "rate_limiting": 1,
    "account_protection": 1,
    "ip_monitoring": 1,
    "admin_alerts": 1,
    "auto_block": 0,
    "auto_protect": 0,
}
BOOL_KEYS = {"rate_limiting", "account_protection", "ip_monitoring",
             "admin_alerts", "auto_block", "auto_protect"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    success INTEGER NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    event_type TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON login_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON login_events(source_ip);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    timestamp TEXT,
    source_ip TEXT,
    attack_type TEXT,
    accounts_targeted INTEGER,
    failed_attempts INTEGER,
    risk_score INTEGER,
    severity TEXT,
    status TEXT DEFAULT 'Open',
    recommended_action TEXT,
    fingerprint TEXT UNIQUE,
    ip_list TEXT,
    targeted_users TEXT,
    reasons TEXT,
    components TEXT,
    window_start TEXT,
    window_end TEXT,
    span_minutes REAL,
    failure_rate REAL
);

CREATE TABLE IF NOT EXISTS ip_monitoring (
    ip_address TEXT PRIMARY KEY,
    failed_attempts INTEGER,
    accounts_targeted INTEGER,
    risk_score INTEGER,
    status TEXT,
    last_activity TEXT
);

CREATE TABLE IF NOT EXISTS account_protection (
    username TEXT PRIMARY KEY,
    failed_attempts INTEGER,
    risk_score INTEGER,
    protection_status TEXT,
    last_activity TEXT,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    level TEXT,
    title TEXT,
    message TEXT,
    source_ip TEXT,
    incident_id TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def now_str():
    return datetime.now().strftime(TS_FMT)


@contextmanager
def session(conn=None):
    """Yield a connection. Commits/closes only if this call opened it."""
    own = conn is None
    if own:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        yield conn
        if own:
            conn.commit()
    except Exception:
        if own:
            conn.rollback()
        raise
    finally:
        if own:
            conn.close()


def init_db():
    with session() as conn:
        conn.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, str(v)))


def read_df(sql, params=(), conn=None):
    with session(conn) as c:
        return pd.read_sql_query(sql, c, params=params)


# ---------------------------------------------------------------- settings
def get_settings(conn=None):
    with session(conn) as c:
        rows = c.execute("SELECT key, value FROM settings").fetchall()
    out = dict(DEFAULT_SETTINGS)
    for k, v in rows:
        if k in DEFAULT_SETTINGS:
            out[k] = int(float(v))
    for k in BOOL_KEYS:
        out[k] = bool(out[k])
    return out


def set_setting(key, value, conn=None):
    with session(conn) as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, str(int(value))))


# ------------------------------------------------------------------ alerts
def add_alert(level, title, message, source_ip="", incident_id="", ts=None, conn=None, force=False):
    """Create an administrator alert (skipped when 'Administrator Alerts' is off)."""
    with session(conn) as c:
        if not force and not get_settings(c)["admin_alerts"]:
            return
        c.execute(
            "INSERT INTO alerts(timestamp, level, title, message, source_ip, incident_id) VALUES (?,?,?,?,?,?)",
            (ts or now_str(), level, title, message, source_ip, incident_id),
        )


# ----------------------------------------------------------------- events
def insert_events(rows, conn=None):
    """rows: iterable of (timestamp, username, source_ip, success, event_type)."""
    with session(conn) as c:
        c.executemany(
            "INSERT INTO login_events(timestamp, username, source_ip, success, risk_score, event_type) "
            "VALUES (?,?,?,?,0,?)",
            list(rows),
        )


# ------------------------------------------------------ simulated responses
def block_ip(ip, reason="Blocked by administrator", ts=None, alert=True, conn=None):
    with session(conn) as c:
        c.execute(
            "INSERT INTO ip_monitoring(ip_address, failed_attempts, accounts_targeted, risk_score, status, last_activity) "
            "VALUES (?,0,0,0,'Blocked',?) ON CONFLICT(ip_address) DO UPDATE SET status='Blocked'",
            (ip, ts or now_str()),
        )
        msg = f"IP {ip} has been blocked by the prevention engine."
        if alert:
            add_alert("INFO", "IP blocked", f"{msg} Reason: {reason}", ip, ts=ts, conn=c)
    return msg


def unblock_ip(ip, conn=None):
    with session(conn) as c:
        c.execute(
            "UPDATE ip_monitoring SET status = CASE WHEN risk_score >= 30 THEN 'Suspicious' ELSE 'Normal' END "
            "WHERE ip_address = ?", (ip,))
    return f"IP {ip} has been unblocked and returned to monitoring."


def protect_account(username, reason="Protected by administrator", ts=None, alert=True, conn=None):
    with session(conn) as c:
        c.execute(
            "INSERT INTO account_protection(username, failed_attempts, risk_score, protection_status, last_activity, reason) "
            "VALUES (?,0,0,'Temporarily Protected',?,?) "
            "ON CONFLICT(username) DO UPDATE SET protection_status='Temporarily Protected', reason=excluded.reason",
            (username, ts or now_str(), reason),
        )
        if alert:
            add_alert("INFO", "Account protected", f"Account protection enabled for {username}. Reason: {reason}",
                      ts=ts, conn=c)
    return f"Account protection enabled for {username}."


def unprotect_account(username, conn=None):
    with session(conn) as c:
        c.execute(
            "UPDATE account_protection SET protection_status = "
            "CASE WHEN risk_score >= 30 THEN 'Monitored' ELSE 'Normal' END, "
            "reason = 'Protection removed by administrator' WHERE username = ?", (username,))
    return f"Account protection removed for {username}."


def update_incident_status(incident_id, status, conn=None):
    with session(conn) as c:
        c.execute("UPDATE incidents SET status=? WHERE incident_id=?", (status, incident_id))


def clear_all(conn=None):
    """Wipe all demo data and restore default settings."""
    with session(conn) as c:
        for t in ("login_events", "incidents", "ip_monitoring", "account_protection", "alerts", "settings"):
            c.execute(f"DELETE FROM {t}")
        try:
            c.execute("DELETE FROM sqlite_sequence")
        except sqlite3.OperationalError:
            pass
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT INTO settings(key, value) VALUES (?, ?)", (k, str(v)))
