"""
simulation.py - SAFE synthetic data: demo dataset + attack simulations.

Nothing here touches a real login system, website, account or network.
It only writes made-up usernames and made-up IPs into the local SQLite file.
"""
import random
from datetime import datetime, timedelta

import database as db
import detection

USERS = [f"user_{i:02d}" for i in range(1, 31)]
SPECIAL_USERS = ["admin_01", "admin_02", "finance_01", "hr_01"]
NORMAL_IPS = [f"10.0.1.{i}" for i in range(11, 29)]

SCENARIOS = {
    "Password spraying (critical)": "spray",
    "Low-and-slow spraying (medium)": "slow",
    "Brute force on one account": "brute",
    "Distributed attack (many IPs)": "distributed",
}


def _ts(dt):
    return dt.strftime(db.TS_FMT)


def _fail(dt, user, ip):
    return (_ts(dt), user, ip, 0, "Login Failure")


def _ok(dt, user, ip):
    return (_ts(dt), user, ip, 1, "Login Success")


def _burst(rows, start, user_attempts, ip, seconds, success_user=None):
    """Spread failed attempts evenly across `seconds`; optionally end with one success."""
    n = len(user_attempts)
    step = seconds / max(n, 1)
    for i, u in enumerate(user_attempts):
        rows.append(_fail(start + timedelta(seconds=i * step), u, ip))
    if success_user:
        rows.append(_ok(start + timedelta(seconds=seconds + 8), success_user, ip))


def _spray_attempts(users, failed):
    """First pass: one attempt per account. Remaining attempts: a second password on some accounts."""
    seq = list(users) + list(users)[: max(0, failed - len(users))]
    return seq[:failed]


def seed_demo_data():
    """Deterministic demo dataset (timestamps are anchored to 'now')."""
    db.init_db()
    rng = random.Random(42)
    now = datetime.now().replace(microsecond=0)
    rows = []

    # --- normal activity: ~24h of ordinary logins, with a few typos -----------
    people = USERS + SPECIAL_USERS
    home = {u: NORMAL_IPS[i % len(NORMAL_IPS)] for i, u in enumerate(people)}
    for _ in range(190):
        u = rng.choice(people)
        t = now - timedelta(minutes=rng.randint(25, 1430), seconds=rng.randint(0, 59))
        ip = home[u]
        r = rng.random()
        if r < 0.10:                       # typo, then success
            rows.append(_fail(t, u, ip))
            rows.append(_ok(t + timedelta(seconds=rng.randint(15, 60)), u, ip))
        elif r < 0.12:                     # forgot password: two failures, then success
            rows.append(_fail(t, u, ip))
            rows.append(_fail(t + timedelta(seconds=20), u, ip))
            rows.append(_ok(t + timedelta(seconds=75), u, ip))
        else:
            rows.append(_ok(t, u, ip))
    for k in range(5):                     # lone failures (no follow-up)
        u = people[k * 5]
        rows.append(_fail(now - timedelta(minutes=100 + k * 170), u, home[u]))

    # --- unusual but not an incident ------------------------------------------
    t = now - timedelta(hours=2, minutes=20)
    _burst(rows, t, ["user_25", "user_26", "user_27", "user_28", "user_25"], "10.0.2.45", 200, "user_27")
    _burst(rows, now - timedelta(hours=9), ["user_08"] * 3, "192.0.2.77", 90, "user_08")

    # --- attacks ---------------------------------------------------------------
    # A) CRITICAL password spraying: 14 accounts, 21 failures, 1 success
    _burst(rows, now - timedelta(minutes=38), _spray_attempts(USERS[:14], 21), "192.168.1.50", 230, "user_05")
    # B) HIGH password spraying
    _burst(rows, now - timedelta(hours=3, minutes=10), _spray_attempts(USERS[14:22], 12), "203.0.113.45", 270, "user_20")
    # C) MEDIUM low-and-slow spraying
    _burst(rows, now - timedelta(hours=7), _spray_attempts(USERS[25:30], 6), "172.16.8.31", 240, "user_28")
    # D) MEDIUM brute force on one account
    _burst(rows, now - timedelta(hours=5, minutes=20), ["user_14"] * 13, "198.51.100.23", 230)
    # E) HIGH distributed attack on admin_01 from 5 IPs
    t = now - timedelta(hours=1, minutes=45)
    for i, (ip, n) in enumerate(zip([f"198.51.100.{x}" for x in range(11, 16)], [2, 2, 2, 2, 1])):
        for k in range(n):
            rows.append(_fail(t + timedelta(seconds=i * 50 + k * 20), "admin_01", ip))
    # F) older HIGH spray (already mitigated)
    _burst(rows, now - timedelta(hours=20, minutes=30), _spray_attempts(USERS[:9], 14), "198.51.100.200", 260)
    # G) older MEDIUM spray (resolved)
    _burst(rows, now - timedelta(hours=15), _spray_attempts(USERS[9:15], 7), "172.16.9.8", 240, "user_12")

    db.insert_events(rows)
    db.add_alert("INFO", "Detection engine started", "Password Spray Sentinel is analysing login events.",
                 ts=_ts(now - timedelta(hours=24)), force=True)

    result = detection.run_detection(respond=True)  # auto-response toggles are OFF by default
    by_ip = {i["source_ip"]: i for i in result["new_incidents"]}

    # Pre-applied responses so the demo already shows blocked IPs and protected accounts
    def at(ip, minutes=1):
        return _ts(datetime.strptime(by_ip[ip]["timestamp"], db.TS_FMT) + timedelta(minutes=minutes))

    a, b, f_, e = by_ip["192.168.1.50"], by_ip["203.0.113.45"], by_ip["198.51.100.200"], None
    for inc, status in ((a, "Investigating"), (b, "Investigating"), (f_, "Mitigated")):
        db.block_ip(inc["source_ip"], f"Response to {inc['incident_id']}", ts=at(inc["source_ip"]))
        db.update_incident_status(inc["incident_id"], status)
    for u in USERS[:8]:
        db.protect_account(u, f"Targeted in {a['incident_id']} (Password Spraying)",
                           ts=at("192.168.1.50", 2), alert=False)
    db.add_alert("INFO", "Accounts protected", f"8 accounts protected for {a['incident_id']}.",
                 "192.168.1.50", a["incident_id"], ts=at("192.168.1.50", 2))
    dist = [i for i in result["new_incidents"] if i["pattern"] == "Distributed Attack"][0]
    db.update_incident_status(dist["incident_id"], "Investigating")
    db.protect_account("admin_01", f"Targeted in {dist['incident_id']} (Distributed Attack)",
                       ts=_ts(datetime.strptime(dist["timestamp"], db.TS_FMT) + timedelta(minutes=1)))
    old = by_ip["172.16.9.8"]
    db.update_incident_status(old["incident_id"], "Resolved")
    db.add_alert("LOW", "Unusual login failures",
                 "Source IP: 10.0.2.45\n5 failures across 4 accounts - below incident threshold, monitoring.",
                 "10.0.2.45", ts=_ts(now - timedelta(hours=2, minutes=15)), force=True)
    detection.run_detection(respond=False)  # refresh derived tables after state changes


def ensure_demo_data():
    db.init_db()
    if db.read_df("SELECT COUNT(*) AS n FROM login_events").iloc[0]["n"] == 0:
        seed_demo_data()


def reset_demo_data():
    db.init_db()
    db.clear_all()
    seed_demo_data()


# ---------------------------------------------------------------- simulation
def _free_ip():
    n = 99
    while not db.read_df("SELECT 1 FROM login_events WHERE source_ip=? LIMIT 1", (f"192.168.1.{n}",)).empty:
        n += 1
    return f"192.168.1.{n}"


def run_attack_simulation(scenario="Password spraying (critical)"):
    """Insert a synthetic attack into the local DB, analyse it, and return a report."""
    kind = SCENARIOS.get(scenario, "spray")
    s = db.get_settings()
    n_prev = int(db.read_df("SELECT COUNT(*) AS n FROM incidents").iloc[0]["n"])
    rng = random.Random(1000 + n_prev)
    now = datetime.now().replace(microsecond=0)
    rows, ips = [], []

    if kind == "spray":
        ip, users, failed, secs = _free_ip(), sorted(rng.sample(USERS, 12)), 18, 140
        start = now - timedelta(seconds=secs + 8)
        _burst(rows, start, _spray_attempts(users, failed), ip, secs, users[3])
        label, target_users, key, fp = ip, users, ip, f"{ip}|Password Spraying"
    elif kind == "slow":
        ip, users, failed, secs = _free_ip(), sorted(rng.sample(USERS, 5)), 6, 250
        start = now - timedelta(seconds=secs + 8)
        _burst(rows, start, _spray_attempts(users, failed), ip, secs, users[0])
        label, target_users, key, fp = ip, users, ip, f"{ip}|Password Spraying"
    elif kind == "brute":
        ip, user, failed, secs = _free_ip(), rng.choice(USERS), 20, 170
        start = now - timedelta(seconds=secs + 2)
        _burst(rows, start, [user] * failed, ip, secs)
        label, target_users, users, key, fp = ip, [user], [user], ip, f"{ip}|Brute Force"
    else:
        user = rng.choice(SPECIAL_USERS + USERS[:10])
        ips = [_free_ip()]
        base = 150
        while len(ips) < 6:
            ips.append(f"192.168.1.{base + len(ips)}")
        failed, secs = 12, 200
        start = now - timedelta(seconds=secs + 2)
        for i in range(failed):
            rows.append(_fail(start + timedelta(seconds=i * secs / failed), user, ips[i % 6]))
        label, target_users, users, key, fp = f"{len(ips)} IPs", [user], [user], f"DIST|{user}", f"DIST|{user}"

    db.insert_events(rows)
    result = detection.run_detection(respond=True)
    found = next((a for a in result["analyses"] if a["key"] == key), None)
    inc = None
    if found:
        sev = db.read_df("SELECT * FROM incidents WHERE fingerprint=?", (fp,))
        inc = sev.iloc[0].to_dict() if not sev.empty else None
    throttled = max(0, found["failed"] - s["failed_threshold"]) if (found and s["rate_limiting"]) else 0

    steps = [
        f"Simulation started - scenario: {scenario}",
        f"Simulated source: {label}",
        f"Accounts targeted: {len(target_users)}",
        f"Failed attempts: {found['failed'] if found else len(rows)}",
        "Analyzing behavior...",
    ]
    if found:
        steps.append(f"Pattern detected: {found['pattern']}" if found["pattern"] != "Normal" else "No attack pattern matched")
        steps.append(f"Risk score: {found['score']}/100   Severity: {found['level'].upper()}")
    if inc:
        steps.append(f"Incident {inc['incident_id']} created automatically ({inc['recommended_action']})")
    else:
        steps.append("No incident created - risk is below the Medium threshold for the current settings")
    if throttled:
        steps.append(f"Rate limiting would have throttled {throttled} of the simulated attempts")
    return {"steps": steps, "incident": inc, "analysis": found, "score": found["score"] if found else 0,
            "severity": found["level"] if found else "Low"}
