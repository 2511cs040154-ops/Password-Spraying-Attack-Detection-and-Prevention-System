"""
detection.py - behavioural detection engine.

Reads login events from SQLite, looks for attack shapes (spraying, brute force,
distributed), scores them with risk_engine, then updates incidents, IP monitoring,
account protection and alerts. Settings are read from the database on every run.
"""
import json

import pandas as pd

import database as db
import risk_engine as risk

DIST_MIN_IPS = 4  # distinct IPs against one account before we call it "distributed"
INCIDENT_PATTERNS = ("Password Spraying", "Brute Force", "Distributed Attack")


def load_events(conn=None):
    df = db.read_df(
        "SELECT id, timestamp, username, source_ip, success, risk_score, event_type "
        "FROM login_events ORDER BY timestamp, id", conn=conn)
    df["ts"] = pd.to_datetime(df["timestamp"])
    return df


def _best_window(fails, window_min, key_col):
    """Slide a time window over failures; keep the one touching the most distinct `key_col` values."""
    fails = fails.sort_values(["ts", "id"]).reset_index(drop=True)
    times, keys = fails["ts"].tolist(), fails[key_col].tolist()
    n, j, best = len(times), 0, None
    for i in range(n):
        while j < n and (times[j] - times[i]).total_seconds() <= window_min * 60:
            j += 1
        cand = (len(set(keys[i:j])), j - i, i, j)
        if best is None or cand[:2] > best[:2]:
            best = cand
    return fails.iloc[best[2]:best[3]]


def analyze_sources(events, s):
    """One result per source IP that has failures (password spraying / brute force view)."""
    results = []
    for ip, g in events.groupby("source_ip"):
        fails = g[g["success"] == 0]
        if fails.empty:
            continue
        w = _best_window(fails, s["window_minutes"], "username")
        start, end = w["ts"].min(), w["ts"].max()
        attempts = int(((g["ts"] >= start) & (g["ts"] <= end)).sum())
        per = w["username"].value_counts()
        failed, accounts, max_per = len(w), len(per), int(per.max())
        span = (end - start).total_seconds() / 60
        pattern = risk.classify_pattern(accounts, failed, max_per, s)
        score, comps, reasons = risk.score_source(accounts, failed, attempts, span, max_per, pattern, s)
        results.append({
            "kind": "source", "key": ip, "source_ip": ip, "ip_list": [ip], "pattern": pattern,
            "accounts": accounts, "users": sorted(per.index.tolist()),
            "attempts_by_user": {k: int(v) for k, v in per.items()},
            "failed": failed, "attempts": attempts, "failure_rate": failed / attempts if attempts else 0.0,
            "span_min": span, "max_per_account": max_per, "score": score,
            "level": risk.level_for(score, s), "components": comps, "reasons": reasons,
            "window_start": start, "window_end": end, "total_failed": len(fails),
            "event_ids": [int(x) for x in w["id"]],
        })
    return results


def analyze_distributed(events, s):
    """Many IPs -> same account."""
    results = []
    for user, g in events.groupby("username"):
        fails = g[g["success"] == 0]
        if fails["source_ip"].nunique() < DIST_MIN_IPS:
            continue
        w = _best_window(fails, s["window_minutes"], "source_ip")
        ips = sorted(w["source_ip"].unique().tolist())
        if len(ips) < DIST_MIN_IPS:
            continue
        start, end = w["ts"].min(), w["ts"].max()
        attempts = int(((g["ts"] >= start) & (g["ts"] <= end) & g["source_ip"].isin(ips)).sum())
        failed, span = len(w), (end - start).total_seconds() / 60
        score, comps, reasons = risk.score_distributed(len(ips), failed, attempts, span, s)
        results.append({
            "kind": "distributed", "key": f"DIST|{user}", "source_ip": f"Multiple IPs ({len(ips)})",
            "ip_list": ips, "pattern": "Distributed Attack", "accounts": 1, "users": [user],
            "attempts_by_user": {user: failed}, "failed": failed, "attempts": attempts,
            "failure_rate": failed / attempts if attempts else 0.0, "span_min": span,
            "max_per_account": failed, "score": score, "level": risk.level_for(score, s),
            "components": comps, "reasons": reasons, "window_start": start, "window_end": end,
            "total_failed": len(fails), "event_ids": [int(x) for x in w["id"]],
        })
    return results


def analyze_events(events, s):
    """Pure analysis (no database writes). Sorted by risk, highest first."""
    return sorted(analyze_sources(events, s) + analyze_distributed(events, s),
                  key=lambda a: a["score"], reverse=True)


# ------------------------------------------------------------ DB updates
def _event_risk(events, src, dist):
    by_ip = {a["source_ip"]: a["score"] for a in src}
    out = {}
    for eid, ip, ok in zip(events["id"], events["source_ip"], events["success"]):
        sc = by_ip.get(ip, 0)
        out[int(eid)] = int(sc) if ok == 0 else int(round(sc * 0.3))
    for a in dist:
        for eid in a["event_ids"]:
            out[eid] = max(out.get(eid, 0), a["score"])
    return out


def _upsert_incidents(conn, analyses):
    new = []
    for a in analyses:
        if a["pattern"] not in INCIDENT_PATTERNS or a["score"] < risk.MEDIUM_THRESHOLD:
            continue
        fp = a["key"] if a["kind"] == "distributed" else f"{a['key']}|{a['pattern']}"
        action = risk.short_action(a["level"], a["pattern"])
        common = (a["source_ip"], a["pattern"], a["accounts"], a["failed"], a["score"], a["level"], action,
                  json.dumps(a["ip_list"]), json.dumps(a["users"]), json.dumps(a["reasons"]),
                  json.dumps(a["components"]), a["window_start"].strftime(db.TS_FMT),
                  a["window_end"].strftime(db.TS_FMT), round(a["span_min"], 2), round(a["failure_rate"], 3))
        row = conn.execute("SELECT incident_id FROM incidents WHERE fingerprint=?", (fp,)).fetchone()
        if row:  # re-scored with current settings; status is kept
            conn.execute(
                "UPDATE incidents SET source_ip=?, attack_type=?, accounts_targeted=?, failed_attempts=?, "
                "risk_score=?, severity=?, recommended_action=?, ip_list=?, targeted_users=?, reasons=?, "
                "components=?, window_start=?, window_end=?, span_minutes=?, failure_rate=? "
                "WHERE fingerprint=?", common + (fp,))
        else:
            n = conn.execute("SELECT MAX(CAST(SUBSTR(incident_id,5) AS INTEGER)) FROM incidents").fetchone()[0] or 0
            iid = f"INC-{n + 1:03d}"
            conn.execute(
                "INSERT INTO incidents(incident_id, timestamp, source_ip, attack_type, accounts_targeted, "
                "failed_attempts, risk_score, severity, status, recommended_action, fingerprint, ip_list, "
                "targeted_users, reasons, components, window_start, window_end, span_minutes, failure_rate) "
                "VALUES (?,?,?,?,?,?,?,?,'Open',?,?,?,?,?,?,?,?,?,?)",
                (iid, a["window_end"].strftime(db.TS_FMT)) + common[:7 - 0][0:7] + (fp,) + common[7:])
            new.append({"incident_id": iid, "timestamp": a["window_end"].strftime(db.TS_FMT), **a,
                        "severity": a["level"], "action": action})
    return new


def _update_ip_monitoring(conn, events, src, dist):
    best = {a["source_ip"]: a["score"] for a in src}
    boost = {}
    for a in dist:  # IPs inside a distributed attack inherit part of its risk
        for ip in a["ip_list"]:
            boost[ip] = max(boost.get(ip, 0), int(round(a["score"] * 0.6)))
    for ip, g in events.groupby("source_ip"):
        f = g[g["success"] == 0]
        sc = max(best.get(ip, 0), boost.get(ip, 0))
        status = "Suspicious" if sc >= risk.MEDIUM_THRESHOLD else "Normal"
        conn.execute(
            "INSERT INTO ip_monitoring(ip_address, failed_attempts, accounts_targeted, risk_score, status, last_activity) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(ip_address) DO UPDATE SET failed_attempts=excluded.failed_attempts, "
            "accounts_targeted=excluded.accounts_targeted, risk_score=excluded.risk_score, "
            "last_activity=excluded.last_activity, "
            "status=CASE WHEN ip_monitoring.status='Blocked' THEN 'Blocked' ELSE excluded.status END",
            (ip, len(f), int(f["username"].nunique()), int(sc), status, g["timestamp"].max()))


def _update_accounts(conn, events, event_risk):
    for user, g in events.groupby("username"):
        f = g[g["success"] == 0]
        sc = max([event_risk.get(int(i), 0) for i in f["id"]], default=0)
        flagged = sc >= risk.MEDIUM_THRESHOLD
        status = "Monitored" if flagged else "Normal"
        reason = f"Targeted by suspicious login activity (risk {sc})" if flagged else "No suspicious activity"
        conn.execute(
            "INSERT INTO account_protection(username, failed_attempts, risk_score, protection_status, last_activity, reason) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET failed_attempts=excluded.failed_attempts, "
            "risk_score=excluded.risk_score, last_activity=excluded.last_activity, "
            "protection_status=CASE WHEN account_protection.protection_status='Temporarily Protected' "
            "THEN 'Temporarily Protected' ELSE excluded.protection_status END, "
            "reason=CASE WHEN account_protection.protection_status='Temporarily Protected' "
            "THEN account_protection.reason ELSE excluded.reason END",
            (user, len(f), int(sc), status, g["timestamp"].max(), reason))


def _respond(conn, new_incidents, s):
    """Alerts + automatic (simulated) prevention for brand-new incidents."""
    for inc in new_incidents:
        sev, ip = inc["severity"], inc["source_ip"]
        db.add_alert(
            sev.upper(), f"{sev.upper()}-RISK {inc['pattern'].upper()} DETECTED",
            f"Source IP: {ip}\nAccounts Targeted: {inc['accounts']}\nFailed Attempts: {inc['failed']}\n"
            f"Risk Score: {inc['score']}\nRecommended Action: {inc['action']}",
            ip, inc["incident_id"], ts=inc["timestamp"], conn=conn)
        if sev not in ("High", "Critical"):
            continue
        done = 0
        if s["auto_block"]:
            for x in inc["ip_list"]:
                db.block_ip(x, f"Automatic block ({inc['incident_id']})", alert=False, conn=conn)
            db.add_alert("INFO", "Automatic IP blocking", f"{len(inc['ip_list'])} IP(s) blocked for {inc['incident_id']}.",
                         ip, inc["incident_id"], conn=conn)
            done += 1
        if s["auto_protect"] and s["account_protection"]:
            for u in inc["users"]:
                db.protect_account(u, f"Automatic protection ({inc['incident_id']})", alert=False, conn=conn)
            db.add_alert("INFO", "Automatic account protection",
                         f"{len(inc['users'])} account(s) protected for {inc['incident_id']}.",
                         ip, inc["incident_id"], conn=conn)
            done += 1
        if done:
            db.update_incident_status(inc["incident_id"], "Mitigated" if done == 2 else "Investigating", conn=conn)


def run_detection(respond=True):
    """Analyse every stored event and refresh all derived tables."""
    s = db.get_settings()
    with db.session() as conn:
        events = load_events(conn)
        if events.empty:
            return {"new_incidents": [], "analyses": []}
        src, dist = analyze_sources(events, s), analyze_distributed(events, s)
        ev_risk = _event_risk(events, src, dist)
        conn.executemany("UPDATE login_events SET risk_score=? WHERE id=?", [(v, k) for k, v in ev_risk.items()])
        new = _upsert_incidents(conn, src + dist)
        if s["ip_monitoring"]:
            _update_ip_monitoring(conn, events, src, dist)
        _update_accounts(conn, events, ev_risk)
        if respond:
            _respond(conn, new, s)
    return {"new_incidents": new, "analyses": sorted(src + dist, key=lambda a: -a["score"])}


def apply_response(incident_id):
    """'Apply recommended response': block the IP(s), protect accounts, mark Mitigated."""
    s = db.get_settings()
    inc = db.read_df("SELECT * FROM incidents WHERE incident_id=?", (incident_id,))
    if inc.empty:
        return "Incident not found."
    inc = inc.iloc[0]
    ips, users = json.loads(inc["ip_list"]), json.loads(inc["targeted_users"])
    with db.session() as conn:
        for ip in ips:
            db.block_ip(ip, f"Response to {incident_id}", alert=False, conn=conn)
        parts = [f"blocked {len(ips)} IP(s)"]
        if s["account_protection"]:
            for u in users:
                db.protect_account(u, f"Targeted in {incident_id} ({inc['attack_type']})", alert=False, conn=conn)
            parts.append(f"protected {len(users)} account(s)")
        else:
            parts.append("account protection is disabled in Prevention settings, so accounts were not changed")
        db.update_incident_status(incident_id, "Mitigated", conn=conn)
        text = f"Response applied to {incident_id}: " + ", ".join(parts) + "."
        db.add_alert("INFO", f"Response applied to {incident_id}", text, inc["source_ip"], incident_id, conn=conn)
    return text
