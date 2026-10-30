"""
risk_engine.py - risk scoring, pattern classification and recommendations.

Everything here is a pure function (no database access), which keeps the
scoring logic easy to read, test and explain during a presentation.

Risk score = sum of weighted components, capped at 100:

  Password spraying / brute force (one source IP)
    Accounts targeted ........ up to 30   (more accounts -> more likely spraying)
    Failed attempts .......... up to 25   (relative to the failed-attempt threshold)
    Failure rate ............. up to 15   (failed / total attempts)
    Time concentration ....... up to 15   (all of it inside a short window)
    Behaviour pattern ........ up to 15   (matches a known attack shape)

  Distributed attack (many IPs -> one account)
    Distinct source IPs ...... up to 40
    Failed attempts .......... up to 25
    Failure rate ............. up to 15
    Time concentration ....... up to 10
    Behaviour pattern ........ up to 10
"""

MEDIUM_THRESHOLD = 30  # score at which activity becomes "Medium"

PATTERN_INFO = {
    "Password Spraying": (
        "One IP  ->  many accounts  ->  few attempts per account",
        "The attacker tries a handful of very common passwords against many "
        "different accounts. Because each account only sees one or two failures, "
        "normal account-lockout rules rarely trigger.",
    ),
    "Brute Force": (
        "One IP  ->  one account  ->  many attempts",
        "The attacker hammers a single account with a long list of password "
        "guesses. This is noisy and is usually stopped by lockouts or rate limits.",
    ),
    "Distributed Attack": (
        "Many IPs  ->  same account",
        "Several different source IPs (often a botnet) take turns attacking one "
        "account so that no single IP looks suspicious on its own.",
    ),
}


def level_for(score, settings=None):
    """Convert a 0-100 score into Low / Medium / High / Critical."""
    s = settings or {}
    high = s.get("high_threshold", 60)
    critical = s.get("critical_threshold", 80)
    if score >= critical:
        return "Critical"
    if score >= high:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def classify_pattern(accounts, failed, max_per_account, s):
    """Behavioural analysis: decide which attack shape the activity resembles."""
    if accounts >= s["min_accounts"]:
        return "Password Spraying"
    if accounts <= 2 and failed >= s["failed_threshold"]:
        return "Brute Force"
    if failed >= 5 and accounts >= 3:
        return "Suspicious Activity"
    return "Normal"


def _time_points(failed, span_min, window, max_pts):
    """The tighter the burst, the more suspicious it is."""
    if failed < 5:
        return 0.0
    if span_min <= window / 2:
        return float(max_pts)
    if span_min <= window:
        return max_pts * 2 / 3
    return max_pts * 0.27


def score_source(accounts, failed, attempts, span_min, max_per, pattern, s):
    """Score activity from ONE source IP. Returns (score, components, reasons)."""
    window = s["window_minutes"]
    thr = s["failed_threshold"]
    rate = failed / attempts if attempts else 0.0

    behaviour = {"Password Spraying": 15, "Brute Force": 12, "Suspicious Activity": 5}.get(pattern, 0)
    comps = {
        "Accounts targeted": [30 * min(1.0, accounts / 15), 30],
        "Failed attempts": [25 * min(1.0, failed / (2 * thr)), 25],
        "Failure rate": [15 * rate * min(1.0, failed / 5), 15],
        "Time concentration": [_time_points(failed, span_min, window, 15), 15],
        "Behaviour pattern": [behaviour, 15],
    }
    comps = {k: [round(v[0], 1), v[1]] for k, v in comps.items()}
    score = int(round(min(100, sum(v[0] for v in comps.values()))))

    reasons = []
    if accounts >= s["min_accounts"]:
        reasons.append(f"{accounts} unique accounts targeted from the same source")
    elif accounts > 1:
        reasons.append(f"{accounts} different accounts targeted")
    if failed >= thr:
        reasons.append(f"{failed} failed attempts (threshold: {thr})")
    elif failed >= 5:
        reasons.append(f"{failed} failed attempts")
    if rate >= 0.8 and failed >= 3:
        reasons.append(f"High failure rate ({rate:.0%} of attempts failed)")
    if failed >= 5 and span_min <= window:
        reasons.append(f"Activity concentrated inside {max(span_min, 0.1):.1f} minutes (window: {window} min)")
    if pattern == "Password Spraying" and max_per <= 3:
        reasons.append(f"Only {max_per} attempt(s) per account at most - typical of spraying to avoid lockouts")
    if pattern == "Brute Force":
        reasons.append(f"{max_per} repeated attempts against a single account")
    if not reasons:
        reasons.append("No notable risk factors")
    return score, comps, reasons


def score_distributed(ips, failed, attempts, span_min, s):
    """Score many-IPs -> one-account activity. Returns (score, components, reasons)."""
    window = s["window_minutes"]
    thr = s["failed_threshold"]
    rate = failed / attempts if attempts else 0.0
    comps = {
        "Distinct source IPs": [40 * min(1.0, ips / 8), 40],
        "Failed attempts": [25 * min(1.0, failed / (1.5 * thr)), 25],
        "Failure rate": [15 * rate, 15],
        "Time concentration": [_time_points(failed, span_min, window, 10), 10],
        "Behaviour pattern": [10, 10],
    }
    comps = {k: [round(v[0], 1), v[1]] for k, v in comps.items()}
    score = int(round(min(100, sum(v[0] for v in comps.values()))))
    reasons = [
        f"{ips} different IP addresses attacked the same account",
        f"{failed} failed attempts in total",
        f"Failure rate of {rate:.0%}",
        f"All activity happened within {max(span_min, 0.1):.1f} minutes (window: {window} min)",
        "Spreading attempts across IPs hides the attack from per-IP rules",
    ]
    return score, comps, reasons


def short_action(severity, pattern):
    """One-line recommended action stored on the incident."""
    if severity in ("Critical", "High"):
        return "Block IP + Protect Accounts"
    if severity == "Medium":
        return "Monitor IP + Enable Rate Limiting"
    return "Continue Monitoring"


def recommendations(severity, pattern):
    """Full recommendation list; it depends on the risk level and the pattern."""
    if severity in ("Critical", "High"):
        recs = [
            "Block the suspicious IP address(es)",
            "Temporarily protect the targeted accounts",
            "Enable login rate limiting",
            "Notify the administrator",
            "Continue monitoring the source IP",
        ]
        if severity == "Critical":
            recs.insert(3, "Force a password reset and review MFA for the affected accounts")
    elif severity == "Medium":
        recs = [
            "Place the source IP under close monitoring",
            "Enable login rate limiting",
            "Review recent activity on the targeted accounts",
            "Notify the administrator if the activity continues",
        ]
    else:
        recs = ["Continue routine monitoring - no action required yet"]

    extra = {
        "Password Spraying": "Check every targeted account for a successful login from this source",
        "Brute Force": "Lock the targeted account after repeated failures and require MFA",
        "Distributed Attack": "Require MFA on the targeted account and review all source IPs together",
    }.get(pattern)
    if extra and severity != "Low":
        recs.append(extra)
    return recs


def explain(pattern):
    """Plain-language 'Why was this detected?' text for each pattern."""
    texts = {
        "Password Spraying": (
            "Multiple accounts were targeted from the same source within a short time period.",
            "The system observed multiple failed login attempts from the same IP address "
            "against several different user accounts within a short period. Each account "
            "received only a few attempts, which is how attackers avoid account lockouts. "
            "This behavior matches a password-spraying pattern.",
        ),
        "Brute Force": (
            "One account received a large number of failed attempts from a single source.",
            "The system observed many failed login attempts from one IP address against "
            "one account. Repeatedly guessing passwords for the same account matches a "
            "brute-force pattern.",
        ),
        "Distributed Attack": (
            "Many different IP addresses attacked the same account at the same time.",
            "The system observed failed logins against one account coming from several "
            "different IP addresses within a short period. Attackers spread attempts over "
            "many IPs so that no single IP looks suspicious. This matches a distributed attack.",
        ),
    }
    return texts.get(pattern, (
        "Unusual login failures were observed.",
        "The activity shows more failures than normal but does not yet match a known attack pattern.",
    ))
