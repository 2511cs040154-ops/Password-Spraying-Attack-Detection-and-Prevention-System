# Password Spray Sentinel
**Password Spraying Detection and Prevention System** - a SOC-style dashboard for a college cybersecurity project.

> **Safe by design.** Only synthetic usernames, synthetic IPs and a local SQLite file are used. No real website, login system or account is contacted, no attack is performed, and passwords are never stored or displayed. Blocking an IP or protecting an account only updates the local database.

## Run it
```bash
pip install -r requirements.txt
streamlit run app.py
```
The first launch creates `data/password_sentinel.db` and fills it with a demo dataset. Use **Settings > Reset demo data** just before presenting so timestamps are fresh.

## Files
| File | Role |
|---|---|
| `app.py` | Streamlit UI: 9 pages, theme, charts, buttons |
| `database.py` | SQLite schema, settings, simulated block/protect actions |
| `detection.py` | Sliding-window behavioural analysis, incidents, alerts, auto-response |
| `risk_engine.py` | 0-100 risk scoring, pattern classification, recommendations, explanations |
| `simulation.py` | Demo dataset and the "Run Attack Simulation" scenarios |
| `.streamlit/config.toml` | Dark theme, telemetry off |

## How detection works (for your presentation)
1. For each source IP, slide a time window (default 5 min) over its failed logins and keep the busiest window.
2. **Classify the pattern:** many accounts + few tries each = *password spraying*; one account + many tries = *brute force*; many IPs + one account = *distributed attack*.
3. **Score 0-100** from: accounts targeted (30), failed attempts (25), failure rate (15), time concentration (15), behaviour pattern (15). Levels: 0-29 Low, 30-59 Medium, 60-79 High, 80+ Critical (High/Critical thresholds are configurable).
4. Scores of 30+ with a known attack pattern become **incidents**, with reasons, recommendations and alerts.
5. Prevention toggles change behaviour: e.g. *Automatic IP Blocking* blocks the source of every new High/Critical incident.

## Demo script
1. Dashboard: status is PROTECTED, KPIs and alerts come from the database.
2. Sidebar: **Run Attack Simulation** (password spraying). Status flips to UNDER ATTACK.
3. Incidents: open the new incident and read **Why was this detected?** and the recommendations.
4. Click **Apply recommended response**: IP blocked, accounts protected, status back to PROTECTED.
5. Prevention: turn on automatic blocking, run another simulation, see it handled automatically.
6. Settings: lower the minimum accounts and watch detection change.
