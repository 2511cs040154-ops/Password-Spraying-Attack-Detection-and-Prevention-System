"""
Password Spray Sentinel - Password Spraying Detection and Prevention System.
Run with:  streamlit run app.py

SAFE DEMO: only synthetic users, synthetic IPs and a local SQLite file are used.
No real login system is contacted and no passwords are ever stored.
"""
import html as _html
import inspect
import json
from datetime import datetime, time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import database as db
import detection
import risk_engine as risk
import simulation

st.set_page_config(page_title="Password Spray Sentinel", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")


def _stretch(fn):
    """Full-width kwarg that works on both old and new Streamlit versions."""
    p = inspect.signature(fn).parameters
    if "width" in p and "stretch" in str(p["width"].annotation):
        return {"width": "stretch"}
    if "use_container_width" in p:
        return {"use_container_width": True}
    return {}


BTN, DF, PLOT = _stretch(st.button), _stretch(st.dataframe), _stretch(st.plotly_chart)

# ------------------------------------------------------------------ theme
LEVEL_COLOR = {"Low": "#34c38f", "Medium": "#f2b84b", "High": "#f27d42", "Critical": "#f0485b"}
BADGE_CLASS = {
    "Critical": "red", "High": "orange", "Medium": "amber", "Low": "green", "Normal": "grey",
    "CRITICAL": "red", "HIGH": "orange", "MEDIUM": "amber", "LOW": "green", "INFO": "blue",
    "Suspicious": "amber", "Blocked": "red", "Blocked IP": "red", "Monitored": "amber",
    "Temporarily Protected": "blue", "Open": "red", "Investigating": "amber", "Mitigated": "blue",
    "Resolved": "green", "Failed": "red", "Success": "green", "Login Failure": "orange",
    "Login Success": "green",
}
GLOSS = {
    "Risk score": "0-100 score built from accounts targeted, failed attempts, failure rate, speed and behaviour.",
    "Risk": "0-100 score built from accounts targeted, failed attempts, failure rate, speed and behaviour.",
    "Failure rate": "Share of login attempts that failed.",
    "Pattern": "The attack shape the behaviour resembles (spraying, brute force, distributed).",
    "Accounts": "Number of different user accounts the source tried to log in to.",
    "Window (min)": "How long the burst of failures lasted.",
    "Status": "Current state of the item.",
}
PAGES = ["Dashboard", "Detection", "Incidents", "Analytics", "Prevention",
         "IP Monitoring", "Account Protection", "Event Logs", "Settings"]
ICONS = {"Dashboard": "📊", "Detection": "🔍", "Incidents": "🚨", "Analytics": "📈", "Prevention": "🛡️",
         "IP Monitoring": "🌐", "Account Protection": "🔒", "Event Logs": "🧾", "Settings": "⚙️"}

CSS = """
<style>
:root{--bg:#0c111d;--panel:#131a2b;--panel2:#18213a;--line:#25304b;--text:#e6eaf3;--muted:#8d99b5;
--accent:#5b9dff;--green:#34c38f;--amber:#f2b84b;--orange:#f27d42;--red:#f0485b;--grey:#7c8aa5;}
.stApp{background:var(--bg);font-family:"Segoe UI",Inter,system-ui,-apple-system,Roboto,sans-serif;}
header[data-testid="stHeader"]{background:transparent;} footer{visibility:hidden;}
.block-container{padding-top:2.2rem;max-width:1450px;}
section[data-testid="stSidebar"]{background:#0a0e18;border-right:1px solid var(--line);}
section[data-testid="stSidebar"] div[role="radiogroup"]{gap:2px;}
section[data-testid="stSidebar"] div[role="radiogroup"] label{padding:9px 12px;border-radius:9px;width:100%;cursor:pointer;}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover{background:rgba(91,157,255,.08);}
section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child{display:none;}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked){background:rgba(91,157,255,.18);}
.brand{display:flex;align-items:center;gap:10px;margin:2px 0 14px 2px;}
.brand .logo{font-size:26px;} .brand b{font-size:16px;display:block;line-height:1.1;} .brand span{font-size:11.5px;color:var(--muted);}
.topbar{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:18px;}
.topbar h1{font-size:30px;font-weight:700;margin:0;letter-spacing:-.01em;line-height:1.15;}
.topbar p{margin:4px 0 0;color:var(--muted);font-size:14px;max-width:760px;}
.simpill{border:1px solid rgba(91,157,255,.4);background:rgba(91,157,255,.1);color:#9cc2ff;padding:5px 12px;border-radius:99px;font-size:12px;}
.hero{display:grid;grid-template-columns:1.5fr 1fr;gap:28px;padding:26px 30px;border-radius:18px;border:1px solid var(--line);
border-left:6px solid var(--tone);background:linear-gradient(90deg,rgba(var(--rgb),.13),var(--panel) 62%);margin-bottom:16px;}
@media(max-width:900px){.hero{grid-template-columns:1fr;}}
.hero .t{font-size:15px;color:var(--muted);} .hero .big{font-size:42px;font-weight:800;color:var(--tone);letter-spacing:.01em;line-height:1.1;margin:2px 0 6px;}
.hero .d{color:#c3cce0;font-size:14px;margin-bottom:14px;}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:99px;border:1px solid var(--line);background:rgba(255,255,255,.03);font-size:12.5px;margin:0 6px 6px 0;}
.pill i{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);} .pill.off i{background:var(--red);box-shadow:none;}
.seg{display:flex;gap:5px;margin:10px 0 6px;} .seg span{flex:1;height:14px;border-radius:4px;opacity:.18;} .seg span.on{opacity:1;}
.seglbl{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);}
.score{font-size:46px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums;} .score small{font-size:18px;color:var(--muted);font-weight:600;}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;height:100%;}
.kpi .l{color:var(--muted);font-size:13px;border-bottom:1px dotted #3a4766;display:inline-block;cursor:help;}
.kpi .v{font-size:32px;font-weight:700;font-variant-numeric:tabular-nums;margin-top:4px;line-height:1.15;} .kpi .s{font-size:12px;color:var(--muted);margin-top:2px;}
.sec{margin:20px 0 10px;} .sec h3{font-size:17px;font-weight:650;margin:0;} .sec p{margin:2px 0 0;color:var(--muted);font-size:13px;}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:12px;}
.card h4{margin:0 0 8px;font-size:15px;} .card p,.card li{color:#c3cce0;font-size:14px;line-height:1.55;} .card ul,.card ol{margin:6px 0 0;padding-left:20px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-top:10px;}
.grid .k{font-size:12px;color:var(--muted);} .grid .v{font-size:15px;font-weight:600;margin-top:2px;}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border:1px solid;white-space:nowrap;}
.bd-red{color:#ff8a98;background:rgba(240,72,91,.12);border-color:rgba(240,72,91,.45);}
.bd-orange{color:#ffa06b;background:rgba(242,125,66,.12);border-color:rgba(242,125,66,.45);}
.bd-amber{color:#f6cc77;background:rgba(242,184,75,.12);border-color:rgba(242,184,75,.45);}
.bd-green{color:#6fdcb0;background:rgba(52,195,143,.12);border-color:rgba(52,195,143,.45);}
.bd-blue{color:#9cc2ff;background:rgba(91,157,255,.12);border-color:rgba(91,157,255,.45);}
.bd-grey{color:#a9b4cc;background:rgba(124,138,165,.12);border-color:rgba(124,138,165,.4);}
.tbl-wrap{max-height:430px;overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel);}
.tbl{width:100%;border-collapse:collapse;font-size:13px;} .tbl th{position:sticky;top:0;background:#172037;color:var(--muted);text-align:left;font-weight:600;padding:9px 11px;border-bottom:1px solid var(--line);white-space:nowrap;}
.tbl th[title]{cursor:help;text-decoration:underline dotted #3a4766;} .tbl td{padding:9px 11px;border-bottom:1px solid rgba(37,48,75,.6);white-space:nowrap;}
.tbl tr:hover td{background:rgba(91,157,255,.05);} .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;}
.rb{display:flex;align-items:center;gap:8px;min-width:120px;} .rb b{width:26px;text-align:right;font-variant-numeric:tabular-nums;} .rb .meter{flex:1;}
.meter{height:8px;border-radius:99px;background:#222c45;overflow:hidden;} .meter i{display:block;height:100%;border-radius:99px;}
.alert{border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;padding:11px 13px;margin-bottom:10px;background:var(--panel);}
.alert .h{display:flex;gap:9px;align-items:center;flex-wrap:wrap;} .alert .ti{font-weight:650;font-size:13px;} .alert .tm{margin-left:auto;color:var(--muted);font-size:11.5px;}
.alert .b{color:#c3cce0;font-size:12.5px;margin-top:6px;line-height:1.55;}
.console{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#080c15;border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:12px;padding:14px 18px;color:#b9c6e4;font-size:13px;line-height:1.8;margin-bottom:14px;}
.console b{color:#fff;} .empty{padding:22px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:12px;}
.why{border-left:4px solid var(--accent);} .chk li{list-style:none;margin-left:-18px;} .chk li:before{content:"✓  ";color:var(--green);font-weight:700;}
.chip{display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:8px;background:#1b2540;border:1px solid var(--line);font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;}
</style>
"""

TONES = {"green": ("#34c38f", "52,195,143"), "amber": ("#f2b84b", "242,184,75"),
         "orange": ("#f27d42", "242,125,66"), "red": ("#f0485b", "240,72,91")}


# ---------------------------------------------------------------- helpers
def esc(x):
    return _html.escape(str(x))


def H(markup):
    """Render HTML. Lines are joined so Markdown never mistakes indentation for a code block."""
    st.markdown(" ".join(l.strip() for l in markup.strip().splitlines()), unsafe_allow_html=True)


def flash(msg, kind="success"):
    st.session_state.setdefault("flash", []).append((kind, msg))


def show_flash():
    for kind, msg in st.session_state.pop("flash", []):
        {"success": st.success, "warning": st.warning, "error": st.error}.get(kind, st.info)(msg, icon="✅" if kind == "success" else None)


def lvl(score):
    return risk.level_for(score, S)


def badge(text):
    return f'<span class="badge bd-{BADGE_CLASS.get(str(text), "grey")}">{esc(text)}</span>'


def risk_bar(score):
    sc = int(score)
    return (f'<div class="rb"><b>{sc}</b><div class="meter"><i style="width:{min(sc, 100)}%;'
            f'background:{LEVEL_COLOR[lvl(sc)]}"></i></div></div>')


def table_html(df, cols, max_rows=300, empty="No records to show."):
    """cols: list of (header, column, kind). kinds: text, mono, time, badge, risk, pct."""
    if df is None or len(df) == 0:
        return f'<div class="empty">{esc(empty)}</div>'
    head = "".join(f'<th title="{esc(GLOSS.get(h, ""))}">{esc(h)}</th>' if h in GLOSS else f"<th>{esc(h)}</th>"
                   for h, _, _ in cols)
    body = []
    for rec in df.head(max_rows).to_dict("records"):
        tds = []
        for _, key, kind in cols:
            v = rec.get(key, "")
            if kind == "badge":
                c = badge(v)
            elif kind == "risk":
                c = risk_bar(v)
            elif kind == "mono":
                c = f'<span class="mono">{esc(v)}</span>'
            elif kind == "time":
                c = f'<span class="mono">{esc(str(v)[5:])}</span>'
            elif kind == "pct":
                c = f"{float(v) * 100:.0f}%"
            else:
                c = esc(v)
            tds.append(f"<td>{c}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    return (f'<div class="tbl-wrap"><table class="tbl"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def section(title, sub=""):
    H(f'<div class="sec"><h3>{esc(title)}</h3>' + (f"<p>{esc(sub)}</p>" if sub else "") + "</div>")


def kpi(label, value, sub, tip, color="var(--text)"):
    return (f'<div class="kpi"><span class="l" title="{esc(tip)}">{esc(label)}</span>'
            f'<div class="v" style="color:{color}">{value}</div><div class="s">{esc(sub)}</div></div>')


def style_fig(fig, height=320):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=height,
        font=dict(color="#c3cce0", size=12), margin=dict(l=8, r=8, t=10, b=8),
        legend=dict(orientation="h", y=-0.22, title_text=""), title_text="")
    fig.update_xaxes(gridcolor="#1f2940", zeroline=False, title_text=None)
    fig.update_yaxes(gridcolor="#1f2940", zeroline=False)
    return fig


def show(fig, key, height=320):
    st.plotly_chart(style_fig(fig, height), key=key, **PLOT)


def meter_big(score):
    """Segmented risk meter used on the dashboard hero and the detection detail view."""
    bands = [(0, "Low"), (30, "Medium"), (S["high_threshold"], "High"), (S["critical_threshold"], "Critical")]
    cur = lvl(score)
    order = ["Low", "Medium", "High", "Critical"]
    segs = "".join(f'<span class="{"on" if order.index(n) <= order.index(cur) and score > 0 else ""}" '
                   f'style="background:{LEVEL_COLOR[n]}"></span>' for _, n in bands)
    lbl = "".join(f"<span>{n} {a}+</span>" for a, n in bands)
    return f'<div class="seg">{segs}</div><div class="seglbl">{lbl}</div>'


def alert_card(a):
    lv = str(a["level"])
    color = {"CRITICAL": "#f0485b", "HIGH": "#f27d42", "MEDIUM": "#f2b84b", "LOW": "#34c38f", "INFO": "#5b9dff"}.get(lv, "#7c8aa5")
    icon = "⚠ " if lv in ("CRITICAL", "HIGH") else ""
    body = esc(a["message"]).replace("\n", "<br>")
    return (f'<div class="alert" style="--c:{color}"><div class="h">{badge(lv)}<span class="ti">{icon}{esc(a["title"])}</span>'
            f'<span class="tm">{esc(str(a["timestamp"])[5:16])}</span></div><div class="b">{body}</div></div>')


# --------------------------------------------------------------- data load
def load_data():
    ev = db.read_df("SELECT * FROM login_events ORDER BY timestamp DESC, id DESC")
    ev["ts"] = pd.to_datetime(ev["timestamp"])
    inc = db.read_df("SELECT * FROM incidents ORDER BY timestamp DESC")
    ips = db.read_df("SELECT * FROM ip_monitoring ORDER BY risk_score DESC, failed_attempts DESC")
    acc = db.read_df("SELECT * FROM account_protection ORDER BY risk_score DESC, failed_attempts DESC")
    al = db.read_df("SELECT * FROM alerts ORDER BY timestamp DESC, alert_id DESC")
    blocked = set(ips.loc[ips["status"] == "Blocked", "ip_address"])
    ev["result"] = ev["success"].map({1: "Success", 0: "Failed"})
    ev["status"] = ["Blocked IP" if ip in blocked else ("Suspicious" if r >= risk.MEDIUM_THRESHOLD else "Normal")
                    for ip, r in zip(ev["source_ip"], ev["risk_score"])]
    ev["level"] = [lvl(r) for r in ev["risk_score"]]
    return dict(events=ev, incidents=inc, ips=ips, accounts=acc, alerts=al)


def system_status(inc):
    open_ = inc[inc["status"] == "Open"]
    n_c, n_h = int((open_["severity"] == "Critical").sum()), int((open_["severity"] == "High").sum())
    active = int(inc["status"].isin(["Open", "Investigating"]).sum())
    if n_c:
        return "UNDER ATTACK", "red", f"{n_c} critical incident(s) are waiting for a response. Open Incidents to apply the recommended response."
    if n_h:
        return "ELEVATED RISK", "orange", f"{n_h} high-risk incident(s) are open and need review."
    return "PROTECTED", "green", f"No unhandled high-risk incidents. {active} incident(s) are open or being investigated."


# ------------------------------------------------------------------ pages
def topbar(title, desc):
    H(f'<div class="topbar"><div><h1>{esc(title)}</h1><p>{esc(desc)}</p></div>'
      f'<div class="simpill">Simulation mode: synthetic data only</div></div>')


def why_box(pattern, reasons, accounts, failed, rate, span):
    head, body = risk.explain(pattern)
    factors = "".join(f"<li>{esc(r)}</li>" for r in reasons)
    H(f'<div class="card why"><h4>Why was this detected?</h4><p><b>{esc(head)}</b></p><p>{esc(body)}</p>'
      f'<p style="margin-top:8px">Risk factors:</p><ul class="chk">{factors}</ul></div>')


def comp_chart(comps, key):
    names = list(comps.keys())
    fig = go.Figure()
    fig.add_bar(y=names, x=[comps[n][1] for n in names], orientation="h", marker_color="#222c45", name="Maximum", hoverinfo="skip")
    fig.add_bar(y=names, x=[comps[n][0] for n in names], orientation="h", marker_color="#5b9dff", name="Points scored")
    fig.update_layout(barmode="overlay")
    fig.update_yaxes(autorange="reversed")
    show(fig, key, 250)


def page_dashboard(D):
    ev, inc, ips, acc, al = D["events"], D["incidents"], D["ips"], D["accounts"], D["alerts"]
    title, tone, sub = system_status(inc)
    color, rgb = TONES[tone]
    prevent_on = any(S[k] for k in ("rate_limiting", "account_protection", "auto_block", "auto_protect"))
    engines = [("Detection Engine", True), ("Prevention Engine", prevent_on),
               ("IP Monitoring", S["ip_monitoring"]), ("Alert System", S["admin_alerts"])]
    pills = "".join(f'<span class="pill {"" if on else "off"}"><i></i>{n}: {"Active" if on else "Disabled"}</span>' for n, on in engines)
    active = inc[inc["status"].isin(["Open", "Investigating"])]
    peak = int(active["risk_score"].max()) if not active.empty else 0
    H(f'''<div class="hero" style="--tone:{color};--rgb:{rgb}">
      <div><div class="t">System status</div><div class="big">{title}</div><div class="d">{esc(sub)}</div>{pills}</div>
      <div><div class="t" title="Highest risk score among incidents that are still open or under investigation.">Highest active risk</div>
      <div class="score" style="color:{LEVEL_COLOR[lvl(peak)] if peak else '#34c38f'}">{peak}<small> / 100</small></div>
      {meter_big(peak)}</div></div>''')

    fails = int((ev["success"] == 0).sum())
    susp = int(((ev["success"] == 0) & (ev["risk_score"] >= risk.MEDIUM_THRESHOLD)).sum())
    hi = inc["severity"].isin(["High", "Critical"])
    cards = [
        kpi("Total Login Attempts", f"{len(ev):,}", f"{fails / max(len(ev), 1):.0%} failed", "Every authentication event recorded in the local database."),
        kpi("Suspicious Attempts", susp, "failed logins from risky sources", "Failed logins whose source has a risk score of 30 or more.", LEVEL_COLOR["Medium"]),
        kpi("Detected Incidents", len(inc), f"{int((inc['status'] == 'Open').sum())} open", "Attacks the detection engine turned into incidents.", LEVEL_COLOR["High"]),
        kpi("High-Risk Incidents", int(hi.sum()), f"{int((inc['severity'] == 'Critical').sum())} critical", "Incidents with High or Critical severity.", LEVEL_COLOR["Critical"]),
        kpi("Suspicious IPs", int(ips["status"].isin(["Suspicious", "Blocked"]).sum()), f"{int((ips['status'] == 'Blocked').sum())} blocked", "IP addresses that are suspicious or already blocked.", LEVEL_COLOR["Medium"]),
        kpi("Protected Accounts", int((acc["protection_status"] == "Temporarily Protected").sum()), "temporary protection", "Accounts under simulated temporary protection.", "#5b9dff"),
    ]
    for col, c in zip(st.columns(6), cards):
        with col:
            H(c)

    left, right = st.columns([3, 2], gap="large")
    with left:
        section("Login activity, last 24 hours", "Successful and failed logins in 30-minute buckets. Attack bursts show as red spikes.")
        recent = ev[ev["ts"] >= ev["ts"].max() - pd.Timedelta(hours=24)].copy()
        recent["bucket"] = recent["ts"].dt.floor("30min")
        g = recent.groupby(["bucket", "result"]).size().reset_index(name="count")
        fig = px.bar(g, x="bucket", y="count", color="result", color_discrete_map={"Success": "#3b6fb6", "Failed": "#f0485b"},
                     category_orders={"result": ["Success", "Failed"]})
        fig.update_layout(bargap=0.15, yaxis_title=None)
        show(fig, "dash_activity", 280)
        section("Recent security events", "Latest flagged events (risk 30 or higher).")
        flagged = ev[ev["risk_score"] >= risk.MEDIUM_THRESHOLD].head(8)
        flagged = flagged if not flagged.empty else ev.head(8)
        H(table_html(flagged, [("Time", "timestamp", "time"), ("Event", "event_type", "badge"), ("User", "username", "mono"),
                               ("Source IP", "source_ip", "mono"), ("Risk", "risk_score", "risk"), ("Status", "status", "badge")]))
    with right:
        section("Administrator alerts", "Newest first.")
        if al.empty:
            H('<div class="empty">No alerts yet. Run an attack simulation to generate one.</div>')
        for _, a in al.head(5).iterrows():
            H(alert_card(a))
        section("Top suspicious sources")
        H(table_html(ips.head(5), [("IP address", "ip_address", "mono"), ("Risk", "risk_score", "risk"), ("Status", "status", "badge")]))


def page_detection(D):
    topbar("Detection", "How the engine analyses login behaviour, scores risk and explains each decision.")
    events = detection.load_events()
    analyses = detection.analyze_events(events, S)
    n_ips = events["source_ip"].nunique()
    H(f'<div class="card"><p>The engine analysed <b>{len(events):,}</b> events from <b>{n_ips}</b> source IPs using a sliding '
      f'<b>{S["window_minutes"]}-minute</b> window. Spraying is flagged when one source fails against at least '
      f'<b>{S["min_accounts"]}</b> accounts; brute force needs <b>{S["failed_threshold"]}</b>+ failures on one or two accounts. '
      f'Change these in Settings.</p></div>')

    section("Behavioural patterns the engine looks for")
    cols = st.columns(3)
    for col, (name, (shape, desc)) in zip(cols, risk.PATTERN_INFO.items()):
        with col:
            H(f'<div class="card"><h4>{name}</h4><p class="mono" style="color:#9cc2ff">{esc(shape)}</p><p>{esc(desc)}</p></div>')

    section("Detection results", "Every source IP with failed logins, ranked by risk score.")
    rows = pd.DataFrame([{"source": a["source_ip"], "pattern": a["pattern"], "accounts": a["accounts"], "failed": a["failed"],
                          "window": f'{a["span_min"]:.1f}', "rate": a["failure_rate"], "score": a["score"], "level": a["level"]}
                         for a in analyses])
    H(table_html(rows, [("Source", "source", "mono"), ("Pattern", "pattern", "text"), ("Accounts", "accounts", "text"),
                        ("Failed", "failed", "text"), ("Window (min)", "window", "text"), ("Failure rate", "rate", "pct"),
                        ("Risk score", "score", "risk"), ("Level", "level", "badge")], empty="No failed logins found."))
    if not analyses:
        return
    section("Inspect a detection")
    idx = st.selectbox("Source to inspect", range(len(analyses)), key="det_pick",
                       format_func=lambda i: f'{analyses[i]["source_ip"]}  -  {analyses[i]["pattern"]}  -  risk {analyses[i]["score"]}',
                       help="Pick a source to see exactly why it received its score.")
    a = analyses[idx]
    c1, c2 = st.columns([1, 1], gap="large")
    with c1:
        H(f'<div class="card"><div style="display:flex;align-items:center;gap:12px"><div class="score" style="color:{LEVEL_COLOR[a["level"]]}">'
          f'{a["score"]}<small> / 100</small></div><div>{badge(a["level"].upper())}</div></div>{meter_big(a["score"])}'
          f'<div class="grid"><div><div class="k">Detected pattern</div><div class="v">{esc(a["pattern"])}</div></div>'
          f'<div><div class="k">Source</div><div class="v mono">{esc(a["source_ip"])}</div></div>'
          f'<div><div class="k">Accounts targeted</div><div class="v">{a["accounts"]}</div></div>'
          f'<div><div class="k">Failed attempts</div><div class="v">{a["failed"]}</div></div>'
          f'<div><div class="k">Time window</div><div class="v">{a["span_min"]:.1f} min</div></div>'
          f'<div><div class="k">Failure rate</div><div class="v">{a["failure_rate"]:.0%}</div></div></div></div>')
        section("Score breakdown", "Points earned by each risk factor, compared with its maximum.")
        comp_chart(a["components"], "det_comp")
    with c2:
        why_box(a["pattern"], a["reasons"], a["accounts"], a["failed"], a["failure_rate"], a["span_min"])
        if a["pattern"] != "Normal":
            recs = "".join(f"<li>{esc(r)}</li>" for r in risk.recommendations(a["level"], a["pattern"]))
            H(f'<div class="card"><h4>Recommended actions</h4><ol>{recs}</ol></div>')
        t = pd.DataFrame({"account": list(a["attempts_by_user"].keys()), "failed attempts": list(a["attempts_by_user"].values())})
        fig = px.bar(t, x="account", y="failed attempts", color_discrete_sequence=["#f27d42"])
        show(fig, "det_users", 220)


def page_incidents(D):
    topbar("Incidents", "Every detected attack becomes an incident that an administrator can investigate and close.")
    inc = D["incidents"]
    if inc.empty:
        H('<div class="empty">No incidents yet. Use "Run Attack Simulation" in the sidebar.</div>')
        return
    counts = inc["status"].value_counts()
    for col, stt in zip(st.columns(4), ["Open", "Investigating", "Mitigated", "Resolved"]):
        with col:
            H(kpi(stt, int(counts.get(stt, 0)), "incidents", f"Incidents currently marked {stt}."))
    f1, f2 = st.columns(2)
    sev_f = f1.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"], key="inc_sev")
    st_f = f2.multiselect("Status", ["Open", "Investigating", "Mitigated", "Resolved"], default=["Open", "Investigating", "Mitigated", "Resolved"], key="inc_status")
    view = inc[inc["severity"].isin(sev_f) & inc["status"].isin(st_f)]
    H(table_html(view, [("Incident", "incident_id", "mono"), ("Time", "timestamp", "time"), ("Source IP", "source_ip", "mono"),
                        ("Attack type", "attack_type", "text"), ("Accounts", "accounts_targeted", "text"), ("Failed", "failed_attempts", "text"),
                        ("Risk score", "risk_score", "risk"), ("Severity", "severity", "badge"), ("Status", "status", "badge"),
                        ("Recommended action", "recommended_action", "text")], empty="No incidents match the filters."))
    if view.empty:
        return
    section("Incident details")
    ids = view["incident_id"].tolist()
    iid = st.selectbox("Select an incident", ids, key="inc_pick",
                       format_func=lambda i: f'{i}  -  {view.loc[view.incident_id == i, "attack_type"].iloc[0]}  -  {view.loc[view.incident_id == i, "source_ip"].iloc[0]}')
    r = view[view["incident_id"] == iid].iloc[0]
    users, reasons, comps = json.loads(r["targeted_users"]), json.loads(r["reasons"]), json.loads(r["components"])
    H(f'<div class="card"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><h4 style="margin:0" class="mono">{esc(iid)}</h4>'
      f'{badge(r["severity"].upper())}{badge(r["status"])}<span style="color:var(--muted);font-size:13px">{esc(r["attack_type"])}</span></div>'
      f'<div class="grid"><div><div class="k">Detected</div><div class="v">{esc(r["timestamp"])}</div></div>'
      f'<div><div class="k">Source IP</div><div class="v mono">{esc(r["source_ip"])}</div></div>'
      f'<div><div class="k">Accounts targeted</div><div class="v">{r["accounts_targeted"]}</div></div>'
      f'<div><div class="k">Failed attempts</div><div class="v">{r["failed_attempts"]}</div></div>'
      f'<div><div class="k">Risk score</div><div class="v" style="color:{LEVEL_COLOR[r["severity"]]}">{r["risk_score"]}/100</div></div>'
      f'<div><div class="k">Failure rate</div><div class="v">{r["failure_rate"]:.0%}</div></div>'
      f'<div><div class="k">Attack window</div><div class="v">{r["span_minutes"]:.1f} min</div></div>'
      f'<div><div class="k">Recommended action</div><div class="v">{esc(r["recommended_action"])}</div></div></div>'
      f'<div style="margin-top:12px">{"".join(f"<span class=chip>{esc(u)}</span>" for u in users)}</div></div>')
    c1, c2 = st.columns(2, gap="large")
    with c1:
        why_box(r["attack_type"], reasons, r["accounts_targeted"], r["failed_attempts"], r["failure_rate"], r["span_minutes"])
    with c2:
        recs = "".join(f"<li>{esc(x)}</li>" for x in risk.recommendations(r["severity"], r["attack_type"]))
        H(f'<div class="card"><h4>Recommended actions</h4><ol>{recs}</ol></div>')
        comp_chart(comps, f"inc_comp_{iid}")
    section("Respond")
    a1, a2, a3 = st.columns([2, 1, 2])
    new = a1.selectbox("Incident status", ["Open", "Investigating", "Mitigated", "Resolved"],
                       index=["Open", "Investigating", "Mitigated", "Resolved"].index(r["status"]), key=f"stat_{iid}")
    a2.write("")
    if a2.button("Update status", key=f"upd_{iid}", **BTN):
        db.update_incident_status(iid, new)
        flash(f"{iid} status changed to {new}.")
        st.rerun()
    a3.write("")
    if a3.button("Apply recommended response", key=f"resp_{iid}", type="primary", **BTN,
                 help="Simulated: blocks the source IP(s), protects targeted accounts and marks the incident Mitigated."):
        flash(detection.apply_response(iid))
        st.rerun()
    ips = json.loads(r["ip_list"])
    qs = ",".join("?" * len(ips))
    rel = db.read_df(f"SELECT timestamp, username, source_ip, event_type, risk_score FROM login_events WHERE source_ip IN ({qs}) "
                     f"AND timestamp BETWEEN ? AND ? ORDER BY timestamp", tuple(ips) + (r["window_start"], r["window_end"]))
    section("Events inside the attack window")
    st.dataframe(rel, hide_index=True, **DF)


def page_analytics(D):
    topbar("Analytics", "Attack trends and security statistics calculated from the local database.")
    ev, ips, acc = D["events"], D["ips"], D["accounts"]
    if ev.empty:
        H('<div class="empty">No data yet.</div>')
        return
    f = ev[ev["success"] == 0]
    top_ip = f["source_ip"].value_counts()
    top_user = f["username"].value_counts()
    cards = [kpi("Failure rate", f"{len(f) / len(ev):.0%}", f"{len(f)} of {len(ev)} attempts", "Share of all attempts that failed."),
             kpi("Peak risk score", int(ev["risk_score"].max()), "highest event score", "Highest risk score on any event."),
             kpi("Top failing IP", top_ip.index[0] if len(top_ip) else "-", f"{int(top_ip.iloc[0]) if len(top_ip) else 0} failures", "Source with the most failed logins."),
             kpi("Most targeted account", top_user.index[0] if len(top_user) else "-", f"{int(top_user.iloc[0]) if len(top_user) else 0} failures", "Account with the most failed logins.")]
    for col, c in zip(st.columns(4), cards):
        with col:
            H(c)
    ev = ev.copy()
    c1, c2 = st.columns(2, gap="large")
    with c1:
        section("Login attempts over time", "All attempts in 15-minute buckets.")
        ev["b15"] = ev["ts"].dt.floor("15min")
        g = ev.groupby("b15").size().reset_index(name="attempts")
        fig = px.line(g, x="b15", y="attempts", color_discrete_sequence=["#5b9dff"])
        fig.update_traces(line_shape="spline", fill="tozeroy", fillcolor="rgba(91,157,255,.12)")
        show(fig, "an_time")
    with c2:
        section("Failed vs successful logins", "Hourly totals.")
        ev["b60"] = ev["ts"].dt.floor("60min")
        g = ev.groupby(["b60", "result"]).size().reset_index(name="count")
        fig = px.bar(g, x="b60", y="count", color="result", barmode="group",
                     color_discrete_map={"Success": "#34c38f", "Failed": "#f0485b"})
        show(fig, "an_fs")
    c3, c4 = st.columns(2, gap="large")
    with c3:
        section("Suspicious attempts by IP", "Top 10 sources by failed logins, coloured by risk level.")
        g = f.groupby("source_ip").agg(failed=("id", "count"), risk=("risk_score", "max")).reset_index()
        g["level"] = [lvl(x) for x in g["risk"]]
        g = g.sort_values("failed", ascending=False).head(10)
        fig = px.bar(g, y="source_ip", x="failed", color="level", orientation="h", color_discrete_map=LEVEL_COLOR)
        fig.update_yaxes(autorange="reversed", title_text=None)
        show(fig, "an_ip")
    with c4:
        section("Failed attempts by risk level", "Which risk bands the failed logins fall into.")
        g = f["level"].value_counts().reset_index()
        g.columns = ["level", "count"]
        fig = px.pie(g, names="level", values="count", hole=0.6, color="level", color_discrete_map=LEVEL_COLOR)
        fig.update_traces(textinfo="label+value")
        show(fig, "an_pie")
    c5, c6 = st.columns(2, gap="large")
    with c5:
        section("Accounts targeted", "Top 12 accounts by failed logins, coloured by protection status.")
        g = f.groupby("username").size().reset_index(name="failed").merge(acc[["username", "protection_status"]], on="username", how="left")
        g = g.sort_values("failed", ascending=False).head(12)
        fig = px.bar(g, x="username", y="failed", color="protection_status",
                     color_discrete_map={"Temporarily Protected": "#5b9dff", "Monitored": "#f2b84b", "Normal": "#7c8aa5"})
        show(fig, "an_acc")
    with c6:
        section("Attack activity timeline", "Each dot is a failed login from a risky source. Dense rows are attack bursts.")
        t = f[f["risk_score"] >= risk.MEDIUM_THRESHOLD]
        if t.empty:
            H('<div class="empty">No risky failed logins.</div>')
        else:
            fig = px.scatter(t, x="ts", y="source_ip", color="level", color_discrete_map=LEVEL_COLOR,
                             hover_data=["username", "risk_score"])
            fig.update_traces(marker=dict(size=8, opacity=0.8))
            fig.update_yaxes(title_text=None)
            show(fig, "an_tl")


def page_prevention(D):
    topbar("Prevention", "Simulated prevention controls. These switches change how the detection engine responds.")
    inc, ips, acc, al = D["incidents"], D["ips"], D["accounts"], D["alerts"]
    controls = [
        ("rate_limiting", "Login Rate Limiting", "Limits repeated authentication attempts within a defined time window."),
        ("account_protection", "Temporary Account Protection", "Temporarily protects accounts showing suspicious authentication behavior."),
        ("ip_monitoring", "Suspicious IP Monitoring", "Continuously monitors IP addresses for abnormal login activity."),
        ("admin_alerts", "Administrator Alerts", "Generates security alerts when high-risk activity is detected."),
        ("auto_block", "Automatic IP Blocking", "Simulates automatic blocking of high-risk IP addresses."),
        ("auto_protect", "Automatic Account Protection", "Simulates automatic protection of accounts affected by password spraying."),
    ]
    for row in range(0, 6, 2):
        for col, (key, name, desc) in zip(st.columns(2, gap="large"), controls[row:row + 2]):
            with col, st.container(border=True):
                H(f'<h4 style="margin:0 0 4px">{name}</h4><p style="color:#a9b4cc;font-size:13.5px;margin:0">{desc}</p>')
                val = st.toggle("Enabled", value=S[key], key=f"tg_{key}")
                if val != S[key]:
                    db.set_setting(key, val)
                    flash(f"{name} {'enabled' if val else 'disabled'}.")
                    st.rerun()
    section("Prevention effect", "What the controls have done so far, calculated from the database.")
    throttled = int(sum(max(0, r - S["failed_threshold"]) for r in inc["failed_attempts"])) if S["rate_limiting"] else 0
    cards = [kpi("Blocked IPs", int((ips["status"] == "Blocked").sum()), "by the prevention engine", "IPs currently blocked (simulated)."),
             kpi("Protected accounts", int((acc["protection_status"] == "Temporarily Protected").sum()), "temporarily protected", "Accounts under simulated protection."),
             kpi("Attempts throttled", throttled, "if rate limiting had been active", "Failed attempts beyond the failed-attempt threshold that rate limiting would have rejected."),
             kpi("Alerts raised", len(al), "administrator alerts", "Alerts stored in the database.")]
    for col, c in zip(st.columns(4), cards):
        with col:
            H(c)
    section("Respond to open high-risk incidents")
    todo = inc[inc["severity"].isin(["High", "Critical"]) & inc["status"].isin(["Open", "Investigating"])]
    H(table_html(todo, [("Incident", "incident_id", "mono"), ("Source IP", "source_ip", "mono"), ("Risk score", "risk_score", "risk"),
                        ("Severity", "severity", "badge"), ("Status", "status", "badge"), ("Recommended action", "recommended_action", "text")],
                 empty="All high-risk incidents have been handled."))
    if not todo.empty and st.button(f"Apply recommended response to {len(todo)} incident(s)", type="primary", key="bulk_resp"):
        for i in todo["incident_id"]:
            detection.apply_response(i)
        flash(f"Recommended response applied to {len(todo)} incident(s).")
        st.rerun()


def page_ips(D):
    topbar("IP Monitoring", "Every source IP, its behaviour and its simulated block status.")
    ips = D["ips"]
    counts = ips["status"].value_counts()
    for col, s_ in zip(st.columns(3), ["Normal", "Suspicious", "Blocked"]):
        with col:
            H(kpi(s_, int(counts.get(s_, 0)), "IP addresses", f"IPs currently marked {s_}."))
    pick = st.multiselect("Show statuses", ["Normal", "Suspicious", "Blocked"], default=["Suspicious", "Blocked"], key="ip_filter")
    H(table_html(ips[ips["status"].isin(pick)], [("IP address", "ip_address", "mono"), ("Failed attempts", "failed_attempts", "text"),
                                                ("Accounts targeted", "accounts_targeted", "text"), ("Risk score", "risk_score", "risk"),
                                                ("Status", "status", "badge"), ("Last activity", "last_activity", "time")]))
    section("Prevention action", "Simulated only. This updates the local database and nothing else.")
    if ips.empty:
        return
    c1, c2, c3 = st.columns([3, 1, 1])
    ip = c1.selectbox("IP address", ips["ip_address"].tolist(), key="ip_pick")
    cur = ips.loc[ips["ip_address"] == ip, "status"].iloc[0]
    c2.write("")
    if c2.button("Block IP", type="primary", disabled=cur == "Blocked", key="ip_block", **BTN):
        flash(db.block_ip(ip))
        st.rerun()
    c3.write("")
    if c3.button("Unblock IP", disabled=cur != "Blocked", key="ip_unblock", **BTN):
        flash(db.unblock_ip(ip))
        st.rerun()


def page_accounts(D):
    topbar("Account Protection", "Accounts under attack can be temporarily protected. This is simulated; no real accounts exist.")
    acc = D["accounts"]
    counts = acc["protection_status"].value_counts()
    for col, s_ in zip(st.columns(3), ["Normal", "Monitored", "Temporarily Protected"]):
        with col:
            H(kpi(s_, int(counts.get(s_, 0)), "accounts", f"Accounts with status {s_}."))
    pick = st.multiselect("Show statuses", ["Normal", "Monitored", "Temporarily Protected"],
                          default=["Monitored", "Temporarily Protected"], key="acc_filter")
    view = acc[acc["protection_status"].isin(pick)].copy()
    view["level"] = [lvl(x) for x in view["risk_score"]]
    H(table_html(view, [("Username", "username", "mono"), ("Failed attempts", "failed_attempts", "text"), ("Risk level", "level", "badge"),
                        ("Risk score", "risk_score", "risk"), ("Protection status", "protection_status", "badge"),
                        ("Last activity", "last_activity", "time"), ("Protection reason", "reason", "text")]))
    section("Protection action")
    if not S["account_protection"]:
        st.warning("Temporary Account Protection is switched off on the Prevention page.")
    c1, c2, c3 = st.columns([3, 1, 1])
    u = c1.selectbox("Account", acc["username"].tolist(), key="acc_pick")
    cur = acc.loc[acc["username"] == u, "protection_status"].iloc[0]
    c2.write("")
    if c2.button("Protect Account", type="primary", disabled=(cur == "Temporarily Protected" or not S["account_protection"]), key="acc_protect", **BTN):
        flash(db.protect_account(u, "Protected manually by administrator"))
        st.rerun()
    c3.write("")
    if c3.button("Remove protection", disabled=cur != "Temporarily Protected", key="acc_unprotect", **BTN):
        flash(db.unprotect_account(u))
        st.rerun()


def page_logs(D):
    topbar("Event Logs", "Every authentication event, with the risk score the engine assigned to it.")
    ev = D["events"]
    c1, c2, c3 = st.columns(3)
    ip_f = c1.text_input("Source IP contains", key="lg_ip")
    user_f = c2.text_input("Username contains", key="lg_user")
    lv_f = c3.multiselect("Risk level", ["Low", "Medium", "High", "Critical"], default=["Low", "Medium", "High", "Critical"], key="lg_lv")
    c4, c5, c6 = st.columns(3)
    et_f = c4.multiselect("Event type", sorted(ev["event_type"].unique()), default=sorted(ev["event_type"].unique()), key="lg_et")
    dmin, dmax = ev["ts"].min().date(), ev["ts"].max().date()
    dr = c5.date_input("Date range", value=(dmin, dmax), min_value=dmin, max_value=dmax, key="lg_date")
    tr = c6.slider("Time of day", value=(time(0, 0), time(23, 59)), key="lg_time")
    v = ev[ev["event_type"].isin(et_f) & ev["level"].isin(lv_f)]
    if ip_f:
        v = v[v["source_ip"].str.contains(ip_f.strip(), regex=False)]
    if user_f:
        v = v[v["username"].str.contains(user_f.strip(), case=False, regex=False)]
    d0, d1 = (dr[0], dr[-1]) if isinstance(dr, (tuple, list)) and len(dr) else (dr, dr)
    v = v[(v["ts"].dt.date >= d0) & (v["ts"].dt.date <= d1)]
    v = v[(v["ts"].dt.time >= tr[0]) & (v["ts"].dt.time <= tr[1])]
    st.caption(f"{len(v):,} of {len(ev):,} events match. Showing the newest 1,000.")
    out = v.head(1000)[["timestamp", "event_type", "username", "source_ip", "result", "risk_score", "status"]]
    out.columns = ["Timestamp", "Event Type", "Username", "Source IP", "Result", "Risk Score", "Status"]
    st.dataframe(out, hide_index=True, height=520, column_config={
        "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d",
                                                      help="0-100 risk assigned by the detection engine")}, **DF)
    st.download_button("Download filtered events (CSV)", out.to_csv(index=False), "events.csv", "text/csv", key="lg_dl")


def page_settings(D):
    topbar("Settings", "Detection thresholds used by the engine. Saving re-runs detection on all stored events.")
    before = len(D["incidents"])
    with st.form("settings_form"):
        c1, c2 = st.columns(2, gap="large")
        w = c1.number_input("Detection window (minutes)", 1, 60, S["window_minutes"], help="Failures closer together than this count as one burst.")
        m = c1.number_input("Minimum accounts targeted", 2, 50, S["min_accounts"], help="Accounts one IP must target before it is called password spraying.")
        f = c1.number_input("Failed attempt threshold", 3, 100, S["failed_threshold"], help="Failures needed to flag brute force, and the scale for the failure-count score.")
        hi = c2.number_input("High risk threshold", 31, 98, S["high_threshold"], help="Scores at or above this are High.")
        cr = c2.number_input("Critical risk threshold", 32, 100, S["critical_threshold"], help="Scores at or above this are Critical.")
        saved = st.form_submit_button("Save settings and re-run detection", type="primary")
    if saved:
        if cr <= hi:
            st.error("The Critical threshold must be higher than the High threshold.")
        else:
            for k, val in (("window_minutes", w), ("min_accounts", m), ("failed_threshold", f), ("high_threshold", hi), ("critical_threshold", cr)):
                db.set_setting(k, val)
            detection.run_detection(respond=False)
            after = int(db.read_df("SELECT COUNT(*) n FROM incidents").iloc[0]["n"])
            flash(f"Settings saved. Detection re-run: {after} incident(s) (was {before}).")
            st.rerun()
    section("Demo data")
    H('<div class="card"><p>Reset rebuilds the demo dataset with timestamps anchored to now and restores default settings. Do this just before presenting.</p></div>')
    ok = st.checkbox("I understand this deletes all current events, incidents and actions", key="reset_ok")
    if st.button("Reset demo data", disabled=not ok, key="reset_btn"):
        simulation.reset_demo_data()
        st.session_state.pop("sim_report", None)
        flash("Demo data reset.")
        st.rerun()


# ------------------------------------------------------------------- main
simulation.ensure_demo_data()
S = db.get_settings()
st.markdown(CSS, unsafe_allow_html=True)

with st.sidebar:
    H('<div class="brand"><div class="logo">🛡️</div><div><b>Password Spray Sentinel</b><span>Detection and Prevention System</span></div></div>')
    page = st.radio("Navigation", PAGES, key="nav", label_visibility="collapsed", format_func=lambda p: f"{ICONS[p]}   {p}")
    st.divider()
    scenario = st.selectbox("Simulation scenario", list(simulation.SCENARIOS), key="sim_scn",
                            help="Choose which synthetic attack to generate. Nothing real is contacted.")
    if st.button("Run Attack Simulation", type="primary", key="sim_run", **BTN,
                 help="Inserts a synthetic attack into the local database, analyses it and opens an incident."):
        with st.spinner("Analyzing behavior..."):
            st.session_state["sim_report"] = simulation.run_attack_simulation(scenario)
        st.toast("Simulation complete. Incident created." if st.session_state["sim_report"]["incident"] else "Simulation complete.")
    if st.button("Refresh Security Data", key="refresh", **BTN, help="Re-run detection on all stored events and reload every page."):
        detection.run_detection(respond=False)
        st.session_state["last_refresh"] = datetime.now().strftime("%H:%M:%S")
        flash("Security data refreshed.")
        st.rerun()
    st.caption(f"Last refresh: {st.session_state.get('last_refresh', 'on page load')}")
    st.caption("Safe demo: synthetic users and IPs only. No real logins, passwords or networks are touched.")

D = load_data()
if page == "Dashboard":
    H('<div class="topbar"><div><h1>Password Spray Sentinel</h1><p>Password Spraying Detection and Prevention System. '
      'It detects password-spraying behavior, scores the risk, flags suspicious sources, opens incidents and applies simulated prevention controls.</p></div>'
      '<div class="simpill">Simulation mode: synthetic data only</div></div>')
show_flash()
rep = st.session_state.get("sim_report")
if rep:
    lines = "<br>".join(f"&gt; {esc(x)}" for x in rep["steps"])
    H(f'<div class="console">{lines}</div>')
    if st.button("Dismiss simulation report", key="sim_dismiss"):
        st.session_state.pop("sim_report")
        st.rerun()

{"Dashboard": page_dashboard, "Detection": page_detection, "Incidents": page_incidents, "Analytics": page_analytics,
 "Prevention": page_prevention, "IP Monitoring": page_ips, "Account Protection": page_accounts,
 "Event Logs": page_logs, "Settings": page_settings}[page](D)
