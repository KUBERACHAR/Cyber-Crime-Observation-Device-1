"""Real-time SOC dashboard.

    streamlit run dashboard/app.py

Reads ``runtime/state.json`` written by the collector (decoupled processes: the UI can
restart without losing telemetry). The guided-response panel lives outside the
auto-refreshing fragment so a confirmation in progress is never interrupted.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import SETTINGS  # noqa: E402
from common.jsonio import read_json, tail_jsonl  # noqa: E402
from common.response import is_protected, register_monitor, terminate_process  # noqa: E402

st.set_page_config(page_title="Cyber Crime Observation Device", page_icon="🛡️", layout="wide")
SETTINGS.ensure_dirs()


@st.cache_resource
def _register_dashboard() -> bool:
    register_monitor("dashboard")
    return True


_register_dashboard()
ss = st.session_state
ss.setdefault("target", None)
ss.setdefault("dismissed", set())


# ----------------------------------------------------------------------------- helpers
def fmt_time(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "-"


def proc_alive(pid: int, create_time: float | None) -> bool:
    try:
        p = psutil.Process(pid)
        return create_time is None or abs(p.create_time() - create_time) < 1.0
    except psutil.Error:
        return False


def process_tree(tree_rows: list, pid: int) -> str:
    name = {r[0]: r[2] for r in tree_rows}
    parent = {r[0]: r[1] for r in tree_rows}
    kids: dict[int, list[int]] = {}
    for r in tree_rows:
        kids.setdefault(r[1], []).append(r[0])
    chain, cur, seen = [], parent.get(pid), {pid}
    while cur and cur in name and cur not in seen and len(chain) < 10:
        chain.append(cur)
        seen.add(cur)
        cur = parent.get(cur)
    lines = []
    for depth, p in enumerate(reversed(chain)):
        lines.append(f"{'   ' * depth}└─ {name.get(p, '?')} ({p})")
    base = len(chain)
    lines.append(f"{'   ' * base}└─ ▶ {name.get(pid, '?')} ({pid})   ◀ flagged")

    def walk(p, d):
        for c in sorted(kids.get(p, []))[:25]:
            if c in seen:
                continue
            seen.add(c)
            lines.append(f"{'   ' * d}└─ {name.get(c, '?')} ({c})")
            walk(c, d + 1)

    walk(pid, base + 1)
    return "\n".join(lines)


def active_alerts(state: dict) -> list[dict]:
    """Latest alert per live process, newest first, minus ones the analyst dismissed."""
    out, seen = [], set()
    for ev in state.get("alerts", []):
        d = ev["data"]
        key = (d["pid"], d.get("create_time"))
        if key in seen or key in ss.dismissed:
            continue
        seen.add(key)
        if proc_alive(d["pid"], d.get("create_time")):
            out.append(ev)
    return out


# ------------------------------------------------------------------ guided response
def response_panel(state: dict) -> None:
    ev = ss.target
    d = ev["data"]
    pid, name = d["pid"], d["name"]
    with st.container(border=True):
        st.markdown(f"### 🚨 Guided response — `{name}` (PID {pid})")
        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown(f"**Threat score:** `{d['score']:.0%}` · **user:** `{d.get('username') or '?'}` "
                        f"· **parent:** `{d.get('parent_name') or '?'}` ({d.get('ppid')}) "
                        f"· **detected:** {fmt_time(ev['ts'])} in {d.get('latency_ms', 0):.0f} ms")
            st.markdown("**Why it was flagged**")
            for r in d["reasons"]:
                st.markdown(f"- {r}")
            st.markdown("**Command line**")
            st.code(d.get("cmdline") or "(unavailable)", language="powershell")
        with c2:
            st.markdown("**Process tree**")
            st.code(process_tree(state.get("tree", []), pid), language=None)

        alive = proc_alive(pid, d.get("create_time"))
        protected, why = is_protected(pid, name)
        if not alive:
            st.info("This process is no longer running.")
        elif protected:
            st.warning(f"Termination blocked: {why}. Protected processes are never stopped.")
        else:
            confirm = st.checkbox(f"I have reviewed the evidence and authorise terminating "
                                  f"**{name}** (PID {pid}) and its child processes.")
            note = st.text_input("Analyst note (optional)", key="note")
        b1, b2, b3 = st.columns([1, 1, 4])
        if alive and not protected and b1.button("Terminate process", type="primary",
                                                 disabled=not confirm):
            res = terminate_process(pid, d.get("create_time"), confirmed=True, user_note=note)
            r = res["data"]
            (st.success if r["result"] == "terminated" else st.error)(
                f"{r['result'].upper()}: {r['detail']}")
            ss.target = None
            time.sleep(1.2)
            st.rerun()
        if b2.button("Mark as false positive"):
            ss.dismissed.add((pid, d.get("create_time")))
            ss.target = None
            st.rerun()
        if b3.button("Close"):
            ss.target = None
            st.rerun()


# -------------------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🛡️ CCOD")
    st.caption("AI-Based Cyber Crime Observation Device")
    refresh = st.slider("Refresh interval (s)", 1, 10, 2)
    state0 = read_json(SETTINGS.state_path, {}) or {}
    if state0:
        st.markdown(f"**Model:** {state0['model']['desc']}")
        st.markdown(f"**Alert threshold:** {state0['threshold']:.0%}")
        st.markdown("**Watched folders:**")
        for d in state0.get("watch_dirs", []):
            st.caption(d)
        if state0.get("recording"):
            r = state0["recording"]
            st.info(f"Recording dataset: {r.get('0', r.get(0, 0))} normal / "
                    f"{r.get('1', r.get(1, 0))} suspicious rows")
    st.divider()
    st.caption("Start the sensors in a second terminal:\n\n`python -m sensors.collector`")

state = read_json(SETTINGS.state_path, {}) or {}
if not state:
    st.title("AI-Based Cyber Crime Observation Device")
    st.info("Waiting for telemetry… start the collector with `python -m sensors.collector` "
            "from the project root. This page refreshes automatically.")
    time.sleep(refresh)
    st.rerun()

if ss.target is not None:
    response_panel(state)


# ----------------------------------------------------------------------- live view
@st.fragment(run_every=refresh)
def live() -> None:
    state = read_json(SETTINGS.state_path, {}) or {}
    if not state:
        return
    age = time.time() - state["ts"]
    host, perf = state.get("host", {}), state.get("perf", {})
    alerts = active_alerts(state)
    top = max((p["score"] for p in state.get("processes", [])), default=0.0)

    if age > 5:
        st.warning(f"Collector is not reporting (last update {age:.0f}s ago). Is it running?")
    if alerts:
        d = alerts[0]["data"]
        st.error(f"### 🚨 THREAT DETECTED — {d['name']} (PID {d['pid']}) · score {d['score']:.0%}\n"
                 f"{' · '.join(d['reasons'][:3])}")
    else:
        st.success("✅ No active threats — behaviour classified as **Normal**")

    k = st.columns(7)
    k[0].metric("Threat level", f"{top:.0%}", "ALERT" if top >= state["threshold"] else "normal",
                delta_color="inverse" if top >= state["threshold"] else "off")
    k[1].metric("CPU", f"{host.get('cpu_percent', 0):.0f}%")
    k[2].metric("RAM", f"{host.get('mem_percent', 0):.0f}%",
                f"{host.get('mem_used_gb', 0)}/{host.get('mem_total_gb', 0)} GB", delta_color="off")
    k[3].metric("Processes", host.get("process_count", 0))
    k[4].metric("Connections", len(state.get("connections", [])))
    fr = state.get("file_rates", {})
    k[5].metric("File creates/s", f"{fr.get('file_create_rate', 0):.1f}")
    p95 = perf.get("latency_p95_ms")
    k[6].metric("Detect latency p95", f"{p95:.0f} ms" if p95 is not None else "-",
                "within 500 ms" if p95 is not None and p95 <= 500 else None, delta_color="off")

    t_alert, t_proc, t_net, t_file, t_resp, t_model = st.tabs(
        ["🚨 Alerts", "⚙️ Processes", "🌐 Network", "📁 File activity", "🧾 Response log", "🧠 Model"])

    with t_alert:
        if alerts:
            st.markdown("#### Active alerts — select one to respond")
            for ev in alerts[:10]:
                d = ev["data"]
                c1, c2 = st.columns([6, 1])
                c1.markdown(f"🔴 **{d['name']}** (PID {d['pid']}) — **{d['score']:.0%}** at "
                            f"{fmt_time(ev['ts'])} · {d['reasons'][0]}")
                if c2.button("Respond", key=f"r{d['pid']}_{d.get('create_time')}"):
                    ss.target = ev
                    st.rerun(scope="app")
        c1, c2 = st.columns(2)
        sh = pd.DataFrame(state.get("score_history", []), columns=["ts", "max threat score"])
        if not sh.empty:
            sh["time"] = pd.to_datetime(sh["ts"], unit="s")
            sh["threshold"] = state["threshold"]
            c1.markdown("**Threat score timeline**")
            c1.line_chart(sh.set_index("time")[["max threat score", "threshold"]], height=220)
        hh = pd.DataFrame(state.get("host_history", []), columns=["ts", "CPU %", "RAM %"])
        if not hh.empty:
            hh["time"] = pd.to_datetime(hh["ts"], unit="s")
            c2.markdown("**Host resources**")
            c2.line_chart(hh.set_index("time")[["CPU %", "RAM %"]], height=220)
        hist = tail_jsonl(SETTINGS.alerts_log, 100)
        if hist:
            st.markdown("**Alert history**")
            st.dataframe(pd.DataFrame([{
                "time": fmt_time(e["ts"]), "process": e["data"]["name"], "pid": e["data"]["pid"],
                "score": e["data"]["score"], "latency ms": e["data"].get("latency_ms"),
                "reasons": "; ".join(e["data"]["reasons"])} for e in reversed(hist)]),
                hide_index=True,
                column_config={"score": st.column_config.ProgressColumn(
                    "score", min_value=0.0, max_value=1.0, format="%.2f")})

    with t_proc:
        procs = pd.DataFrame(state.get("processes", []))
        if not procs.empty:
            cols = ["score", "name", "pid", "ppid", "parent_name", "cpu_percent", "mem_percent",
                    "write_ops_rate", "write_kb_rate", "num_conns", "num_threads", "username",
                    "cmdline"]
            procs = procs[[c for c in cols if c in procs.columns]]
            st.dataframe(procs, hide_index=True, height=520,
                         column_config={"score": st.column_config.ProgressColumn(
                             "threat", min_value=0.0, max_value=1.0, format="%.2f")})

    with t_net:
        conns = pd.DataFrame(state.get("connections", []))
        if not conns.empty:
            names = {r[0]: r[2] for r in state.get("tree", [])}
            conns.insert(1, "process", conns["pid"].map(lambda p: names.get(p, "")))
            st.dataframe(conns.sort_values("status"), hide_index=True,
                         height=520)

    with t_file:
        fe = pd.DataFrame(state.get("file_events", []))
        st.caption(f"create {fr.get('file_create_rate', 0):.1f}/s · "
                   f"delete {fr.get('file_delete_rate', 0):.1f}/s · "
                   f"modify {fr.get('file_modify_rate', 0):.1f}/s (5 s window)")
        if not fe.empty:
            fe["time"] = fe["ts"].map(fmt_time)
            st.dataframe(fe[["time", "action", "path"]].iloc[::-1], hide_index=True,
                         height=480)
        else:
            st.info("No file-system events in watched folders yet.")

    with t_resp:
        resp = tail_jsonl(SETTINGS.response_log, 100)
        if resp:
            st.dataframe(pd.DataFrame([{"time": fmt_time(e["ts"]), **e["data"]}
                                       for e in reversed(resp)]),
                         hide_index=True)
        else:
            st.info("No response actions taken yet.")

    with t_model:
        st.markdown(f"**Active model:** {state['model']['desc']}")
        m = read_json(SETTINGS.models_dir / "metrics.json")
        if m:
            o = m["overall"]
            c = st.columns(5)
            c[0].metric("Accuracy", f"{o['accuracy']:.1%}")
            c[1].metric("Precision", f"{o['precision']:.1%}")
            c[2].metric("Recall", f"{o['recall']:.1%}")
            c[3].metric("False-positive rate", f"{o['false_positive_rate']:.2%}")
            c[4].metric("Inference / 300 procs", f"{m.get('inference_ms_per_300_rows', 0)} ms")
            if "real_only" in m:
                r = m["real_only"]
                st.caption(f"On real recordings only: accuracy {r['accuracy']:.1%}, "
                           f"recall {r['recall']:.1%}, FPR {r['false_positive_rate']:.2%} (n={r['n']})")
            fi = pd.Series(m.get("feature_importance", {}), name="importance")
            st.markdown("**Feature importance (Random Forest)**")
            st.bar_chart(fi, horizontal=True, height=420)
            with st.expander("Per-scenario detection & raw metrics"):
                st.json(m)
        st.caption(f"Pipeline: scan {perf.get('scan_ms')} ms · detection latency p50 "
                   f"{perf.get('latency_p50_ms')} ms / p95 {perf.get('latency_p95_ms')} ms · "
                   f"{perf.get('events_logged', 0)} events logged · "
                   f"{perf.get('schema_rejected', 0)} rejected by schema")


live()
