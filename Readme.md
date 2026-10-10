# AI-Based Cyber Crime Observation Device

A lightweight, software-only endpoint telemetry and threat-monitoring engine that
emulates a Security Operations Center (SOC) on a single laptop. It captures host
metrics, active processes, network sockets, and file-system events, classifies
behavior as **Normal** or **Suspicious** using machine learning, and surfaces the
result in a real-time Streamlit dashboard.

See [`spec.md`](spec.md) for the full concept and objectives.

---

## Architecture (two-environment split)

Because training ML models is CPU/GPU heavy, work is split across two machines and
bridged by GitHub:

| Environment | Responsibility |
|-------------|----------------|
| **VS Code (this laptop)** | Sensors, data collection, Streamlit dashboard, git |
| **Google Colab** | Feature engineering + training Random Forest & Isolation Forest |
| **GitHub** | Bridge: push logs/code up, pull trained `model.pkl` back down |

**Key idea:** Colab produces a trained `model.pkl`. The laptop only *loads and runs*
it — running a Random Forest is cheap, so your hardware is never the bottleneck.

---

## Repository layout

```
Code1/
├── common/                    shared by laptop AND Colab
│   ├── config.py              paths, intervals, thresholds (override with CCOD_* env vars)
│   ├── schema.py              unified JSON event envelope + fast validation
│   ├── features.py            the 20-feature vector, LOLBin/shell lists, alert explanations
│   ├── model.py               loads model.pkl, RF+IF threat score (heuristic fallback)
│   ├── response.py            human-in-the-loop termination + protection rules
│   └── jsonio.py              JSONL writer, atomic snapshots, tail reader
├── sensors/                   laptop: telemetry + real-time engine
│   ├── host_sensor.py         CPU / RAM / user sessions
│   ├── process_sensor.py      per-process CPU, memory, threads, I/O rates, cmdline
│   ├── win_fastproc.py        one-syscall snapshot of all processes (Windows fast path)
│   ├── network_sensor.py      sockets: IPs, ports, TCP states, per-process counts
│   ├── file_sensor.py         Watchdog create/delete/modify events + rates
│   └── collector.py           orchestrator: scan → features → score → alert → state.json
├── ml/                        Colab (or local) training
│   ├── generate_dataset.py    synthetic attack + hard-negative scenarios
│   └── train.py               Random Forest + Isolation Forest → models/model.pkl
├── dashboard/app.py           Streamlit SOC dashboard + guided response panel
├── notebooks/train_colab.ipynb  pull repo → train → push model.pkl
├── scripts/
│   ├── start.ps1              start collector + dashboard
│   ├── run_attack_demo.ps1    launch the harmless attack simulation
│   ├── simulate_attack.ps1    rapid file dumping into Downloads (labels itself)
│   └── cleanup_sim.ps1        delete simulation files
├── tests/test_core.py         schema, features, model, sensor speed, response safety
├── models/                    model.pkl + metrics.json (committed: the GitHub bridge)
├── data/                      dataset.csv recorded with --record (committed)
├── logs/  runtime/            event logs, alerts, live state (git-ignored)
├── docs/ROADMAP.md            phase-by-phase development guide
├── docs/SETUP.md              pre-setup checklist, developer setup, training loop
├── requirements.txt           laptop dependencies (ML libs pinned)
└── requirements-colab.txt     Colab dependencies (same pins)
```

### Data flow

```
 sensors (200 ms fast tick / 1 s full scan)
   │ host · process · network · file
   ▼
 features.build_row ──► model.score (RF 0.85 + IF 0.15) ──► alert ≥ 0.70
   │                                                         │
   ├─► logs/events-*.jsonl (schema-validated)                ├─► logs/alerts.jsonl
   ├─► data/dataset.csv (--record, auto-labelled)            └─► runtime/state.json ──► Streamlit
   ▼                                                                                     │
 git push ──► Colab: ml/train.py ──► models/model.pkl ──► git pull (hot-reloaded)        ▼
                                                              user confirms ──► response.py
```

---

## Getting started

Full instructions: [`docs/SETUP.md`](docs/SETUP.md). The ordered development plan is in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q                       # sanity check

python -m sensors.collector               # terminal 1: sensors + ML engine
streamlit run dashboard\app.py            # terminal 2: dashboard at http://localhost:8501

powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1   # harmless demo attack
```

A bootstrap model trained on synthetic data is included, so detection works
immediately. Record your own telemetry with `--record` and retrain in Colab to reach
the accuracy targets on your machine. See SETUP.md part C.

---

## Scope

**In scope:** endpoint resource tracking, network connection tracking, file
create/delete events, supervised ML classification, real-time dashboard, and
**human-in-the-loop active response** — on an alert the dashboard asks permission
and terminates a flagged process only after the user confirms (see
[`common/response.py`](common/response.py)). Core system processes and the monitor
itself are always protected.

**Out of scope:** kernel/Ring-0 inspection, *automated* (no-confirmation) response
or remote endpoint isolation, TLS payload decryption, multi-tenant cloud database
sync.
