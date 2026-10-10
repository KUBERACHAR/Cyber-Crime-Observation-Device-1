# Development roadmap

The phases are in dependency order. The code for every phase already exists in this
repository. Your job in each phase is to **understand it, run it, measure it, and
improve it on your own data**. Each phase ends with acceptance criteria you can show
your guide or reviewers.

Suggested pace for a semester project: about 10 weeks.

```
Phase 0  Setup ──► 1 Sensors ──► 2 Event schema ──► 3 Data collection ──► 4 Training (Colab)
                                                                              │
Phase 9  Demo ◄── 8 Evaluation ◄── 7 Active response ◄── 6 Dashboard ◄── 5 Real-time inference
```

---

### Phase 0: Environment and repository (week 1)
* Do the pre-setup items in [SETUP.md](SETUP.md) (part A).
* Create the venv, install `requirements.txt`, push to your private GitHub repo.
* **Done when:** `python -m pytest -q` passes, and the repo is visible on GitHub.

### Phase 1: Sensors (weeks 1–2)
| Sensor | File | What it captures |
|--------|------|------------------|
| Host | `sensors/host_sensor.py` | CPU %, RAM %, process count, logged-in user sessions |
| Process | `sensors/process_sensor.py`, `sensors/win_fastproc.py` | Every process: parent, name, command line, user, CPU, memory, threads, read/write I/O rates |
| Network | `sensors/network_sensor.py` | Every inet socket: local/remote IP:port, TCP state, owning PID, per-process remote-IP count |
| File | `sensors/file_sensor.py` | Watchdog create/delete/modify/move events in Downloads, Documents and Desktop, plus rates over a 5 s window |

Key design decision: on Windows, psutil opens a handle per process per attribute,
costing about 1.6 s for 300 processes. `win_fastproc.py` gets all counters for all
processes from **one** `NtQuerySystemInformation` call (about 6 ms), so a full scan
takes about 50 ms.
* **Done when:** `python -m sensors.collector --duration 60` runs and
  `logs/events-*.jsonl` has `host`, `process_start`, `network` and `file` events.

### Phase 2: Unified event schema (week 2)
* `common/schema.py` defines one envelope (`schema`, `ts`, `host`, `type`, `data`) and
  required typed fields per event type. Every event is validated before it is written.
* **Done when:** the dashboard's Model tab shows `0 rejected by schema`, and you can
  explain each event type.

### Phase 3: Data collection and labelling (weeks 3–4)
* `--record` mode writes one row per process observation to `data/dataset.csv`, with
  20 features (`common/features.py`) and a label.
* Labels come from `data/attack_pids.txt`, which `scripts/simulate_attack.ps1`
  writes. That process and its children are 1, and everything else is 0. Idle normal
  rows are subsampled to 5% so the dataset stays small.
* Record at least **45 minutes of normal use** across browsing, coding, PDF reading and
  package installs, plus **10 or more attack runs** of different sizes. See SETUP.md
  part C.
* *Extension idea:* write more harmless simulations (an encoded-command PowerShell
  that only prints, or `certutil` downloading a public text file) and add their PIDs
  to `attack_pids.txt`.
* **Done when:** `dataset.csv` has several thousand normal rows and a few hundred
  suspicious rows.

### Phase 4: Feature engineering and training in Colab (weeks 4–5)
* `notebooks/train_colab.ipynb` clones the repo, inspects the data, runs `ml/train.py`
  and pushes `models/model.pkl` back.
* **Random Forest** (supervised, 200 trees, depth 18, balanced classes) gives
  P(suspicious). **Isolation Forest** (unsupervised, fitted on normal rows only) gives
  an anomaly score. Final score = `0.85·RF + 0.15·IF`, alert at ≥ 0.70.
* `ml/generate_dataset.py` adds synthetic scenarios: PowerShell file dumping,
  ransomware-like I/O, download cradles, LOLBins and exfiltration. It also adds
  **hard negatives**: npm installs, zip extraction, OneDrive sync, and VS Code's
  PowerShell host with `-ExecutionPolicy Bypass`. These teach the model that "many
  files" or "bypass flag" alone is not an attack.
* Features are computed **on the laptop** using the same `build_row()` live and in
  training, so the two can never drift apart.
* **Done when:** `models/metrics.json` shows accuracy > 90% **on the `real_only`
  split**, not only overall.

### Phase 5: Real-time inference and alerting (week 6)
* `sensors/collector.py` runs on one thread with three cadences:
  * **Fast tick every 200 ms:** new PIDs and drained file events trigger immediate
    scoring of the new processes and of the likely culprits (recent processes, shells,
    LOLBins).
  * **Every 1 s:** full process scan and host metrics.
  * **Every 2 s:** network scan.
* The model batch-scores about 300 processes in roughly 15–25 ms. Thread fan-out is
  disabled because it costs more than it saves for small batches.
* Alerts include the score, plain-language reasons (`features.explain`), command
  line, parent and detection latency. The same process won't re-alert for 30 s.
* `git pull` of a new `model.pkl` is hot-reloaded without restarting.
* **Done when:** latency p95 is **≤ 500 ms** on the dashboard during the attack
  simulation.

### Phase 6: SOC dashboard (week 7)
* `dashboard/app.py` (Streamlit) shows a red/green threat banner, KPI tiles, a
  threat-score timeline, CPU/RAM history, an alert history, and process, network,
  file-activity, response-log and model tabs.
* It reads `runtime/state.json`, which the collector writes atomically. The UI and
  the sensors are separate processes, so restarting one doesn't affect the other.
* **Done when:** the attack simulation turns the banner red and the alert appears
  with its reasons.

### Phase 7: Human-in-the-loop active response (week 7)
* Clicking **Respond** opens a panel with the evidence, the process tree and an
  explicit confirmation checkbox. Termination only happens after that.
* `common/response.py` enforces its safety rules on the server side, not only in the
  UI:
  * Core OS processes (lsass, csrss, svchost and others) are never terminated.
  * The monitor and its ancestors are never terminated.
  * A **PID-reuse check** compares `create_time`, so a recycled PID is never killed.
  * Termination is graceful first, then forced.
  * Every attempt is written to `logs/response.jsonl`.
* **Done when:** you can terminate the simulation from the UI and see the entry in the
  Response log tab.

### Phase 8: Evaluation and report (weeks 8–9)
Report these numbers, all produced by the system itself:

| Objective | Target | Where to read it |
|-----------|--------|------------------|
| Detection accuracy | > 90% | `models/metrics.json` → `real_only.accuracy` |
| False positives in routine work | low | `real_only.false_positive_rate`, plus a 30-minute normal session with **zero** alerts |
| End-to-end latency | < 500 ms | Dashboard KPI *Detect latency p95*; `latency_ms` in each alert |
| Schema consistency | 100% | `schema_rejected = 0` |
| Scan overhead | low | Dashboard *scan ms* (about 35–60 ms). The collector uses about 2–3% of one CPU core and about 180 MB RAM |

Also include per-scenario detection rates, feature importance (Model tab), a
confusion matrix and an ablation such as RF-only versus RF+IF.

### Phase 9: Demo rehearsal (week 10)
Follow the spec's demonstration flow:
1. **System start:** `scripts\start.ps1`. Chrome and VS Code are running and the
   banner is green.
2. **Attack trigger:** `scripts\run_attack_demo.ps1`. PowerShell starts dumping
   files into Downloads.
3. **AI evaluation:** the feature vector is scored, with a threat probability of
   about 90% or higher.
4. **Dashboard alert:** the red banner shows the reasons, the latency in ms and the
   process tree.
5. **Guided response:** Respond → confirm → Terminate. The Response log shows
   `terminated`.
6. Clean up with `scripts\cleanup_sim.ps1`.

---

### Possible extensions (beyond scope)
* Attribute file events to the process that caused them using ETW (Windows) or
  fanotify (Linux).
* Add per-user baselines and time-of-day features.
* Use SHAP values for per-alert explanations instead of rule-based reasons.
* Export alerts to Sysmon/SIEM formats (ECS, CEF).
