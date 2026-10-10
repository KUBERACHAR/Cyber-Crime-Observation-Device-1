# Setup guide

Two parts: **A. pre-setup** (accounts and installs only you can do) and **B. developer
setup** (getting the project running, then the daily workflow).

---

## A. Pre-setup: what you need to do first

| # | Item | Why | How / notes |
|---|------|-----|-------------|
| 1 | **Windows 10/11, 64-bit** laptop | Sensors use a Windows fast path (`NtQuerySystemInformation`) | Linux/macOS also work through a slower psutil fallback, but the demo scripts are PowerShell |
| 2 | **Python 3.11 – 3.13 (64-bit)** | Runtime | python.org installer. Tick **"Add python.exe to PATH"**. Check with `python --version` |
| 3 | **Git** | Push data to Colab, pull the model back | git-scm.com. Then `git config --global user.name "..."` and `user.email` |
| 4 | **VS Code** + *Python* extension | Development | Select the `.venv` interpreter when prompted |
| 5 | **GitHub account** + an empty **private** repo | Bridge between the laptop and Colab | Don't let GitHub add a README. Private, because telemetry contains process names and paths |
| 6 | **Google account** | Google Colab for training | colab.research.google.com |
| 7 | **GitHub fine-grained token** | Lets Colab push `model.pkl` back | GitHub → Settings → Developer settings → Fine-grained tokens → only this repo → *Contents: Read and write*. Store it in Colab's 🔑 Secrets as `GITHUB_TOKEN`. **Never paste it into the notebook or commit it** |
| 8 | **PowerShell script policy** | Run the `scripts\*.ps1` helpers | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (one time) |
| 9 | *(optional)* **Administrator terminal** | Lets you terminate elevated processes and see more command lines | Normal user rights are enough for the demo |

---

## B. Developer setup

### 1. Get the code into your repo
```powershell
cd D:\MajorProject\Code1
git init -b main
git add .
git commit -m "Initial commit: CCOD"
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

### 2. Create the environment
```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```
`numpy`, `scikit-learn` and `joblib` are pinned to the same versions as
`requirements-colab.txt`. **Keep the two files in sync.** A model pickled by one
scikit-learn version may not load in another, and the collector warns you if they
differ.

### 3. Verify
```powershell
python -m pytest -q          # expect: 16 passed
```

### 4. First run (two terminals, both with `.venv` activated, from the project root)
```powershell
# terminal 1: sensors + ML engine
python -m sensors.collector

# terminal 2: dashboard -> opens http://localhost:8501
streamlit run dashboard\app.py
```
You can also run `powershell -ExecutionPolicy Bypass -File scripts\start.ps1`, which
does both.

### 5. Fire the harmless attack simulation
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1
```
Within about a second the dashboard turns red. Open **Alerts → Respond**, review the
evidence, tick the confirmation box and press **Terminate process**. Then clean up with:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\cleanup_sim.ps1
```

---

## C. The training loop (laptop → Colab → laptop)

The shipped `models/model.pkl` was trained on **synthetic** data so the system works
on day one. To reach the accuracy target on *your* machine you have to record real
telemetry.

### 1. Record a normal baseline (label 0)
```powershell
python -m sensors.collector --record --duration 900
```
While it runs, use the laptop normally: browse, edit code in VS Code, read PDFs, run
`git`/`npm`/`pip`, and download a file. Do 2–3 sessions on different days or with
different workloads.

### 2. Record attacks (label 1)
Keep a recording collector running and launch the simulation several times with
different sizes:
```powershell
python -m sensors.collector --record           # terminal 1 (leave running)
powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1 -Waves 5    # terminal 2
powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1 -Waves 20
```
Labelling is automatic: the simulation writes its PID to `data\attack_pids.txt`. Rows
for that process and its children get label 1, and everything else gets label 0.
Background activity during the attack is therefore correctly recorded as normal.
Afterwards, run `scripts\cleanup_sim.ps1` to remove the files and reset the PID list.

### 3. Push the data, train in Colab, pull the model
```powershell
git add data/dataset.csv
git commit -m "Add recorded telemetry"
git push
```
Open `notebooks/train_colab.ipynb` in Colab (*File → Open notebook → GitHub*), set
`GITHUB_USER`/`REPO` and run all cells. The last cell pushes `models/model.pkl` and
`models/metrics.json`. Then:
```powershell
git pull
```
A running collector hot-reloads the new model within 10 seconds. You can also train
locally with `python -m ml.train` (it takes a few seconds).

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard says *Waiting for telemetry* | Start the collector **from the project root** (`python -m sensors.collector`) |
| `ModelMismatchError` | `common/features.py` changed after training: retrain the model |
| Warning *model.pkl was trained with scikit-learn X* | Make the pins in `requirements.txt` and `requirements-colab.txt` identical, reinstall, retrain |
| Terminate returns `denied` | The process runs elevated: start the dashboard from an Administrator terminal |
| Terminate returns `protected` | By design: core OS processes and the monitor itself can never be stopped |
| Too many false alerts | Record more normal sessions (step C1) and retrain, or raise the threshold: `$env:CCOD_ALERT_THRESHOLD="0.8"` |
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| No file events | Only `Downloads`, `Documents` and `Desktop` are watched by default. Add more with `--watch D:\path` |

### Attack Demonstration
* ``` powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1 -Waves 30 ```
* ``` powershell -ExecutionPolicy Bypass -File scripts\cleanup_sim.ps1 ```