"""Unit tests: schema, features, model, sensors and the active-response safety rules.

    python -m pytest -q
"""
from __future__ import annotations

import subprocess
import sys
import time

import numpy as np
import psutil
import pytest

from common import response
from common.features import FEATURE_COLUMNS, build_row, cmdline_risk, explain
from common.model import HeuristicModel, ModelMismatchError, ThreatModel
from common.schema import SchemaError, make_event, validate_event


# ------------------------------------------------------------------------- schema
def test_valid_events_pass():
    validate_event(make_event("file", {"action": "created", "path": "C:/x", "is_dir": False}))
    validate_event(make_event("host", {"cpu_percent": 1.0, "mem_percent": 2, "process_count": 3,
                                       "users": []}))


@pytest.mark.parametrize("event", [
    {"schema": 99, "ts": 1, "type": "file", "data": {}},
    make_event("file", {"action": "exploded", "path": "x", "is_dir": False}),
    make_event("file", {"action": "created", "path": 5, "is_dir": False}),
    make_event("nope", {}),
    make_event("alert", {"pid": 1, "name": "x", "score": 0.5}),  # missing reasons
])
def test_invalid_events_rejected(event):
    with pytest.raises(SchemaError):
        validate_event(event)


# ----------------------------------------------------------------------- features
def test_cmdline_risk_orders_sensibly():
    benign = cmdline_risk("C:\\Program Files\\Google\\Chrome\\chrome.exe --type=renderer")
    vscode = cmdline_risk("pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command Import-Module x")
    evil = cmdline_risk("powershell -nop -w hidden -enc SQBFAFgA -ep bypass")
    assert benign == 0 < vscode < evil


def test_build_row_matches_columns_and_explains():
    row = build_row({"name": "powershell.exe", "cmdline": "powershell -enc AAAA", "age_s": 2,
                     "write_ops_rate": 300, "parent_name": "WINWORD.EXE"},
                    {"file_create_rate": 50})
    assert len(row) == len(FEATURE_COLUMNS)
    f = dict(zip(FEATURE_COLUMNS, row))
    assert f["is_shell"] == 1 and f["parent_is_office"] == 1
    text = " ".join(explain(row))
    assert "High write rate" in text and "File creation burst" in text


# -------------------------------------------------------------------------- model
@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    from ml.generate_dataset import generate
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    header, rows = generate(6000, seed=1)
    data = np.array([r[len(header) - len(FEATURE_COLUMNS):] for r in rows], dtype=float)
    y = np.array([r[header.index("label")] for r in rows])
    rf = RandomForestClassifier(60, max_depth=14, random_state=0).fit(data[:5000], y[:5000])
    iso = IsolationForest(n_estimators=50, random_state=0).fit(data[:5000][y[:5000] == 0])
    model = ThreatModel({"rf": rf, "iforest": iso, "if_range": (0.4, 0.7),
                         "features": FEATURE_COLUMNS})
    return model, data[5000:], y[5000:]


def test_model_accuracy_above_target(trained):
    model, X, y = trained
    acc = ((model.score(X) >= 0.7).astype(int) == y).mean()
    assert acc > 0.90


def test_model_rejects_feature_mismatch():
    with pytest.raises(ModelMismatchError):
        ThreatModel({"rf": None, "features": ["a", "b"]})


def test_heuristic_flags_demo_attack():
    attack = build_row({"name": "powershell.exe", "cmdline": "powershell -nop -ep bypass -File x.ps1",
                        "write_ops_rate": 400, "age_s": 3}, {"file_create_rate": 60})
    browser = build_row({"name": "chrome.exe", "cmdline": "chrome.exe", "age_s": 5000}, {})
    s = HeuristicModel().score(np.array([attack, browser]))
    assert s[0] > 0.7 > s[1]


# ------------------------------------------------------------------------ sensors
def test_process_sensor_scan_is_fast_and_complete():
    from sensors.process_sensor import ProcessSensor
    ps = ProcessSensor()
    ps.scan()
    t0 = time.perf_counter()
    samples = ps.scan()
    elapsed = time.perf_counter() - t0
    assert len(samples) > 5
    assert {"pid", "name", "cpu_percent", "write_ops_rate", "parent_name"} <= samples[0].keys()
    assert elapsed < 0.5, f"full scan took {elapsed * 1000:.0f} ms"


# ----------------------------------------------------------------------- response
def test_core_and_monitor_processes_are_protected():
    assert response.is_protected(4)[0]
    assert response.is_protected(1234, "lsass.exe")[0]
    assert response.is_protected(psutil.Process().pid)[0]  # the monitor itself


@pytest.fixture
def victim():
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    yield p
    if p.poll() is None:
        p.kill()


def test_terminate_requires_confirmation(victim):
    res = response.terminate_process(victim.pid, confirmed=False)
    assert res["data"]["result"] == "refused" and victim.poll() is None


def test_terminate_detects_pid_reuse(victim):
    ctime = psutil.Process(victim.pid).create_time()
    res = response.terminate_process(victim.pid, expected_create_time=ctime - 100, confirmed=True)
    assert res["data"]["result"] == "pid_reused" and victim.poll() is None


def test_terminate_confirmed(victim):
    ctime = psutil.Process(victim.pid).create_time()
    res = response.terminate_process(victim.pid, expected_create_time=ctime, confirmed=True)
    assert res["data"]["result"] == "terminated"
    victim.wait(timeout=5)
