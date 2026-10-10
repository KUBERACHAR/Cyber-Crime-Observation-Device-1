"""Central configuration: paths, intervals and thresholds shared by every module.

Values can be overridden with environment variables prefixed ``CCOD_`` (e.g.
``CCOD_ALERT_THRESHOLD=0.8``) so the same code runs unchanged on the laptop and
in Google Colab.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default):
    raw = os.environ.get(f"CCOD_{name}")
    if raw is None:
        return default
    return type(default)(raw)


def _default_watch_dirs() -> list[str]:
    home = Path.home()
    dirs = [home / "Downloads", home / "Documents", home / "Desktop"]
    return [str(d) for d in dirs if d.is_dir()]


@dataclass(frozen=True)
class Settings:
    # --- paths -------------------------------------------------------------
    root: Path = ROOT
    logs_dir: Path = ROOT / "logs"
    runtime_dir: Path = ROOT / "runtime"
    data_dir: Path = ROOT / "data"
    models_dir: Path = ROOT / "models"

    # --- sensor timing (seconds) ------------------------------------------
    fast_tick: float = _env("FAST_TICK", 0.2)        # new-PID / file-event check
    process_interval: float = _env("PROCESS_INTERVAL", 1.0)
    network_interval: float = _env("NETWORK_INTERVAL", 2.0)
    state_interval: float = _env("STATE_INTERVAL", 1.0)
    file_window: float = _env("FILE_WINDOW", 5.0)    # rate window for file events

    # --- detection ---------------------------------------------------------
    alert_threshold: float = _env("ALERT_THRESHOLD", 0.70)
    alert_cooldown: float = _env("ALERT_COOLDOWN", 30.0)  # per-process re-alert gap
    rf_weight: float = _env("RF_WEIGHT", 0.85)            # remainder -> IsolationForest

    # --- dashboard ----------------------------------------------------------
    history_len: int = _env("HISTORY_LEN", 300)
    watch_dirs: list[str] = field(default_factory=_default_watch_dirs)

    @property
    def model_path(self) -> Path:
        return self.models_dir / "model.pkl"

    @property
    def dataset_path(self) -> Path:
        return self.data_dir / "dataset.csv"

    @property
    def attack_pids_path(self) -> Path:
        return self.data_dir / "attack_pids.txt"

    @property
    def state_path(self) -> Path:
        return self.runtime_dir / "state.json"

    @property
    def monitor_pids_path(self) -> Path:
        return self.runtime_dir / "monitor_pids.json"

    @property
    def alerts_log(self) -> Path:
        return self.logs_dir / "alerts.jsonl"

    @property
    def response_log(self) -> Path:
        return self.logs_dir / "response.jsonl"

    def ensure_dirs(self) -> None:
        for d in (self.logs_dir, self.runtime_dir, self.data_dir, self.models_dir):
            d.mkdir(parents=True, exist_ok=True)


SETTINGS = Settings()
