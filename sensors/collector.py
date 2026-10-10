"""Collector: runs all sensors, scores processes with the ML model, raises alerts.

Run from the project root::

    python -m sensors.collector                 # live monitoring
    python -m sensors.collector --record        # also append labelled rows to data/dataset.csv
    python -m sensors.collector --duration 600  # stop after 10 minutes

Outputs
    logs/events-YYYYMMDD.jsonl  unified, schema-validated event stream
    logs/alerts.jsonl           threat alerts
    runtime/state.json          live snapshot consumed by the dashboard
    data/dataset.csv            (--record) training rows; label 1 for PIDs listed in
                                data/attack_pids.txt (and their children), else 0

Scheduling (all on one thread, no busy-waiting):
    every fast tick (200 ms)  new PIDs + drained file events -> immediate scoring
    every 1 s                 full process scan + host metrics + scoring
    every 2 s                 network socket scan
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import random
import signal
import statistics
import time
from collections import deque
from datetime import datetime

import numpy as np

from common.config import SETTINGS, Settings
from common.features import FEATURE_COLUMNS, base_name, build_row, explain
from common.jsonio import JsonlWriter, atomic_write_json
from common.response import register_monitor
from common.model import load_model
from common.schema import make_event
from sensors.file_sensor import FileSensor
from sensors.host_sensor import HostSensor
from sensors.network_sensor import NetworkSensor
from sensors.process_sensor import SELF_PID, ProcessSensor

log = logging.getLogger("collector")

META_COLUMNS = ["ts", "pid", "name", "source", "label"]
# OS plumbing spawned under any console program - never label these as the attacker
INFRA_CHILDREN = {"conhost", "werfault", "dllhost"}


class EventLog:
    """Daily-rotated JSONL event stream."""

    def __init__(self, settings: Settings):
        self.dir = settings.logs_dir
        self._day = None
        self._w: JsonlWriter | None = None
        self.count = 0

    def write(self, event: dict) -> None:
        day = datetime.now().strftime("%Y%m%d")
        if day != self._day:
            if self._w:
                self._w.close()
            self._w = JsonlWriter(self.dir / f"events-{day}.jsonl")
            self._day = day
        if self._w.write(event):
            self.count += 1

    @property
    def rejected(self) -> int:
        return self._w.rejected if self._w else 0

    def close(self) -> None:
        if self._w:
            self._w.close()


class DatasetRecorder:
    """Appends feature rows to data/dataset.csv for training in Colab."""

    def __init__(self, settings: Settings, idle_sample: float):
        self.path = settings.dataset_path
        self.attack_file = settings.attack_pids_path
        self.idle_sample = idle_sample
        new = not self.path.exists()
        self._fh = open(self.path, "a", newline="", encoding="utf-8")
        self._csv = csv.writer(self._fh)
        if new:
            self._csv.writerow(META_COLUMNS + FEATURE_COLUMNS)
        self._attack: set[int] = set()
        self._attack_mtime = 0.0
        self.rows = {0: 0, 1: 0}

    def _attack_pids(self) -> set[int]:
        try:
            m = self.attack_file.stat().st_mtime
        except FileNotFoundError:
            return self._attack
        if m != self._attack_mtime:
            self._attack_mtime = m
            pids = set()
            for line in self.attack_file.read_text(encoding="utf-8-sig").split():
                if line.strip().isdigit():
                    pids.add(int(line))
            self._attack |= pids
        return self._attack

    def write(self, samples: list[dict], X: np.ndarray, tree: dict[int, int]) -> None:
        attack = self._attack_pids()
        ts = time.time()
        for s, row in zip(samples, X):
            label = 1 if (_in_tree(s["pid"], attack, tree)
                          and base_name(s["name"]) not in INFRA_CHILDREN) else 0
            if label:
                attack.add(s["pid"])  # children of attack processes become attack PIDs
            idle = (s["cpu_percent"] == 0 and s["write_ops_rate"] == 0)
            if not label and idle and random.random() > self.idle_sample:
                continue
            self._csv.writerow([round(ts, 3), s["pid"], s["name"], "real", label]
                               + [round(float(v), 4) for v in row])
            self.rows[label] += 1
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def _in_tree(pid: int, roots: set[int], parent_of: dict[int, int], depth: int = 8) -> bool:
    for _ in range(depth):
        if pid in roots:
            return True
        pid = parent_of.get(pid)
        if not pid:
            return False
    return False


class Collector:
    def __init__(self, settings: Settings = SETTINGS, record: bool = False,
                 idle_sample: float = 0.05):
        settings.ensure_dirs()
        self.s = settings
        self.model = load_model(settings.model_path)
        self._model_mtime = self._mtime()
        self.host = HostSensor()
        self.procs = ProcessSensor()
        self.net = NetworkSensor()
        self.files = FileSensor(settings.watch_dirs, settings.file_window)
        self.events = EventLog(settings)
        self.alerts = JsonlWriter(settings.alerts_log)
        self.recorder = DatasetRecorder(settings, idle_sample) if record else None

        self.host_now: dict = {}
        self.ctx: dict = {}
        self.scores: dict[int, dict] = {}            # pid -> latest scored row
        self.last_alert: dict[tuple, float] = {}     # (pid, ctime) -> wall time
        self.recent_alerts: deque = deque(maxlen=50)
        self.host_hist: deque = deque(maxlen=settings.history_len)
        self.score_hist: deque = deque(maxlen=settings.history_len)
        self.latency_ms: deque = deque(maxlen=500)
        self.scan_ms: deque = deque(maxlen=100)
        self.started = time.time()
        self._running = True

    # ------------------------------------------------------------------ utils
    def _mtime(self) -> float:
        try:
            return self.s.model_path.stat().st_mtime
        except FileNotFoundError:
            return 0.0

    def _maybe_reload_model(self) -> None:
        """Hot-reload model.pkl after a `git pull` brings a newer one."""
        m = self._mtime()
        if m != self._model_mtime:
            self._model_mtime = m
            try:
                self.model = load_model(self.s.model_path)
                log.info("model reloaded: %s", self.model.describe())
            except Exception as exc:  # keep running on the previous model
                log.error("model reload failed: %s", exc)

    def stop(self, *_):
        self._running = False

    # ---------------------------------------------------------------- scoring
    def _score(self, samples: list[dict], trigger_ts: float | None, record: bool) -> None:
        samples = [s for s in samples if s["pid"] != SELF_PID]
        if not samples:
            return
        for s in samples:
            s["num_conns"], s["num_remote_ips"] = self.net.for_pid(s["pid"])
        X = np.asarray([build_row(s, self.ctx) for s in samples], dtype=np.float64)
        scores = self.model.score(X)
        now = time.time()
        if trigger_ts is not None:
            self.latency_ms.append((now - trigger_ts) * 1000)

        for s, row, sc in zip(samples, X, scores):
            sc = float(sc)
            s["score"] = round(sc, 4)
            s["_row"] = row
            self.scores[s["pid"]] = s
            if sc >= self.s.alert_threshold:
                self._alert(s, row, sc, now, trigger_ts)

        if record and self.recorder is not None:
            tree = {e[0]: e[1] for e in self.procs.tree_rows()}
            self.recorder.write(samples, X, tree)

    def _alert(self, s: dict, row, score: float, now: float, trigger_ts) -> None:
        key = (s["pid"], s["create_time"])
        if now - self.last_alert.get(key, 0.0) < self.s.alert_cooldown:
            return
        self.last_alert[key] = now
        origin = trigger_ts if trigger_ts is not None else s["create_time"]
        data = {
            "pid": s["pid"], "name": s["name"], "score": round(score, 4),
            "reasons": explain(list(row)), "cmdline": s["cmdline"][:500],
            "ppid": s["ppid"], "parent_name": s.get("parent_name", ""),
            "create_time": s["create_time"], "username": s["username"],
            "latency_ms": round(min((now - origin) * 1000, 10_000_000), 1),
            "model": self.model.kind,
            "features": {k: round(float(v), 3) for k, v in zip(FEATURE_COLUMNS, row)},
        }
        ev = make_event("alert", data, ts=now)
        self.alerts.write(ev)
        self.events.write(ev)
        self.recent_alerts.appendleft(ev)
        log.warning("ALERT %.0f%% %s (pid %s): %s", score * 100, s["name"], s["pid"],
                    "; ".join(data["reasons"]))

    # ------------------------------------------------------------------ ticks
    def _drain_files(self) -> list[tuple]:
        file_events = self.files.drain()
        for ts, action, path, is_dir in file_events:
            self.events.write(make_event("file", {"action": action, "path": path,
                                                  "is_dir": is_dir}, ts=ts))
        return file_events

    def _fast_tick(self) -> None:
        file_events = self._drain_files()
        new = self.procs.new_pids()
        targets: set[int] = set()
        if new:
            new_samples = self.procs.sample_pids(new)
            for s in new_samples:
                self.events.write(make_event("process_start", {
                    "pid": s["pid"], "ppid": s["ppid"], "name": s["name"],
                    "cmdline": s["cmdline"][:2000], "username": s["username"]}))
            self.ctx.update(self.files.rates())
            origin = min((s["create_time"] for s in new_samples), default=None)
            self._score(new_samples, origin, record=True)
        if file_events:
            self.ctx.update(self.files.rates())
            targets = set(self.procs.candidates()) - new
            if targets:
                self._score(self.procs.sample_pids(targets), file_events[0][0], record=True)

    def _full_scan(self) -> None:
        t0 = time.perf_counter()
        samples = self.procs.scan()
        self.host_now = self.host.sample(len(samples))
        self.ctx = {**self.files.rates(), "cpu_percent": self.host_now["cpu_percent"]}
        self.events.write(make_event("host", self.host_now))
        self._score(samples, None, record=True)
        alive = {s["pid"] for s in samples}
        self.scores = {p: v for p, v in self.scores.items() if p in alive}
        top = max((s.get("score", 0.0) for s in samples), default=0.0)
        now = time.time()
        self.host_hist.append([round(now, 1), self.host_now["cpu_percent"],
                               self.host_now["mem_percent"]])
        self.score_hist.append([round(now, 1), round(top, 4)])
        self.scan_ms.append((time.perf_counter() - t0) * 1000)

    def _network_scan(self) -> None:
        for row in self.net.scan():
            self.events.write(make_event("network", row))

    def _write_state(self) -> None:
        procs = sorted(self.scores.values(), key=lambda s: s.get("score", 0), reverse=True)
        lat = list(self.latency_ms)
        state = {
            "ts": time.time(), "started": self.started, "pid": SELF_PID,
            "model": {"kind": self.model.kind, "desc": self.model.describe(),
                      "metrics": getattr(self.model, "metrics", {})},
            "threshold": self.s.alert_threshold,
            "host": self.host_now, "file_rates": self.files.rates(),
            "watch_dirs": self.files.watch_dirs,
            "host_history": list(self.host_hist), "score_history": list(self.score_hist),
            "processes": [{k: v for k, v in s.items() if k != "_row"} for s in procs[:150]],
            "tree": self.procs.tree_rows(),
            "connections": self.net.connections[:300],
            "file_events": [{"ts": e[0], "action": e[1], "path": e[2]}
                            for e in list(self.files.recent)[-100:]],
            "alerts": list(self.recent_alerts),
            "perf": {
                "latency_p50_ms": round(statistics.median(lat), 1) if lat else None,
                "latency_p95_ms": round(float(np.percentile(lat, 95)), 1) if lat else None,
                "scan_ms": round(statistics.mean(self.scan_ms), 1) if self.scan_ms else None,
                "events_logged": self.events.count,
                "schema_rejected": self.events.rejected,
            },
            "recording": None if self.recorder is None else self.recorder.rows,
        }
        atomic_write_json(self.s.state_path, state)

    # ------------------------------------------------------------------- loop
    def run(self, duration: float | None = None) -> None:
        register_monitor("collector")
        self.files.start()
        log.info("model: %s", self.model.describe())
        log.info("watching: %s", ", ".join(self.files.watch_dirs) or "(no folders)")
        deadline = time.monotonic() + duration if duration else None
        nxt = {"proc": 0.0, "net": 0.0, "state": 0.0, "model": time.monotonic() + 10}
        try:
            self._network_scan()
            while self._running and (deadline is None or time.monotonic() < deadline):
                tick_start = time.monotonic()
                if tick_start >= nxt["net"]:
                    self._network_scan()
                    nxt["net"] = tick_start + self.s.network_interval
                if tick_start >= nxt["proc"]:
                    self._drain_files()  # fold pending file events into the window first
                    self._full_scan()
                    nxt["proc"] = tick_start + self.s.process_interval
                else:
                    self._fast_tick()
                if tick_start >= nxt["state"]:
                    self._write_state()
                    nxt["state"] = tick_start + self.s.state_interval
                if tick_start >= nxt["model"]:
                    self._maybe_reload_model()
                    nxt["model"] = tick_start + 10
                time.sleep(max(0.0, self.s.fast_tick - (time.monotonic() - tick_start)))
        finally:
            self.files.stop()
            self._write_state()
            self.events.close()
            self.alerts.close()
            if self.recorder:
                self.recorder.close()
                log.info("recorded rows: normal=%d suspicious=%d",
                         self.recorder.rows[0], self.recorder.rows[1])


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--record", action="store_true",
                    help="append labelled feature rows to data/dataset.csv")
    ap.add_argument("--idle-sample", type=float, default=0.05,
                    help="fraction of idle normal rows kept while recording (default 0.05)")
    ap.add_argument("--duration", type=float, default=None, help="seconds to run")
    ap.add_argument("--watch", action="append", default=None,
                    help="folder to watch (repeatable); default Downloads/Documents/Desktop")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    settings = SETTINGS
    if args.watch:
        from dataclasses import replace
        settings = replace(SETTINGS, watch_dirs=[os.path.abspath(w) for w in args.watch])
    c = Collector(settings, record=args.record, idle_sample=args.idle_sample)
    signal.signal(signal.SIGINT, c.stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, c.stop)
    c.run(args.duration)


if __name__ == "__main__":
    main()
