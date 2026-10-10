"""Process telemetry with incremental, low-overhead sampling.

* Dynamic counters (CPU time, threads, memory, I/O) for *all* processes come from one
  call: ``NtQuerySystemInformation`` on Windows (~6 ms for 300 processes, see
  ``win_fastproc``), ``psutil.process_iter`` elsewhere.
* Static attributes (command line, user) are read once per process and cached.
* Rates (CPU %, write ops/s, KB/s) are computed from deltas between samples.
* ``new_pids()`` uses the cheap ``psutil.pids()`` so new processes are noticed within one
  fast tick (~200 ms) instead of waiting for the next full scan.
"""
from __future__ import annotations

import os
import time
from collections import Counter

import psutil

from common.features import LOLBINS, SHELLS, base_name
from sensors import win_fastproc

NCPU = psutil.cpu_count() or 1
SELF_PID = os.getpid()
TOTAL_MEM = psutil.virtual_memory().total

# snapshot tuple layout: (ppid, name, threads, create_time, cpu_s, rss, r_ops, w_ops, w_bytes)
PPID, NAME, THREADS, CTIME, CPU_S, RSS, R_OPS, W_OPS, W_BYTES = range(9)


def _psutil_snapshot() -> dict[int, tuple]:
    attrs = ["ppid", "name", "num_threads", "create_time", "cpu_times", "memory_info"]
    out = {}
    for p in psutil.process_iter(attrs):
        i = p.info
        try:
            io = p.io_counters()
            r_ops, w_ops, w_bytes = io.read_count, io.write_count, io.write_bytes
        except (psutil.Error, AttributeError, OSError):
            r_ops = w_ops = w_bytes = 0
        ct = i["cpu_times"]
        out[p.pid] = (i["ppid"], i["name"] or "", i["num_threads"] or 0, i["create_time"] or 0.0,
                      (ct.user + ct.system) if ct else 0.0,
                      i["memory_info"].rss if i["memory_info"] else 0, r_ops, w_ops, w_bytes)
    return out


_snapshot = win_fastproc.snapshot if win_fastproc.IS_SUPPORTED else _psutil_snapshot


class ProcessSensor:
    def __init__(self):
        self._snap: dict[int, tuple] = {}
        self._static: dict[int, tuple] = {}     # pid -> (create_time, cmdline, username)
        self._prev: dict[int, tuple] = {}       # pid -> (mono_t, create_time, cpu_s, r, w, wb)
        self._known_pids: set[int] = set(psutil.pids())

    # -- discovery ----------------------------------------------------------
    def new_pids(self) -> set[int]:
        current = set(psutil.pids())
        new = current - self._known_pids
        self._known_pids = current
        return new

    def _static_info(self, pid: int, ctime: float) -> tuple[str, str | None]:
        cached = self._static.get(pid)
        if cached and abs(cached[0] - ctime) < 1.0:
            return cached[1], cached[2]
        cmd, user = "", None
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                try:
                    cmd = " ".join(p.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    pass
                try:
                    user = p.username()
                except (psutil.AccessDenied, OSError):
                    pass
        except psutil.Error:
            pass
        self._static[pid] = (ctime, cmd, user)
        return cmd, user

    # -- sampling -----------------------------------------------------------
    def _build(self, pid: int, row: tuple, now_mono: float, now_wall: float,
               children: Counter) -> dict:
        cmd, user = self._static_info(pid, row[CTIME])
        cpu = w_ops = w_kb = r_ops = 0.0
        prev = self._prev.get(pid)
        if prev and abs(prev[1] - row[CTIME]) < 1.0 and now_mono > prev[0]:
            dt = now_mono - prev[0]
            cpu = max(0.0, row[CPU_S] - prev[2]) / dt / NCPU * 100
            r_ops = max(0, row[R_OPS] - prev[3]) / dt
            w_ops = max(0, row[W_OPS] - prev[4]) / dt
            w_kb = max(0, row[W_BYTES] - prev[5]) / 1024 / dt
        self._prev[pid] = (now_mono, row[CTIME], row[CPU_S], row[R_OPS], row[W_OPS], row[W_BYTES])

        parent = self._snap.get(row[PPID])
        # a parent PID can be recycled: only trust it if it started before the child
        parent_name = parent[NAME] if parent and parent[CTIME] <= row[CTIME] + 1 else ""
        return {
            "pid": pid, "ppid": row[PPID], "name": row[NAME], "cmdline": cmd,
            "username": user, "create_time": row[CTIME],
            "age_s": max(0.0, now_wall - row[CTIME]) if row[CTIME] else 1e6,
            "cpu_percent": round(min(cpu, 100.0), 2),
            "mem_percent": round(row[RSS] / TOTAL_MEM * 100, 3),
            "num_threads": row[THREADS], "read_ops_rate": round(r_ops, 2),
            "write_ops_rate": round(w_ops, 2), "write_kb_rate": round(w_kb, 2),
            "parent_name": parent_name, "num_children": children.get(pid, 0),
        }

    def _sample(self, pids=None) -> list[dict]:
        self._snap = _snapshot()
        now_mono, now_wall = time.monotonic(), time.time()
        children = Counter(r[PPID] for r in self._snap.values())
        targets = self._snap.keys() if pids is None else [p for p in pids if p in self._snap]
        return [self._build(pid, self._snap[pid], now_mono, now_wall, children)
                for pid in targets if pid not in (0, SELF_PID)]

    def scan(self) -> list[dict]:
        """Sample every process; prune state for processes that exited."""
        out = self._sample()
        alive = self._snap.keys()
        self._known_pids = set(alive)
        for d in (self._prev, self._static):
            for pid in [p for p in d if p not in alive]:
                del d[pid]
        return out

    def sample_pids(self, pids) -> list[dict]:
        """Sample only ``pids`` (fast path for new processes / file bursts)."""
        return self._sample(pids)

    def candidates(self, max_age_s: float = 60.0) -> list[int]:
        """PIDs worth re-scoring on a file burst: recent processes, shells and LOLBins."""
        t = time.time()
        return [pid for pid, r in self._snap.items()
                if pid not in (0, SELF_PID) and (t - r[CTIME] < max_age_s
                                                 or base_name(r[NAME]) in SHELLS
                                                 or base_name(r[NAME]) in LOLBINS)]

    def tree_rows(self) -> list[list]:
        """Compact [pid, ppid, name] list used by the dashboard's process tree."""
        return [[pid, r[PPID], r[NAME]] for pid, r in self._snap.items()]
