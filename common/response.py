"""Human-in-the-loop active response.

The dashboard calls :func:`terminate_process` only after the user explicitly confirms.
Safety rules enforced here (never in the UI alone):

* Core OS processes (by name, and PIDs 0/4/1) are never touched.
* The monitor itself (collector + dashboard and their ancestors) is never touched.
* The PID must still belong to the *same* process that raised the alert
  (``create_time`` check) - this prevents killing an unrelated process that reused
  the PID after the original exited.
* Every attempt, successful or not, is appended to ``logs/response.jsonl``.
"""
from __future__ import annotations

import os

import psutil

from .config import SETTINGS
from .features import base_name
from .jsonio import JsonlWriter, atomic_write_json, read_json
from .schema import make_event

PROTECTED_NAMES = {
    # Windows
    "system", "system idle process", "registry", "smss", "csrss", "wininit", "winlogon",
    "services", "lsass", "lsaiso", "svchost", "dwm", "explorer", "fontdrvhost",
    "memory compression", "secure system", "spoolsv", "taskmgr", "sihost", "ctfmon",
    "msmpeng", "securityhealthservice", "audiodg", "runtimebroker",
    # Linux / macOS
    "init", "systemd", "launchd", "kthreadd", "sshd", "xorg", "gnome-shell", "loginwindow",
    "windowserver", "kernel_task",
}
PROTECTED_PIDS = {0, 1, 4}


def register_monitor(role: str) -> None:
    """Record this process (with its start time, to survive PID reuse) as part of the monitor."""
    SETTINGS.ensure_dirs()
    reg = read_json(SETTINGS.monitor_pids_path, {}) or {}
    reg[role] = [os.getpid(), psutil.Process().create_time()]
    atomic_write_json(SETTINGS.monitor_pids_path, reg)


def monitor_pids() -> set[int]:
    """PIDs of the monitor (this process, live registered monitor processes, their ancestors)."""
    pids = {os.getpid()}
    for entry in (read_json(SETTINGS.monitor_pids_path, {}) or {}).values():
        try:
            pid, ctime = entry
            if abs(psutil.Process(pid).create_time() - ctime) < 1.0:  # not a stale/reused PID
                pids.add(pid)
        except (psutil.Error, TypeError, ValueError):
            continue
    for pid in list(pids):
        try:
            pids.update(p.pid for p in psutil.Process(pid).parents())
        except psutil.Error:
            pass
    return pids


def is_protected(pid: int, name: str | None = None) -> tuple[bool, str]:
    if pid in PROTECTED_PIDS:
        return True, "core system PID"
    if name is None:
        try:
            name = psutil.Process(pid).name()
        except psutil.Error:
            name = ""
    if base_name(name) in PROTECTED_NAMES:
        return True, f"core system process '{name}'"
    if pid in monitor_pids():
        return True, "part of the monitor itself"
    return False, ""


def _log(pid: int, name: str, result: str, detail: str, user_note: str = "") -> dict:
    SETTINGS.ensure_dirs()
    event = make_event("response", {"pid": pid, "name": name, "result": result,
                                    "detail": detail, "note": user_note})
    w = JsonlWriter(SETTINGS.response_log)
    try:
        w.write(event)
    finally:
        w.close()
    return event


def terminate_process(pid: int, expected_create_time: float | None = None,
                      confirmed: bool = False, timeout: float = 3.0,
                      user_note: str = "") -> dict:
    """Terminate ``pid`` (gracefully, then forcefully). Returns the logged response event."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        ctime = proc.create_time()
    except psutil.NoSuchProcess:
        return _log(pid, "?", "not_found", "process already exited", user_note)
    except psutil.AccessDenied:
        return _log(pid, "?", "denied", "access denied reading process", user_note)

    if not confirmed:
        return _log(pid, name, "refused", "user confirmation required", user_note)
    protected, why = is_protected(pid, name)
    if protected:
        return _log(pid, name, "protected", why, user_note)
    if expected_create_time is not None and abs(ctime - expected_create_time) > 1.0:
        return _log(pid, name, "pid_reused",
                    "PID now belongs to a different process; not terminated", user_note)

    try:
        safe = monitor_pids()
        children = [c for c in proc.children(recursive=True) if c.pid not in safe]
        for p in [proc, *children]:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                pass
        gone, alive = psutil.wait_procs([proc, *children], timeout=timeout)
        for p in alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
        detail = f"terminated (+{len(children)} child process(es))"
        if alive:
            detail += f"; force-killed {len(alive)}"
        return _log(pid, name, "terminated", detail, user_note)
    except psutil.AccessDenied:
        return _log(pid, name, "denied",
                    "access denied - run the dashboard as Administrator to stop this process",
                    user_note)
