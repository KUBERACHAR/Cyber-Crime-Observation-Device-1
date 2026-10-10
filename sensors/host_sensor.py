"""Host-level telemetry: CPU, RAM, process count and logged-in user sessions."""
from __future__ import annotations

import time

import psutil


class HostSensor:
    def __init__(self):
        psutil.cpu_percent(None)  # prime the counter so the first sample is meaningful
        self._users_cache: tuple[float, list] = (0.0, [])

    def _users(self) -> list[dict]:
        now = time.monotonic()
        if now - self._users_cache[0] > 10:  # sessions rarely change; avoid the syscall
            try:
                users = [{"name": u.name, "terminal": u.terminal or "", "host": u.host or "",
                          "started": u.started} for u in psutil.users()]
            except Exception:
                users = []
            self._users_cache = (now, users)
        return self._users_cache[1]

    def sample(self, process_count: int) -> dict:
        vm = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(None),
            "mem_percent": vm.percent,
            "mem_used_gb": round(vm.used / 2**30, 2),
            "mem_total_gb": round(vm.total / 2**30, 2),
            "process_count": process_count,
            "users": self._users(),
        }
