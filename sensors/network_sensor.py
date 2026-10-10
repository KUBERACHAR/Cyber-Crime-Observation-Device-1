"""Network socket telemetry: per-process connection counts and new-connection events."""
from __future__ import annotations

from collections import defaultdict

import psutil

_LOCAL_PREFIXES = ("127.", "::1", "0.0.0.0", "::", "fe80")


def _fmt(addr) -> str:
    if not addr:
        return ""
    return f"[{addr.ip}]:{addr.port}" if ":" in addr.ip else f"{addr.ip}:{addr.port}"


class NetworkSensor:
    def __init__(self):
        self._seen: set[tuple] = set()
        self.per_pid: dict[int, tuple[int, int]] = {}
        self.connections: list[dict] = []

    def scan(self) -> list[dict]:
        """Refresh state; return connections that are new since the previous scan."""
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []  # macOS without root - degrade gracefully
        counts: dict[int, int] = defaultdict(int)
        remotes: dict[int, set] = defaultdict(set)
        current, rows, new = set(), [], []
        for c in conns:
            pid = c.pid or 0
            raddr = _fmt(c.raddr)
            row = {"pid": c.pid, "laddr": _fmt(c.laddr), "raddr": raddr,
                   "status": c.status or "NONE"}
            rows.append(row)
            if c.raddr:
                counts[pid] += 1
                if not c.raddr.ip.startswith(_LOCAL_PREFIXES):
                    remotes[pid].add(c.raddr.ip)
                key = (pid, row["laddr"], raddr)
                current.add(key)
                if key not in self._seen:
                    new.append(row)
        self._seen = current
        self.per_pid = {pid: (counts[pid], len(remotes[pid])) for pid in counts}
        self.connections = rows
        return new

    def for_pid(self, pid: int) -> tuple[int, int]:
        return self.per_pid.get(pid, (0, 0))
