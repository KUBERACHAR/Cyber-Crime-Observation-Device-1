"""File-system telemetry via Watchdog: create/delete/modify/move events in watched dirs.

Events are pushed by Watchdog's observer thread into a lock-free deque; the collector
drains them every fast tick, so a file burst is noticed within ~200 ms.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger(__name__)

_ACTIONS = {"created": "created", "deleted": "deleted", "modified": "modified",
            "moved": "moved"}


class _Handler(FileSystemEventHandler):
    def __init__(self, sink: deque):
        self._sink = sink

    def on_any_event(self, event):
        action = _ACTIONS.get(event.event_type)
        if action is None or (action == "modified" and event.is_directory):
            return  # ignore 'opened'/'closed' and noisy directory-modified events
        self._sink.append((time.time(), action, str(event.src_path), bool(event.is_directory)))


class FileSensor:
    def __init__(self, watch_dirs: list[str], window_s: float = 5.0):
        self.window_s = window_s
        self.watch_dirs = [d for d in watch_dirs if Path(d).is_dir()]
        self._incoming: deque = deque(maxlen=100_000)
        self._window: deque = deque()  # (ts, action) for rate computation
        self.recent: deque = deque(maxlen=200)  # for the dashboard
        self._observer = Observer()
        handler = _Handler(self._incoming)
        for d in self.watch_dirs:
            try:
                self._observer.schedule(handler, d, recursive=True)
            except OSError as exc:
                log.warning("cannot watch %s: %s", d, exc)

    def start(self) -> None:
        self._observer.daemon = True
        self._observer.start()

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=2)

    def drain(self) -> list[tuple]:
        out = []
        while self._incoming:
            ev = self._incoming.popleft()
            out.append(ev)
            self._window.append((ev[0], ev[1]))
            self.recent.append(ev)
        return out

    def rates(self) -> dict:
        cutoff = time.time() - self.window_s
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
        c = {"created": 0, "deleted": 0, "modified": 0, "moved": 0}
        for _, action in self._window:
            c[action] += 1
        w = self.window_s
        return {"file_create_rate": (c["created"] + c["moved"]) / w,
                "file_delete_rate": c["deleted"] / w,
                "file_modify_rate": c["modified"] / w}
