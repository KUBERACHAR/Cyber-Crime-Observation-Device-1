"""Small, robust JSON helpers: append-only JSONL logs, atomic snapshots, tail reads."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .schema import validate_event


class JsonlWriter:
    """Thread-safe, line-buffered JSONL appender that validates every event."""

    def __init__(self, path: Path, validate: bool = True):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._validate = validate
        self._fh = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        self.rejected = 0

    def write(self, event: dict) -> bool:
        if self._validate:
            try:
                validate_event(event)
            except ValueError:
                self.rejected += 1
                return False
        line = json.dumps(event, separators=(",", ":"), default=str)
        with self._lock:
            self._fh.write(line + "\n")
        return True

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def atomic_write_json(path: Path, obj) -> None:
    """Write via temp file + rename so readers never see a half-written file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, separators=(",", ":"), default=str), encoding="utf-8")
    for attempt in range(5):  # Windows refuses replace while a reader holds the file
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.02 * (attempt + 1))


def read_json(path: Path, default=None):
    for _ in range(3):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default
        except (json.JSONDecodeError, PermissionError):
            time.sleep(0.02)
    return default


def tail_jsonl(path: Path, max_lines: int = 200, max_bytes: int = 2_000_000) -> list[dict]:
    """Return the last ``max_lines`` records without reading the whole file."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            chunk = fh.read()
    except FileNotFoundError:
        return []
    lines = chunk.splitlines()
    if size > max_bytes and lines:
        lines = lines[1:]  # first line is probably truncated
    out = []
    for raw in lines[-max_lines:]:
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out
