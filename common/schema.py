"""Unified JSON event schema + fast validation.

Every sensor payload is wrapped in the same envelope::

    {"schema": 1, "ts": 1728570000.123, "host": "LAPTOP", "type": "process", "data": {...}}

``validate_event`` is a hand-written checker (no jsonschema dependency) so it can run
on every event inside the 500 ms latency budget.
"""
from __future__ import annotations

import socket
import time

SCHEMA_VERSION = 1
HOSTNAME = socket.gethostname()

_NUM = (int, float)
_STR = (str,)
_OPT_STR = (str, type(None))
_OPT_NUM = (int, float, type(None))
_LIST = (list,)

# Required ``data`` fields and their allowed types, per event type.
EVENT_FIELDS: dict[str, dict[str, tuple]] = {
    "host": {"cpu_percent": _NUM, "mem_percent": _NUM, "process_count": _NUM,
             "users": _LIST},
    "process_start": {"pid": _NUM, "ppid": _OPT_NUM, "name": _STR,
                      "cmdline": _STR, "username": _OPT_STR},
    "network": {"pid": _OPT_NUM, "laddr": _STR, "raddr": _STR, "status": _STR},
    "file": {"action": _STR, "path": _STR, "is_dir": (bool,)},
    "alert": {"pid": _NUM, "name": _STR, "score": _NUM, "reasons": _LIST},
    "response": {"pid": _NUM, "name": _STR, "result": _STR},
}

FILE_ACTIONS = {"created", "deleted", "modified", "moved"}


class SchemaError(ValueError):
    pass


def make_event(event_type: str, data: dict, ts: float | None = None) -> dict:
    return {"schema": SCHEMA_VERSION, "ts": time.time() if ts is None else ts,
            "host": HOSTNAME, "type": event_type, "data": data}


def validate_event(event: dict) -> dict:
    """Raise SchemaError if ``event`` does not match the schema; return it otherwise."""
    if not isinstance(event, dict):
        raise SchemaError("event must be an object")
    if event.get("schema") != SCHEMA_VERSION:
        raise SchemaError(f"unsupported schema version {event.get('schema')!r}")
    if not isinstance(event.get("ts"), _NUM):
        raise SchemaError("ts must be a number")
    etype = event.get("type")
    spec = EVENT_FIELDS.get(etype)
    if spec is None:
        raise SchemaError(f"unknown event type {etype!r}")
    data = event.get("data")
    if not isinstance(data, dict):
        raise SchemaError("data must be an object")
    for key, types in spec.items():
        if key not in data:
            raise SchemaError(f"{etype}.data missing {key!r}")
        if not isinstance(data[key], types):
            raise SchemaError(f"{etype}.data.{key} has type {type(data[key]).__name__}")
    if etype == "file" and data["action"] not in FILE_ACTIONS:
        raise SchemaError(f"invalid file action {data['action']!r}")
    return event
