"""Windows fast path: one NtQuerySystemInformation call for *all* processes.

psutil opens a handle per process per attribute (~1.5 ms each), so a full scan of ~300
processes costs over a second. ``SystemProcessInformation`` returns CPU times, thread
count, working set and I/O counters for every process in a single syscall (a few ms),
and works even for processes we are not allowed to open.

Layout: SYSTEM_PROCESS_INFORMATION (x64), as used by psutil's own C extension.
"""
from __future__ import annotations

import ctypes
import struct
import sys

IS_SUPPORTED = sys.platform == "win32" and struct.calcsize("P") == 8

_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_SystemProcessInformation = 5
_EPOCH_DIFF = 116444736000000000  # FILETIME (1601) -> Unix epoch, in 100 ns units

# offsets within SYSTEM_PROCESS_INFORMATION on x64
_O_NEXT, _O_THREADS, _O_CREATE, _O_USER, _O_KERNEL = 0, 4, 32, 40, 48
_O_NAME_LEN, _O_NAME_PTR, _O_PID, _O_PPID = 56, 64, 80, 88
_O_WSET, _O_READ_OPS, _O_WRITE_OPS, _O_WRITE_BYTES = 144, 208, 216, 240

if IS_SUPPORTED:
    _ntdll = ctypes.WinDLL("ntdll")
    _NtQSI = _ntdll.NtQuerySystemInformation
    _NtQSI.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                       ctypes.POINTER(ctypes.c_ulong)]
    _NtQSI.restype = ctypes.c_ulong

_buf_size = 512 * 1024


def snapshot() -> dict[int, tuple]:
    """Return {pid: (ppid, name, threads, create_time, cpu_s, wset_bytes,
    read_ops, write_ops, write_bytes)} for every process on the system."""
    global _buf_size
    while True:
        buf = ctypes.create_string_buffer(_buf_size)
        needed = ctypes.c_ulong(0)
        status = _NtQSI(_SystemProcessInformation, buf, _buf_size, ctypes.byref(needed))
        if status == _STATUS_INFO_LENGTH_MISMATCH:
            _buf_size = max(_buf_size * 2, needed.value + 64 * 1024)
            continue
        if status != 0:
            raise OSError(f"NtQuerySystemInformation failed: 0x{status:08X}")
        break

    raw = buf.raw
    base = ctypes.addressof(buf)
    u32, u64, i64 = struct.Struct("<I").unpack_from, struct.Struct("<Q").unpack_from, \
        struct.Struct("<q").unpack_from
    out: dict[int, tuple] = {}
    off = 0
    while True:
        pid = u64(raw, off + _O_PID)[0]
        name_len = struct.unpack_from("<H", raw, off + _O_NAME_LEN)[0]
        name_ptr = u64(raw, off + _O_NAME_PTR)[0]
        if pid == 0:
            name = "System Idle Process"
        elif name_ptr and name_len:
            s = name_ptr - base
            name = raw[s:s + name_len].decode("utf-16-le", "replace")
        else:
            name = "System" if pid == 4 else ""
        ct = i64(raw, off + _O_CREATE)[0]
        out[pid] = (
            u64(raw, off + _O_PPID)[0],
            name,
            u32(raw, off + _O_THREADS)[0],
            (ct - _EPOCH_DIFF) / 1e7 if ct else 0.0,
            (i64(raw, off + _O_USER)[0] + i64(raw, off + _O_KERNEL)[0]) / 1e7,
            u64(raw, off + _O_WSET)[0],
            i64(raw, off + _O_READ_OPS)[0],
            i64(raw, off + _O_WRITE_OPS)[0],
            i64(raw, off + _O_WRITE_BYTES)[0],
        )
        nxt = u32(raw, off + _O_NEXT)[0]
        if nxt == 0:
            break
        off += nxt
    return out
