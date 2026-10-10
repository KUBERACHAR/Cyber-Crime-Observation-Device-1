"""Feature extraction shared by the live collector, the synthetic generator and training.

Keeping one definition of ``FEATURE_COLUMNS`` guarantees that the vector the model was
trained on in Colab is exactly the vector the laptop builds at inference time.

One row = one process observed at one point in time, enriched with host-wide context
(file-system event rates, overall CPU) for the surrounding window.
"""
from __future__ import annotations

import math
import re

FEATURE_COLUMNS: list[str] = [
    "cpu_percent",          # process CPU, 0-100 normalised over all cores
    "mem_percent",          # process RSS as % of total RAM
    "num_threads",
    "log_age_s",            # log1p(seconds since process start)
    "write_ops_rate",       # write I/O operations per second
    "write_kb_rate",        # KB written per second
    "read_ops_rate",        # read I/O operations per second
    "num_conns",            # open inet sockets
    "num_remote_ips",       # distinct remote IPs
    "num_children",
    "is_shell",             # powershell / cmd / script hosts
    "is_lolbin",            # living-off-the-land binaries (certutil, mshta, ...)
    "parent_is_shell",
    "parent_is_office",     # spawned by Word/Excel/Outlook (macro-style chain)
    "cmd_risk",             # weighted count of suspicious command-line tokens
    "cmd_len_log",          # log1p(command-line length) - encoded payloads are long
    "sys_file_create_rate", # file creations/s in watched dirs (host-wide window)
    "sys_file_delete_rate",
    "sys_file_modify_rate",
    "sys_cpu_percent",
]

SHELLS = {"powershell", "pwsh", "cmd", "wscript", "cscript", "powershell_ise"}
LOLBINS = {"mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "msbuild",
           "installutil", "schtasks", "vssadmin", "bcdedit", "wevtutil", "cmstp",
           "forfiles", "msiexec", "curl", "ftp"}
OFFICE = {"winword", "excel", "powerpnt", "outlook", "msaccess", "onenote", "acrord32"}

_STRONG = [r"-e(nc|ncodedcommand|c)\b", r"frombase64string", r"downloadstring",
           r"downloadfile", r"\biex\b", r"invoke-expression",
           r"-w(indowstyle)?\s+h(idden)?\b", r"\bbypass\b", r"vssadmin.*delete",
           r"shadowcopy", r"-urlcache", r"invoke-webrequest", r"net\.webclient",
           r"start-bitstransfer", r"(add|set)-mppreference", r"invoke-shellcode",
           r"reflection\.assembly"]
_WEAK = [r"-nop\b", r"-noprofile\b", r"-noni\b", r"-noninteractive\b", r"https?://",
         r"\\appdata\\local\\temp\\", r"\.(ps1|vbs|js|hta|bat)\b"]
_STRONG_RE = [re.compile(p) for p in _STRONG]
_WEAK_RE = [re.compile(p) for p in _WEAK]


def base_name(name: str | None) -> str:
    n = (name or "").lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return n[:-4] if n.endswith(".exe") else n


def cmdline_risk(cmdline: str) -> int:
    c = (cmdline or "").lower()
    if not c:
        return 0
    return 2 * sum(1 for r in _STRONG_RE if r.search(c)) + sum(1 for r in _WEAK_RE if r.search(c))


def build_row(proc: dict, ctx: dict) -> list[float]:
    """Build one feature vector.

    ``proc`` keys: name, parent_name, cmdline, age_s, cpu_percent, mem_percent,
    num_threads, write_ops_rate, write_kb_rate, read_ops_rate, num_conns,
    num_remote_ips, num_children.  ``ctx`` keys: file_create_rate,
    file_delete_rate, file_modify_rate, cpu_percent.
    """
    name = base_name(proc.get("name"))
    parent = base_name(proc.get("parent_name"))
    cmd = proc.get("cmdline") or ""
    return [
        float(proc.get("cpu_percent", 0.0)),
        float(proc.get("mem_percent", 0.0)),
        float(proc.get("num_threads", 0)),
        math.log1p(max(0.0, float(proc.get("age_s", 0.0)))),
        float(proc.get("write_ops_rate", 0.0)),
        float(proc.get("write_kb_rate", 0.0)),
        float(proc.get("read_ops_rate", 0.0)),
        float(proc.get("num_conns", 0)),
        float(proc.get("num_remote_ips", 0)),
        float(proc.get("num_children", 0)),
        1.0 if name in SHELLS else 0.0,
        1.0 if name in LOLBINS else 0.0,
        1.0 if parent in SHELLS else 0.0,
        1.0 if parent in OFFICE else 0.0,
        float(cmdline_risk(cmd)),
        math.log1p(len(cmd)),
        float(ctx.get("file_create_rate", 0.0)),
        float(ctx.get("file_delete_rate", 0.0)),
        float(ctx.get("file_modify_rate", 0.0)),
        float(ctx.get("cpu_percent", 0.0)),
    ]


def explain(row: list[float] | dict) -> list[str]:
    """Human-readable diagnostics for the dashboard (why did this score high?)."""
    f = row if isinstance(row, dict) else dict(zip(FEATURE_COLUMNS, row))
    reasons = []
    if f["is_shell"] and f["cmd_risk"] >= 2:
        reasons.append(f"Shell with suspicious command-line flags (risk {int(f['cmd_risk'])})")
    elif f["cmd_risk"] >= 2:
        reasons.append(f"Suspicious command-line tokens (risk {int(f['cmd_risk'])})")
    if f["is_lolbin"]:
        reasons.append("Living-off-the-land binary in use")
    if f["parent_is_office"]:
        reasons.append("Spawned by an Office/PDF application")
    if f["parent_is_shell"] and (f["is_shell"] or f["is_lolbin"]):
        reasons.append("Chained shell execution (shell -> shell/LOLBin)")
    if f["write_ops_rate"] >= 50:
        reasons.append(f"High write rate: {f['write_ops_rate']:.0f} ops/s, {f['write_kb_rate']:.0f} KB/s")
    if f["sys_file_create_rate"] >= 10:
        reasons.append(f"File creation burst: {f['sys_file_create_rate']:.1f} files/s in watched folders")
    if f["sys_file_delete_rate"] >= 10:
        reasons.append(f"File deletion burst: {f['sys_file_delete_rate']:.1f} files/s")
    if f["num_remote_ips"] >= 15:
        reasons.append(f"Contacting many remote hosts ({int(f['num_remote_ips'])} IPs)")
    if f["cpu_percent"] >= 50:
        reasons.append(f"High CPU usage ({f['cpu_percent']:.0f}%)")
    if f["log_age_s"] < math.log1p(10):
        reasons.append("Newly started process (<10 s)")
    return reasons or ["Behaviour deviates from learned baseline"]
