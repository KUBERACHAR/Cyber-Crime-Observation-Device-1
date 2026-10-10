<#
.SYNOPSIS
  HARMLESS attack simulation for the demo: rapid file dumping into Downloads.

.DESCRIPTION
  Mimics the behaviour of a malicious script (burst of file creation in a user folder)
  without doing anything harmful: it only writes small random text files into
  "$HOME\Downloads\ccod_sim_<timestamp>". Remove them with scripts\cleanup_sim.ps1.

  Its PID is appended to data\attack_pids.txt so that, while the collector runs with
  --record, its rows are labelled "suspicious" (1) automatically.

  Normally launched through scripts\run_attack_demo.ps1, which adds the suspicious
  command-line flags (-NoProfile -ExecutionPolicy Bypass ...) a real dropper would use.
#>
param(
    [int]$FilesPerWave = 300,
    [int]$Waves = 20,
    [int]$PauseMs = 1500,
    [string]$Target = (Join-Path $HOME ("Downloads\ccod_sim_" + (Get-Date -Format "yyyyMMdd_HHmmss")))
)

$root = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $root "data\attack_pids.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $pidFile) | Out-Null
Add-Content -Path $pidFile -Value $PID

New-Item -ItemType Directory -Force -Path $Target | Out-Null
Write-Host "[sim] PID $PID dumping files into $Target (Ctrl+C or terminate from dashboard to stop)"

$rand = New-Object System.Random
for ($w = 1; $w -le $Waves; $w++) {
    for ($i = 1; $i -le $FilesPerWave; $i++) {
        $bytes = New-Object byte[] 2048
        $rand.NextBytes($bytes)
        [System.IO.File]::WriteAllBytes((Join-Path $Target ("doc_{0:D3}_{1:D4}.dat" -f $w, $i)), $bytes)
    }
    Write-Host "[sim] wave $w/$Waves written"
    Start-Sleep -Milliseconds $PauseMs
}
Write-Host "[sim] finished"
