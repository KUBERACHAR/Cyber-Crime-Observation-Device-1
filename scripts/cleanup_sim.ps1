# Remove files created by simulate_attack.ps1 and reset the attack PID list.
$dirs = Get-ChildItem -Path (Join-Path $HOME "Downloads") -Directory -Filter "ccod_sim_*" -ErrorAction SilentlyContinue
foreach ($d in $dirs) {
    # antivirus / the file watcher may briefly hold a handle on fresh files: retry
    for ($try = 1; $try -le 5 -and (Test-Path $d.FullName); $try++) {
        Remove-Item -Recurse -Force $d.FullName -ErrorAction SilentlyContinue
        if (Test-Path $d.FullName) { Start-Sleep -Milliseconds (300 * $try) }
    }
    if (Test-Path $d.FullName) { Write-Warning "could not remove $($d.FullName) (in use) - run again later" }
    else { Write-Host "removed $($d.FullName)" }
}
$pidFile = Join-Path (Split-Path -Parent $PSScriptRoot) "data\attack_pids.txt"
if (Test-Path $pidFile) { Remove-Item $pidFile; Write-Host "cleared $pidFile" }
