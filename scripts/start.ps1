<#
.SYNOPSIS
  Start the collector (new window) and the dashboard using the project's virtualenv.

  powershell -ExecutionPolicy Bypass -File scripts\start.ps1           # monitor
  powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Record   # monitor + record dataset
#>
param([switch]$Record)

$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$collectorArgs = @("-m", "sensors.collector")
if ($Record) { $collectorArgs += "--record" }
Start-Process -FilePath $py -ArgumentList $collectorArgs -WorkingDirectory $root
Write-Host "Collector started in a new window."

Set-Location $root
& $py -m streamlit run dashboard\app.py
