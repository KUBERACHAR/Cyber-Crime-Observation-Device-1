<#
.SYNOPSIS
  Launch the harmless attack simulation the way a dropper would (hidden-ish window,
  -NoProfile, -ExecutionPolicy Bypass). Use during the demo or while recording data.

  powershell -ExecutionPolicy Bypass -File scripts\run_attack_demo.ps1
#>
param([int]$Waves = 20)

$sim = Join-Path $PSScriptRoot "simulate_attack.ps1"
$p = Start-Process -FilePath "powershell.exe" -PassThru -WindowStyle Minimized -ArgumentList @(
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "`"$sim`"", "-Waves", $Waves)
Write-Host "Attack simulation started: powershell.exe PID $($p.Id) (window minimised)."
Write-Host "Watch the dashboard - it should raise a red alert within a second."
