# After reboot: finish Ubuntu WSL + build/test ebpf-netmon
$ErrorActionPreference = "Stop"
$Repo = Split-Path $PSScriptRoot -Parent
$Log = Join-Path $Repo "scripts\setup_run.log"

function Log($m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m
  Add-Content -Path $Log -Value $line
  Write-Host $line
}

Set-Content -Path $Log -Value "=== setup $(Get-Date) ==="
Log "repo=$Repo"

wsl --set-default-version 2 2>$null | Out-Null

$list = & wsl -l -q 2>$null
$has = $false
if ($list) {
  $plain = ($list | Out-String) -replace "`0",""
  if ($plain -match "Ubuntu") { $has = $true }
}

if (-not $has) {
  Log "install Ubuntu-24.04"
  & wsl --install -d Ubuntu-24.04 --no-launch
}

$dist = "Ubuntu-24.04"
$names = ((& wsl -l -q) | Out-String) -replace "`0","" -split "`r?`n" | Where-Object { $_.Trim() -ne "" }
foreach ($n in $names) {
  if ($n -match "Ubuntu") { $dist = $n.Trim(); break }
}
Log "distro=$dist"

# first-time init as root if needed
& wsl -d $dist -u root -- true 2>$null
if ($LASTEXITCODE -ne 0) {
  Log "registering distro via ubuntu2404"
  & ubuntu2404 install --root
}

$wslPath = (& wsl -d $dist -u root -- bash -lc "wslpath -a '$Repo'").Trim()
Log "wslpath=$wslPath"

& wsl -d $dist -u root -- bash -lc "cd '$wslPath' && chmod +x scripts/*.sh && bash scripts/bootstrap_and_test.sh"
$code = $LASTEXITCODE
Log "done exit=$code"
exit $code
