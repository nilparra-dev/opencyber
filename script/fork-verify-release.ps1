# Verifies the packaged Windows release before fork-release publishes it (FORK.md section 4.5).
#
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script/fork-verify-release.ps1 `
#     -Version 2.0.24-cyber.2 -Zip release\opencyber-windows-x64.zip -Previous v2.0.24-cyber.1
#
# Every check runs against the zip users download: the staged executable's versions, a real
# install through script/fork-install.ps1, the background service (start, a durable session,
# recovery from an abrupt kill, stop) and the updater chain from a published previous release
# back to the artifact under test.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [Parameter(Mandatory = $true)]
  [string]$Zip,

  # Published release to install before the upgrade check. Empty skips the upgrade chain.
  [string]$Previous = "",

  # Release the upgrade chain installs. The chain reads GitHub Releases, so a verify-only run of
  # an unpublished version passes an already-published target; release runs use -Version.
  [string]$UpgradeTarget = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Version = $Version.TrimStart("v")
$Previous = $Previous.TrimStart("v")
$UpgradeTarget = if ($UpgradeTarget) { $UpgradeTarget.TrimStart("v") } else { $Version }
# The explicit upgrade command ignores this; only the start-up check would call the GitHub API,
# and shared runner IPs can be rate-limited on it.
$env:OPENCODE_DISABLE_AUTOUPDATE = "1"

function Get-DisplayVersion([string]$Value) {
  # Human-facing versions drop the -cyber.N prerelease (F-005).
  "$($Value.Split('-')[0]) (Cyber)"
}

function Invoke-Opencyber([string]$Exe, [string[]]$Arguments) {
  # stderr is not redirected: with ErrorActionPreference Stop, redirecting a native command's
  # stderr can surface its lines as terminating errors. It still reaches the CI log.
  $output = (& $Exe @Arguments | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "opencyber $($Arguments -join ' ') exited with ${LASTEXITCODE}:`n$output" }
  $output
}

function Assert-Contains([string]$Value, [string]$Expected, [string]$What) {
  if (-not $Value.Contains($Expected)) { throw "${What}: expected '$Expected' in:`n$Value" }
}

function Assert-Release([string]$Exe, [string]$Expected) {
  Assert-Contains (Invoke-Opencyber $Exe @("--version")) (Get-DisplayVersion $Expected) "$Exe --version"
  # The display form drops the prerelease, so only the baked build version proves which release
  # is installed when two of them share an upstream base.
  $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Exe))
  if (-not $text.Contains($Expected)) { throw "$Exe does not embed the build version $Expected" }
}

function Start-OpencyberService([string]$Exe) {
  $output = Invoke-Opencyber $Exe @("service", "start")
  $url = ($output -split "`r?`n" | Where-Object { $_ -match "^http://" } | Select-Object -Last 1)
  if (-not $url) { throw "service start reported no URL:`n$output" }
  $url.Trim()
}

function Get-ServiceStatus([string]$Exe) {
  $lines = (Invoke-Opencyber $Exe @("service", "status")) -split "`r?`n" | Where-Object { $_.Trim() }
  ($lines | Select-Object -Last 1).Trim()
}

function Get-ServicePassword([string]$Exe) {
  # The service always has one (service-config.ts keeps it across restarts), and the HTTP API
  # rejects unauthenticated requests with 401. Captured raw so a failure never logs it.
  $output = (& $Exe @("service", "get", "password") | Out-String)
  if ($LASTEXITCODE -ne 0) { throw "opencyber service get password exited with ${LASTEXITCODE}" }
  $output.Trim()
}

function Get-ServiceAuth([string]$Exe) {
  $password = Get-ServicePassword $Exe
  $token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("opencode:$password"))
  @{ Authorization = "Basic $token" }
}

function Stop-ServerAbruptly([string]$Url) {
  $port = ([Uri]$Url).Port
  $owners = @(
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty OwningProcess -Unique
  )
  if (-not $owners) { throw "no listener on port $port to kill" }
  $owners | ForEach-Object { Stop-Process -Id $_ -Force }
  # A forced kill releases the listener asynchronously; wait for it before restarting.
  $deadline = (Get-Date).AddSeconds(10)
  while (
    (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) -and
    (Get-Date) -lt $deadline
  ) { Start-Sleep -Milliseconds 200 }
}

function Install-Release([string]$Installer, [string]$Release, [string]$Package) {
  # Same invocation shape as the updater's child process (fork-updater.ts).
  $env:OPENCYBER_VERSION = $Release
  $env:OPENCYBER_ZIP = $Package
  & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Installer
  if ($LASTEXITCODE -ne 0) { throw "fork-install.ps1 exited with ${LASTEXITCODE}" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) "opencyber-verify-$([Guid]::NewGuid().ToString('N'))"
$installed = Join-Path $HOME ".opencyber\bin\opencyber.exe"
$installer = Join-Path $PSScriptRoot "fork-install.ps1"

Write-Host "[1/4] Unpacking the release artifact"
Expand-Archive -Path (Resolve-Path $Zip).Path -DestinationPath $work -Force
$staged = Join-Path $work "opencyber.exe"
if (-not (Test-Path $staged)) { throw "opencyber-windows-x64.zip does not contain opencyber.exe" }
Unblock-File $staged -ErrorAction SilentlyContinue
Assert-Release $staged $Version

Write-Host "[2/4] Installing $Version from the artifact"
Install-Release $installer "" $Zip
Unblock-File $installed -ErrorAction SilentlyContinue
Assert-Release $installed $Version
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (@(($userPath -split ";") | Where-Object { $_ }) -notcontains (Split-Path $installed)) {
  throw "the installer did not add $(Split-Path $installed) to the user PATH"
}

Write-Host "[3/4] Running the background service"
# The cyber channel's default port is a fixed hash (49866) and a host can already have a
# listener on it, which the server reports as an unrecoverable port conflict. Pick a free
# loopback port explicitly: the recovery its own error recommends.
$probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$probe.Start()
$freePort = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
$probe.Stop()
Invoke-Opencyber $installed @("service", "set", "port", [string]$freePort)
$url = Start-OpencyberService $installed
$status = Get-ServiceStatus $installed
if ($status -notmatch "^http://") { throw "service status after start: $status" }
if (([Uri]$status).Port -ne ([Uri]$url).Port) { throw "service status ($status) is not the started server ($url)" }

$session = Invoke-RestMethod -Method Post -Uri "$url/api/session" -Headers (Get-ServiceAuth $installed) -ContentType "application/json" -Body (@{ title = "windows release verify" } | ConvertTo-Json)
$id = $session.data.id
if (-not $id) { throw "session create did not return an id" }

# A forced kill leaves the database mid-WAL; the restarted server must recover it and still
# serve the session that was committed before the kill.
Stop-ServerAbruptly $url
$url = Start-OpencyberService $installed
$recovered = Invoke-RestMethod -Uri "$url/api/session/$id" -Headers (Get-ServiceAuth $installed)
if ($recovered.data.id -ne $id) { throw "session $id did not survive the restart" }

Invoke-Opencyber $installed @("service", "stop")
$status = Get-ServiceStatus $installed
if ($status -ne "stopped") { throw "service status after stop: $status" }

if ($Previous) {
  Write-Host "[4/4] Upgrading $Previous to $UpgradeTarget through the updater"
  Install-Release $installer $Previous ""
  Assert-Release $installed $Previous
  # The updater installs the newest published release, so an unpublished target reaches it as
  # the local artifact. fork-updater.ts passes OPENCYBER_VERSION to its child installer.
  $env:OPENCYBER_VERSION = ""
  $env:OPENCYBER_ZIP = $Zip
  Invoke-Opencyber $installed @("upgrade", $UpgradeTarget)
  Assert-Release $installed $UpgradeTarget
} else {
  Write-Host "[4/4] no previous release supplied; skipping the upgrade chain"
}

Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Verified opencyber $Version from $Zip"
