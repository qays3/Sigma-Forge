[CmdletBinding()]
param(
    [switch]$Run,
    [switch]$Dev,
    [switch]$UpdateAttack,
    [switch]$Docker,
    [switch]$Recreate,
    [string]$BindHost = $(if ($env:SIGMA_FORGE_HOST) { $env:SIGMA_FORGE_HOST } else { "127.0.0.1" }),
    [int]$Port = $(if ($env:SIGMA_FORGE_PORT) { [int]$env:SIGMA_FORGE_PORT } else { 8000 }),
    [switch]$Help
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Root ".venv"

function Write-Info($msg) { Write-Host "[sigma-forge] " -ForegroundColor Magenta -NoNewline; Write-Host $msg }
function Write-Ok($msg) { Write-Host "[ok] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn($msg) { Write-Host "[warn] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Stop-Setup($msg) { Write-Host "[error] " -ForegroundColor Red -NoNewline; Write-Host $msg; exit 1 }

if ($Help) {
    Write-Host @"
Sigma Forge setup for Windows

Usage: .\setup.ps1 [options]

  -Run             Start the server after setup
  -Dev             Install test tools and run the test suite
  -UpdateAttack    Download the latest MITRE ATT&CK data
  -Docker          Build and start with Docker Compose instead of a venv
  -Recreate        Delete and rebuild the virtual environment
  -BindHost HOST   Bind address (default: $BindHost)
  -Port PORT       Port (default: $Port)
  -Help            Show this help

If scripts are blocked, run once:
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
"@
    exit 0
}

Set-Location $Root

if ($Docker) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Stop-Setup "Docker is not installed" }
    Write-Info "Building and starting the container"
    if ($UpdateAttack) { docker compose build --build-arg REFRESH_ATTACK=true } else { docker compose build }
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Docker build failed" }
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Docker start failed" }
    Write-Ok "Sigma Forge is running at http://127.0.0.1:8000"
    exit 0
}

function Find-Python {
    $candidates = @(
        @{ Cmd = "py"; Args = @("-3.13") },
        @{ Cmd = "py"; Args = @("-3.12") },
        @{ Cmd = "py"; Args = @("-3.11") },
        @{ Cmd = "py"; Args = @("-3.10") },
        @{ Cmd = "py"; Args = @("-3") },
        @{ Cmd = "python"; Args = @() },
        @{ Cmd = "python3"; Args = @() }
    )
    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Cmd -ErrorAction SilentlyContinue)) { continue }
        try {
            & $c.Cmd @($c.Args + @("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)")) 2>$null
            if ($LASTEXITCODE -eq 0) { return $c }
        } catch { continue }
    }
    return $null
}

$py = Find-Python
if (-not $py) { Stop-Setup "Python 3.10 or newer is required. Install it from https://www.python.org/downloads/ and tick 'Add python.exe to PATH'." }
$version = & $py.Cmd @($py.Args + @("--version"))
Write-Info "Using $version"

if ($Recreate -and (Test-Path $Venv)) {
    Write-Info "Removing old virtual environment"
    Remove-Item -Recurse -Force $Venv
}

$VPy = Join-Path $Venv "Scripts\python.exe"
if (-not (Test-Path $VPy)) {
    Write-Info "Creating virtual environment in .venv"
    & $py.Cmd @($py.Args + @("-m", "venv", $Venv))
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Could not create the virtual environment" }
}

Write-Info "Installing dependencies"
& $VPy -m pip install --upgrade pip | Out-Null
if ($Dev) { & $VPy -m pip install -r requirements-dev.txt } else { & $VPy -m pip install -r requirements.txt }
if ($LASTEXITCODE -ne 0) { Stop-Setup "pip install failed" }
Write-Ok "Dependencies installed"

$AttackFile = Join-Path $Root "data\attack\attack.json"
if ($UpdateAttack -or -not (Test-Path $AttackFile)) {
    Write-Info "Fetching MITRE ATT&CK data"
    & $VPy tools\fetch_attack.py
    if ($LASTEXITCODE -ne 0) { Write-Warn "ATT&CK download failed. Coverage will not work until you run: $VPy tools\fetch_attack.py" }
}

if ($Dev) {
    Write-Info "Running tests"
    & $VPy -m pytest -q
}

Write-Ok "Setup finished"
Write-Host ""
Write-Host "  Start the server:  $VPy -m uvicorn app.main:app --host $BindHost --port $Port"
Write-Host "  Or run:            .\setup.ps1 -Run"
Write-Host "  Open:              http://${BindHost}:$Port"
Write-Host ""

if ($Run) {
    Write-Info "Starting Sigma Forge on http://${BindHost}:$Port (Ctrl+C to stop)"
    & $VPy -m uvicorn app.main:app --host $BindHost --port $Port
}
