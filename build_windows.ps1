param(
    [switch]$OneFile
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
}
$py = ".venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.txt pyinstaller
& $py -m pip install --no-deps -r requirements-legacy.txt

$mode = if ($OneFile) { "--onefile" } else { "--onedir" }
$pyiArgs = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", $mode,
    "--name", "SigmaForge",
    "--paths", ".",
    "--add-data", "web;web",
    "--add-data", "sample;sample",
    "--add-data", "data\attack;data\attack",
    "--add-data", "data\atomic;data\atomic",
    "--collect-all", "sigma",
    "--collect-all", "evtx",
    "--collect-submodules", "uvicorn",
    "--collect-submodules", "app",
    "--hidden-import", "yara",
    "tools\windows_entry.py"
)
& $py @pyiArgs

Write-Host ""
if ($OneFile) {
    Write-Host "Built dist\SigmaForge.exe"
} else {
    Write-Host "Built dist\SigmaForge\SigmaForge.exe. Copy the whole dist\SigmaForge folder."
}
Write-Host "Run it and open http://127.0.0.1:8000. Data is kept in $env:USERPROFILE\.sigma-forge"
