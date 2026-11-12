$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Py = Join-Path $Dir ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
$env:PYTHONPATH = $Dir
& $Py -m app.cli @args
exit $LASTEXITCODE
