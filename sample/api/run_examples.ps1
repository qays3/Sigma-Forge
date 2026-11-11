param(
    [string]$BaseUrl = $(if ($env:SIGMA_FORGE_URL) { $env:SIGMA_FORGE_URL } else { "http://127.0.0.1:8000" })
)

$ErrorActionPreference = "Stop"
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Dir "output"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Invoke-Get($path, $file) {
    Write-Host "GET  $path"
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl$path" -OutFile (Join-Path $Out $file)
}

function Invoke-Post($path, $body, $file) {
    Write-Host "POST $path  <- $body"
    $json = [System.IO.File]::ReadAllText((Join-Path $Dir $body))
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$BaseUrl$path" -ContentType "application/json; charset=utf-8" -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -OutFile (Join-Path $Out $file)
}

Invoke-Get "/api/health" "health.json"
Invoke-Get "/api/targets" "targets.json"
Invoke-Post "/api/analyze" "analyze.json" "analyze_result.json"
Invoke-Post "/api/convert" "convert_splunk.json" "convert_splunk_result.json"
Invoke-Post "/api/convert" "convert_splunk_savedsearches.json" "convert_splunk_savedsearches_result.json"
Invoke-Post "/api/convert" "convert_elastic_siem_rule.json" "convert_elastic_siem_rule_result.json"
Invoke-Post "/api/convert" "convert_defender_xdr.json" "convert_defender_xdr_result.json"
Invoke-Post "/api/convert" "convert_wazuh.json" "convert_wazuh_result.json"
Invoke-Post "/api/convert" "convert_correlation_esql.json" "convert_correlation_esql_result.json"
Invoke-Post "/api/coverage" "coverage.json" "coverage_result.json"
Invoke-Post "/api/coverage/navigator" "navigator.json" "navigator_layer.json"

$wazuh = Get-Content -Raw (Join-Path $Out "convert_wazuh_result.json") | ConvertFrom-Json
[System.IO.File]::WriteAllText((Join-Path $Out "sigma_forge_rules.xml"), $wazuh.bundle)
Write-Host "Wazuh rules saved to $(Join-Path $Out 'sigma_forge_rules.xml')"
Write-Host "Done. Results are in $Out"
