#!/usr/bin/env bash
set -euo pipefail

BASE="${SIGMA_FORGE_URL:-http://127.0.0.1:8000}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/output"
mkdir -p "$OUT"

get() {
  echo "GET  $1"
  curl -fsS "$BASE$1" -o "$OUT/$2"
}

post() {
  echo "POST $1  <- $2"
  curl -fsS -X POST "$BASE$1" -H "Content-Type: application/json" --data-binary "@$DIR/$2" -o "$OUT/$3"
}

get /api/health health.json
get /api/targets targets.json
post /api/analyze analyze.json analyze_result.json
post /api/convert convert_splunk.json convert_splunk_result.json
post /api/convert convert_splunk_savedsearches.json convert_splunk_savedsearches_result.json
post /api/convert convert_elastic_siem_rule.json convert_elastic_siem_rule_result.json
post /api/convert convert_defender_xdr.json convert_defender_xdr_result.json
post /api/convert convert_wazuh.json convert_wazuh_result.json
post /api/convert convert_correlation_esql.json convert_correlation_esql_result.json
post /api/coverage coverage.json coverage_result.json
post /api/coverage/navigator navigator.json navigator_layer.json

if command -v python3 >/dev/null 2>&1; then
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],'w').write(d['bundle'])" "$OUT/convert_wazuh_result.json" "$OUT/sigma_forge_rules.xml"
  echo "Wazuh rules saved to $OUT/sigma_forge_rules.xml"
fi

echo "Done. Results are in $OUT"
