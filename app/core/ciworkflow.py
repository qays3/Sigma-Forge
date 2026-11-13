import json
import re
from typing import Any, Dict, List

FIRE_KEYS = {
    "splunk": {"url": "SPLUNK_API_URL", "token": "SPLUNK_TOKEN", "hec_url": "SPLUNK_HEC_URL", "hec_token": "SPLUNK_HEC_TOKEN", "index": "SPLUNK_TEST_INDEX"},
    "elastic": {"url": "ELASTIC_URL", "token": "ELASTIC_API_KEY", "index": "ELASTIC_TEST_INDEX"},
    "opensearch": {"url": "OPENSEARCH_URL", "username": "OPENSEARCH_USER", "password": "OPENSEARCH_PASSWORD"},
    "wazuh": {"url": "WAZUH_API_URL", "username": "WAZUH_API_USER", "password": "WAZUH_API_PASSWORD"},
    "sentinel": {"workspace_id": "SENTINEL_WORKSPACE_ID", "tenant_id": "AZURE_TENANT_ID", "client_id": "AZURE_CLIENT_ID", "client_secret": "AZURE_CLIENT_SECRET",
                 "dce": "SENTINEL_DCE", "dcr_id": "SENTINEL_DCR_ID"},
}
DEPLOY_KEYS = {
    "splunk": {"url": "SPLUNK_API_URL", "token": "SPLUNK_TOKEN"},
    "elastic": {"url": "KIBANA_URL", "token": "ELASTIC_API_KEY"},
    "sentinel": {"subscription": "AZURE_SUBSCRIPTION_ID", "resource_group": "SENTINEL_RESOURCE_GROUP", "workspace": "SENTINEL_WORKSPACE_NAME", "token": "AZURE_MGMT_TOKEN"},
    "wazuh": {"url": "WAZUH_API_URL", "username": "WAZUH_API_USER", "password": "WAZUH_API_PASSWORD"},
}
TOOL_REPO = "qays3/Sigma-Forge"


def _safe_path(p: str, default: str) -> str:
    p = (p or default).strip().strip("/")
    if not re.match(r"^[\w./ -]{1,200}$", p) or ".." in p:
        raise ValueError(f"Bad path: {p}")
    return p


def generate(opts: Dict[str, Any]) -> Dict[str, Any]:
    rules = _safe_path(opts.get("rules"), "rules")
    py = str(opts.get("python") or "3.12")
    if not re.match(r"^3\.\d{1,2}$", py):
        raise ValueError("Python version must look like 3.12")
    checks = set(opts.get("checks") or ["validate", "sigmahq", "unit", "generated", "coverage"])
    fail_on = opts.get("fail_on") if opts.get("fail_on") in ("low", "medium", "high", "critical", "never") else "high"
    min_quality = max(0, min(int(opts.get("min_quality") or 0), 100))
    min_cov = max(0, min(int(opts.get("min_coverage") or 0), 100))
    branch = re.sub(r"[^\w./-]", "", opts.get("branch") or "main") or "main"
    fire = opts.get("firecheck") or {}
    dep = opts.get("deploy") or {}
    files: Dict[str, str] = {}
    secrets: List[str] = []
    q = f'"$GITHUB_WORKSPACE/{rules}"'
    tool = 'cd "$GITHUB_WORKSPACE/.sigma-forge"'
    steps = [
        "      - uses: actions/checkout@v4",
        "      - uses: actions/checkout@v4",
        "        with:",
        f"          repository: {TOOL_REPO}",
        "          path: .sigma-forge",
        "      - uses: actions/setup-python@v5",
        "        with:",
        f'          python-version: "{py}"',
        "          cache: pip",
        "      - name: Install Sigma Forge",
        "        run: python -m pip install --quiet -r .sigma-forge/requirements.txt",
    ]

    def step(name: str, cmd: str, cond: str = "", env: Dict[str, str] = None):
        steps.append(f"      - name: {name}")
        if cond:
            steps.append(f"        if: {cond}")
        if env:
            steps.append("        env:")
            for k, v in env.items():
                steps.append(f"          {k}: {v}")
        steps.append("        run: |")
        steps.append(f"          {tool}")
        for line in cmd.splitlines():
            steps.append(f"          {line}")

    if "validate" in checks:
        step("Check rules and quality", f"python -m app.cli validate {q} --fail-on {fail_on} --min-quality {min_quality} --summary \"$GITHUB_STEP_SUMMARY\"")
    if "sigmahq" in checks:
        step("SigmaHQ style check", f"python -m app.cli sigmahq {q}")
    if "unit" in checks:
        step("Rule unit tests", f"python -m app.cli unit {q} --summary \"$GITHUB_STEP_SUMMARY\" || [ $? -eq 2 ]")
    if "generated" in checks:
        step("Rules fire on generated events", f"python -m app.cli test {q} --generate --expect-all --summary \"$GITHUB_STEP_SUMMARY\"")
    if "coverage" in checks:
        step("ATT&CK coverage report", f"python -m app.cli coverage {q} --report \"$GITHUB_WORKSPACE/coverage-report.html\"" + (f" --min-coverage {min_cov}" if min_cov else ""))
        steps += ["      - uses: actions/upload-artifact@v4", "        if: always()", "        with:", "          name: coverage-report", "          path: coverage-report.html"]
    if fire.get("platform") in FIRE_KEYS:
        plat = fire["platform"]
        keys = FIRE_KEYS[plat]
        settings = {k: f"env:{v}" for k, v in keys.items()}
        if plat == "splunk":
            settings["splunk_windows_source"] = fire.get("splunk_windows_source", "xml")
        settings_file = f".sigma-forge-firecheck-{plat}.json"
        files[settings_file] = json.dumps(settings, indent=2) + "\n"
        secrets += list(keys.values())
        logs = _safe_path(fire.get("logs") or "", "") if fire.get("logs") else ""
        args = f'--platform {plat} --settings "$GITHUB_WORKSPACE/{settings_file}"'
        if fire.get("target"):
            args += f" --target {re.sub(r'[^a-z_]', '', fire['target'])}"
        args += f' --logs "$GITHUB_WORKSPACE/{logs}"' if logs else ""
        args += " --attack" if fire.get("attack", True) else ""
        args += f" --min-score {max(0, min(int(fire.get('min_score') or 100), 100))}"
        step(f"Fire check on {plat}", f"python -m app.cli firecheck {q} {args} --summary \"$GITHUB_STEP_SUMMARY\"", env={v: f"${{{{ secrets.{v} }}}}" for v in keys.values()})
    if dep.get("kind") in DEPLOY_KEYS:
        kind = dep["kind"]
        keys = DEPLOY_KEYS[kind]
        settings = {k: f"env:{v}" for k, v in keys.items()}
        settings.update({"enable": bool(dep.get("enable", False))})
        settings_file = f".sigma-forge-deploy-{kind}.json"
        files[settings_file] = json.dumps(settings, indent=2) + "\n"
        secrets += [v for v in keys.values() if v not in secrets]
        args = f'--kind {kind} --settings "$GITHUB_WORKSPACE/{settings_file}"'
        if dep.get("target"):
            args += f" --target {re.sub(r'[^a-z_]', '', dep['target'])}"
        step(f"Deploy to {kind}", f"python -m app.cli deploy {q} {args}", cond=f"github.event_name == 'push' && github.ref == 'refs/heads/{branch}'",
             env={v: f"${{{{ secrets.{v} }}}}" for v in keys.values()})
    yaml = "\n".join([
        "name: Sigma Forge",
        "",
        "on:",
        "  pull_request:",
        "    paths:",
        f'      - "{rules}/**"',
        "  push:",
        f"    branches: [{branch}]",
        "    paths:",
        f'      - "{rules}/**"',
        "  workflow_dispatch:",
        "",
        "permissions:",
        "  contents: read",
        "",
        "concurrency:",
        "  group: sigma-forge-${{ github.ref }}",
        "  cancel-in-progress: true",
        "",
        "jobs:",
        "  detections:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        *steps,
        "",
    ])
    files[".github/workflows/sigma-forge.yml"] = yaml
    return {"files": [{"name": k, "content": v} for k, v in files.items()], "secrets": secrets, "workflow": yaml}
