import io
import json
import re
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.config import APP_NAME, APP_VERSION
from app.core.attack import split_attack_tags
from app.core.converter import ConversionRequestError, convert
from app.core.parsing import parse_inputs
from app.core.targets import TARGET_MAP, target_formats

QUERY_EXT = {
    "spl": "spl", "spl2": "spl2", "lucene": "txt", "esql": "esql", "eql": "eql", "kql": "kql", "xml": "xml", "yaml": "yml",
    "ppl": "ppl", "logscale": "txt", "s1ql": "txt", "powerquery": "txt", "xql": "xql", "udm": "txt", "cbc": "txt", "aql": "aql",
    "lpql": "txt", "netwitness": "txt", "json": "json", "python": "py", "tql": "txt", "logql": "logql", "quickwit": "txt",
    "sql": "sql", "surrealql": "surql",
}


class Package:
    def __init__(self, pid: str, name: str, description: str, targets: Tuple[str, ...], fmt: str, kind: str, ext: str = "", install: str = ""):
        self.id = pid
        self.name = name
        self.description = description
        self.targets = targets
        self.format = fmt
        self.kind = kind
        self.ext = ext
        self.install = install


PACKAGES = [
    Package("splunk_app", "Splunk app", "A Splunk app folder with one scheduled saved search per rule.", ("splunk", "splunk_cim"), "default", "splunk_app",
            install="Copy the app folder into $SPLUNK_HOME/etc/apps/ (or tar it as a .spl file and install it from Apps > Install app from file), then restart Splunk. Every search runs every 15 minutes over the last 15 minutes and is turned off until you enable it."),
    Package("spl2_module", "SPL2 module", "One SPL2 module file with a named search per rule.", ("splunk_spl2",), "module", "bundle", "spl2",
            install="Open Splunk Cloud Platform search or the SPL2 editor and import the module file."),
    Package("kibana_rules", "Kibana detection rules", "An NDJSON file you can import into Elastic Security as detection rules.", ("elastic_lucene", "elastic_esql", "elastic_eql"), "siem_rule_ndjson", "bundle", "ndjson",
            install="In Kibana go to Security > Rules > Detection rules > Import rules and pick rules.ndjson. Rules are imported turned on, so check them first."),
    Package("elastalert_rules", "ElastAlert rules", "One ElastAlert rule file per Sigma rule.", ("elastalert",), "default", "per_rule", "yml",
            install="Copy the rules folder into the rules_folder of your ElastAlert config and set the alert outputs."),
    Package("opensearch_monitors", "OpenSearch monitors", "One alerting monitor JSON per rule.", ("opensearch_lucene",), "monitor_rule", "per_rule", "json",
            install="POST each file to _plugins/_alerting/monitors on your OpenSearch cluster."),
    Package("sentinel_arm", "Sentinel analytics rules (ARM)", "An ARM template with one scheduled analytics rule per Sigma rule.", ("sentinel_asim", "azure_monitor", "defender_xdr"), "default", "sentinel_arm",
            install="Deploy azuredeploy.json with: az deployment group create -g <resource group> --template-file azuredeploy.json --parameters workspace=<workspace name>. Rules are created turned off."),
    Package("secops_yaral", "Google SecOps YARA-L rules", "One YARA-L 2.0 rule file per Sigma rule.", ("secops",), "yara_l", "per_rule", "yaral",
            install="Paste each rule in the Rules Editor of Google SecOps or upload them with the Detection Engine API."),
    Package("loki_ruler", "Loki ruler rules", "A Loki ruler YAML file with one alert per rule.", ("loki",), "ruler", "bundle", "yml",
            install="Put rules.yml in the ruler storage of each tenant (for example /loki/rules/<tenant>/) or load it with lokitool rules sync."),
    Package("grafana_alerting", "Grafana alert rules", "Grafana alerting rules for a Loki data source.", ("loki",), "grafana_alerting", "bundle", "yml",
            install="Import the file in Grafana under Alerting > Alert rules > Import, or with the provisioning API."),
    Package("cse_rules", "Sumo Logic CSE rules", "A JSON file with Cloud SIEM rules.", ("sumologic_cse",), "cse_rule", "bundle", "json",
            install="Import the rules with the Cloud SIEM rules API or the Sumo Logic Terraform provider."),
    Package("panther_rules", "Panther simple detections", "Panther simple detection YAML per rule.", ("panther",), "sdyaml", "per_rule", "yml",
            install="Add the files to your panther-analysis repo, set LogTypes and run panther_analysis_tool upload."),
    Package("clickdetect", "ClickDetect rules", "One ClickDetect rule file per Sigma rule.", ("clickhouse",), "clickdetect", "per_rule", "yml",
            install="Copy the rules folder into the ClickDetect rules path."),
    Package("zircolite", "Zircolite rule pack", "A Zircolite JSON rule pack for offline EVTX hunting.", ("sqlite",), "zircolite", "bundle", "json",
            install="Run: python zircolite.py --evtx <logs> --ruleset rules.json"),
    Package("wazuh_rules", "Wazuh rules file", "One Wazuh rules XML file ready for the manager.", ("wazuh",), "default", "bundle", "xml",
            install="Copy the XML file to /var/ossec/etc/rules/ on the Wazuh manager, run /var/ossec/bin/wazuh-logtest to check it, then restart the manager."),
]

GENERIC = Package("queries", "Query files", "One query file per rule with a manifest.", (), "", "per_rule")

SEVERITY_SPLUNK = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}
SEVERITY_SENTINEL = {"informational": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "High"}
SENTINEL_TACTICS = {
    "reconnaissance": "Reconnaissance", "resource-development": "ResourceDevelopment", "initial-access": "InitialAccess",
    "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "PrivilegeEscalation",
    "defense-evasion": "DefenseEvasion", "stealth": "DefenseEvasion", "defense-impairment": "DefenseEvasion",
    "credential-access": "CredentialAccess", "discovery": "Discovery", "lateral-movement": "LateralMovement",
    "collection": "Collection", "command-and-control": "CommandAndControl", "exfiltration": "Exfiltration", "impact": "Impact",
}


def packages_for(target_id: str) -> List[Dict]:
    target = TARGET_MAP.get(target_id)
    if target is None:
        return []
    formats = target_formats(target)
    out = []
    for pkg in PACKAGES:
        if target_id in pkg.targets and (pkg.format in formats):
            out.append(_describe(pkg))
    generic = _describe(GENERIC)
    generic["description"] = f"One {target.name} query file per rule, a manifest and a README."
    out.append(generic)
    return out


def _describe(pkg: Package) -> Dict:
    return {"id": pkg.id, "name": pkg.name, "description": pkg.description, "format": pkg.format or "default"}


def all_packages() -> Dict[str, List[Dict]]:
    return {t: packages_for(t) for t in TARGET_MAP}


def _slug(text: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:80] or "rule"
    name = base
    n = 2
    while name in used:
        name = f"{base}_{n}"
        n += 1
    used.add(name)
    return name


def _guid(rule_id: str, title: str) -> str:
    try:
        return str(uuid.UUID(rule_id))
    except (ValueError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"sigma-forge:{title}"))


def _meta(items) -> Dict[str, Dict]:
    out = {}
    for p in parse_inputs(items):
        obj = p.rule if p.rule is not None else p.correlation
        if obj is None:
            continue
        techniques, tactics = split_attack_tags(getattr(obj, "tags", []) or [])
        out[p.key] = {
            "id": str(obj.id) if getattr(obj, "id", None) else "",
            "title": obj.title,
            "description": (getattr(obj, "description", "") or "").strip(),
            "level": obj.level.name.lower() if getattr(obj, "level", None) else "medium",
            "techniques": techniques,
            "tactics": tactics,
            "author": getattr(obj, "author", "") or "",
            "references": list(getattr(obj, "references", []) or []),
            "falsepositives": list(getattr(obj, "falsepositives", []) or []),
        }
    return out


def _conf_value(text: str) -> str:
    return " \\\n".join(line.rstrip() for line in str(text).splitlines() if line.strip()) or ""


def _splunk_app(name: str, rows: List[Dict], meta: Dict[str, Dict]) -> Dict[str, str]:
    stanzas = []
    used = set()
    for row in rows:
        info = meta.get(row["key"], {})
        title = f"Sigma - {row['title']}"
        while title in used:
            title += " (2)"
        used.add(title)
        query = row["queries"][0]
        if len(row["queries"]) > 1:
            query = "\n| append [ search " + " ]\n| append [ search ".join(row["queries"][1:]) + " ]"
            query = row["queries"][0] + query
        lines = [
            f"[{title.replace('[', '(').replace(']', ')')}]",
            f"search = {_conf_value(query)}",
            f"description = {_conf_value(info.get('description', ''))}",
            "cron_schedule = */15 * * * *",
            "dispatch.earliest_time = -15m@m",
            "dispatch.latest_time = now",
            "enableSched = 1",
            "disabled = 1",
            "alert.track = 1",
            f"alert.severity = {SEVERITY_SPLUNK.get(info.get('level', 'medium'), 4)}",
            "alert.digest_mode = 1",
            "counttype = number of events",
            "relation = greater than",
            "quantity = 0",
        ]
        if info.get("techniques"):
            lines.append(f"action.correlationsearch.annotations = {json.dumps({'mitre_attack': info['techniques']})}")
        stanzas.append("\n".join(lines))
    app_conf = "\n".join([
        "[install]", "is_configured = 1", "",
        "[ui]", "is_visible = 0", f"label = {name}", "",
        "[launcher]", f"author = {APP_NAME}", f"description = Sigma rules converted by {APP_NAME}", f"version = {APP_VERSION}", "",
        "[package]", f"id = {name}", "",
    ])
    meta_conf = "[]\naccess = read : [ * ], write : [ admin, sc_admin ]\nexport = system\n"
    return {
        f"{name}/default/app.conf": app_conf,
        f"{name}/default/savedsearches.conf": "\n\n".join(stanzas) + "\n",
        f"{name}/metadata/default.meta": meta_conf,
    }


def _sentinel_arm(rows: List[Dict], meta: Dict[str, Dict]) -> str:
    resources = []
    for row in rows:
        info = meta.get(row["key"], {})
        guid = _guid(info.get("id", ""), row["title"])
        tactics = sorted({SENTINEL_TACTICS[t] for t in info.get("tactics", []) if t in SENTINEL_TACTICS})
        techniques = sorted({t.split(".")[0] for t in info.get("techniques", [])})
        query = row["queries"][0] if len(row["queries"]) == 1 else "\n| union ".join(f"({q})" for q in row["queries"])
        resources.append({
            "id": f"[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/{guid}')]",
            "name": f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/{guid}')]",
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "kind": "Scheduled",
            "apiVersion": "2023-02-01",
            "properties": {
                "displayName": row["title"],
                "description": info.get("description", "")[:4900],
                "severity": SEVERITY_SENTINEL.get(info.get("level", "medium"), "Medium"),
                "enabled": False,
                "query": query,
                "queryFrequency": "PT1H",
                "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False,
                "tactics": tactics,
                "techniques": techniques,
                "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
            },
        })
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {"type": "String", "metadata": {"description": "Name of the Log Analytics workspace with Microsoft Sentinel"}}},
        "resources": resources,
    }
    return json.dumps(template, indent=2)


def _merge_into(base: str, queries: List[str], ext: str) -> Optional[str]:
    try:
        items = [json.loads(q) for q in queries]
    except ValueError:
        return None
    if not all(isinstance(i, dict) for i in items):
        return None
    if ext == "ndjson":
        lines = [line for line in base.splitlines() if line.strip()]
        return "\n".join(lines + [json.dumps(i, default=str) for i in items])
    if ext != "json":
        return None
    try:
        data = json.loads(base) if base.strip() else []
    except ValueError:
        return None
    if isinstance(data, list):
        data.extend(items)
        return json.dumps(data, indent=2, default=str)
    if isinstance(data, dict):
        lists = [k for k, v in data.items() if isinstance(v, list)]
        if len(lists) == 1:
            data[lists[0]].extend(items)
            return json.dumps(data, indent=4, default=str)
    return None


def _structured(text: str) -> bool:
    try:
        return isinstance(json.loads(text), (dict, list))
    except ValueError:
        return False


def _as_ext(text: str, path: str) -> str:
    if path.endswith((".yml", ".yaml")):
        try:
            data = json.loads(text)
        except ValueError:
            return text
        if isinstance(data, (dict, list)):
            import yaml

            return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096)
    return text


def _readme(pkg: Package, target, name: str, rows: List[Dict], failed: List[Dict], skipped: List[Dict], notes: List[str], mapped: Dict) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {name}",
        "",
        f"{pkg.name} for {target.name}, made by {APP_NAME} on {stamp}.",
        "",
        "## Install",
        "",
        pkg.install or f"Each file holds the {target.name} query for one rule. Paste them into {target.name} or load them with its API.",
        "",
        "## Rules",
        "",
        f"{len(rows)} converted, {len(skipped)} skipped, {len(failed)} failed.",
        "",
        "| Rule | Level | File |",
        "| --- | --- | --- |",
    ]
    for row in rows:
        lines.append(f"| {row['title']} | {row['level'] or '-'} | {row.get('file_out', '-')} |")
    if failed:
        lines += ["", "## Not converted", ""]
        for row in failed:
            lines.append(f"- {row['title']} ({row['file']}): {row['error']}")
    if skipped:
        lines += ["", "## Skipped", ""]
        for row in skipped:
            lines.append(f"- {row['title']} ({row['file']}): only used inside a correlation rule")
    extra = [r for r in rows if str(r.get("file_out", "")).startswith("extra/")]
    if extra:
        lines += ["", "## Extra files", "", "Correlation rules and rules that needed a fallback could not go into the main file. They are in the extra folder as plain queries, so add them by hand."]
    warned = [r for r in rows if r["warnings"]]
    if warned:
        lines += ["", "## Check these", ""]
        for row in warned:
            lines.append(f"- {row['title']}: {' '.join(row['warnings'])}")
    if notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in notes]
    if mapped:
        lines += ["", "## Field mapping", "", "| Sigma field | Uses |", "| --- | --- |"]
        lines += [f"| {k} | {v} |" for k, v in sorted(mapped.items())]
    return "\n".join(lines) + "\n"


def build_export(items, target_id: str, fmt: str, options, field_mapping, package_id: str, name: str) -> Tuple[str, bytes, Dict]:
    target = TARGET_MAP.get(target_id)
    if target is None:
        raise ConversionRequestError(f"Unknown target: {target_id}")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._") or "sigma-forge"
    offered = {p["id"] for p in packages_for(target_id)}
    if package_id == "auto":
        package_id = next(iter(p["id"] for p in packages_for(target_id)))
    if package_id not in offered:
        raise ConversionRequestError(f"Package '{package_id}' is not available for {target.name}")
    pkg = next((p for p in PACKAGES if p.id == package_id), GENERIC)
    use_fmt = pkg.format or fmt
    items = list(items)
    result = convert(items, target_id, use_fmt, options, field_mapping)
    meta = _meta(items)
    rows = [r for r in result["results"] if not r["error"] and r["queries"]]
    failed = [r for r in result["results"] if r["error"]]
    skipped = [r for r in result["results"] if not r["error"] and not r["queries"]]
    if not rows:
        raise ConversionRequestError("No rule converted, so there is nothing to export")

    files: Dict[str, str] = {}
    ext = pkg.ext or QUERY_EXT.get(target.language, "txt")
    if pkg.kind == "splunk_app":
        files.update(_splunk_app(name, rows, meta))
        for row in rows:
            row["file_out"] = "savedsearches.conf"
    elif pkg.kind == "sentinel_arm":
        files["azuredeploy.json"] = _sentinel_arm(rows, meta)
        for row in rows:
            row["file_out"] = "azuredeploy.json"
    elif pkg.kind == "bundle":
        filename = {"ndjson": "rules.ndjson", "xml": f"{name}_rules.xml"}.get(ext, f"rules.{ext}")
        if target_id == "wazuh":
            base, extras = result["bundle"], []
        else:
            base = result.get("bundle_base") or ""
            extras = [r for r in rows if r["kind"] == "correlation" or r["meta"].get("fallback")]
        if not base and not extras:
            raise ConversionRequestError(result.get("bundle_error") or "The bundle is empty")
        merged = set()
        for row in extras:
            new_base = _merge_into(base, row["queries"], ext)
            if new_base is not None:
                base = new_base
                merged.add(row["key"])
        if base:
            files[filename] = base.strip() + "\n"
        used = set()
        extra_keys = {r["key"] for r in extras} - merged
        for row in rows:
            if row["key"] in extra_keys:
                stem = _slug(row["title"], used)
                path = f"extra/{stem}.{QUERY_EXT.get(target.language, 'txt') if not _structured(row['queries'][0]) else ext}"
                files[path] = "\n\n".join(_as_ext(q, path) for q in row["queries"]).rstrip() + "\n"
                row["file_out"] = path
            else:
                row["file_out"] = filename
    else:
        used = set()
        for row in rows:
            stem = _slug(row["title"], used)
            path = f"rules/{stem}.{ext}"
            if ext == "json" and len(row["queries"]) > 1:
                body = "[\n" + ",\n".join(row["queries"]) + "\n]"
            else:
                body = "\n\n".join(_as_ext(q, path) for q in row["queries"])
            files[path] = body.rstrip() + "\n"
            row["file_out"] = path

    manifest = {
        "generator": f"{APP_NAME} {APP_VERSION}",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": result["target"],
        "package": package_id,
        "format": use_fmt,
        "summary": result["summary"],
        "field_mapping": field_mapping or {},
        "rules": [
            {
                "title": r["title"],
                "id": meta.get(r["key"], {}).get("id", ""),
                "level": r["level"],
                "source": r["file"],
                "file": r.get("file_out", ""),
                "status": "failed" if r["error"] else ("skipped" if not r["queries"] else "converted"),
                "warnings": r["warnings"],
                "error": r["error"],
                "techniques": meta.get(r["key"], {}).get("techniques", []),
            }
            for r in result["results"]
        ],
    }
    files["manifest.json"] = json.dumps(manifest, indent=2)
    files["README.md"] = _readme(pkg, target, name, rows, failed, skipped, result["notes"], result.get("mapped_fields") or {})

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, body in files.items():
            archive.writestr(f"{name}/{path}", body)
    summary = {"package": package_id, "files": len(files), **result["summary"]}
    return f"{name}-{target_id}-{package_id}.zip", buffer.getvalue(), summary
