import re
import uuid
from datetime import date, datetime
from typing import Any, Dict, List

import yaml

ORDER = ["title", "id", "related", "name", "taxonomy", "status", "description", "references", "author", "date", "modified", "tags",
         "logsource", "detection", "correlation", "fields", "falsepositives", "level", "simulation", "regression_tests_path"]
REQUIRED = ["title", "id", "status", "description", "author", "date", "logsource", "detection", "level"]
RECOMMENDED = ["references", "tags", "falsepositives"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
TACTICS = {"reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
           "credential_access", "stealth", "discovery", "lateral_movement", "collection", "command_and_control", "exfiltration", "impact"}

WIN_CAT = {
    "process_creation": "proc_creation_win_", "network_connection": "net_connection_win_", "file_event": "file_event_win_",
    "file_delete": "file_delete_win_", "file_access": "file_access_win_", "file_rename": "file_rename_win_", "file_change": "file_change_win_",
    "registry_set": "registry_set_", "registry_event": "registry_event_", "registry_add": "registry_add_", "registry_delete": "registry_delete_",
    "image_load": "image_load_", "dns_query": "dns_query_win_", "pipe_created": "pipe_created_", "create_remote_thread": "create_remote_thread_win_",
    "process_access": "proc_access_win_", "driver_load": "driver_load_win_", "ps_script": "posh_ps_", "ps_module": "posh_pm_",
    "ps_classic_start": "posh_pc_", "ps_classic_provider_start": "posh_pc_", "create_stream_hash": "create_stream_hash_",
    "raw_access_thread": "raw_access_thread_", "wmi_event": "sysmon_wmi_", "process_tampering": "proc_tampering_", "sysmon_error": "sysmon_",
    "sysmon_status": "sysmon_", "clipboard_capture": "sysmon_",
}
WIN_SVC = {"security": "win_security_", "system": "win_system_", "application": "win_app_", "sysmon": "sysmon_", "powershell": "win_powershell_",
           "windefend": "win_defender_", "taskscheduler": "win_taskscheduler_", "bits-client": "win_bits_client_", "wmi": "win_wmi_",
           "dns-client": "win_dns_client_", "firewall-as": "win_firewall_as_", "codeintegrity-operational": "win_codeintegrity_",
           "ntlm": "win_ntlm_", "applocker": "win_applocker_", "msexchange-management": "win_exchange_", "appxdeployment-server": "win_appxdeployment_server_"}
LNX_CAT = {"process_creation": "proc_creation_lnx_", "network_connection": "net_connection_lnx_", "file_event": "file_event_lnx_"}
MAC_CAT = {"process_creation": "proc_creation_macos_", "file_event": "file_event_macos_"}
PRODUCT = {"aws": "aws_", "azure": "azure_", "gcp": "gcp_", "m365": "microsoft365_", "okta": "okta_", "github": "github_", "onelogin": "onelogin_",
           "google_workspace": "gworkspace_", "zeek": "zeek_", "kubernetes": "kubernetes_"}


def prefix_for(ls: Dict[str, Any]) -> str:
    product = str(ls.get("product") or "").lower()
    category = str(ls.get("category") or "").lower()
    service = str(ls.get("service") or "").lower()
    if product == "windows":
        if category in WIN_CAT:
            return WIN_CAT[category]
        if service in WIN_SVC:
            return WIN_SVC[service]
        return "win_"
    if product == "linux":
        if category in LNX_CAT:
            return LNX_CAT[category]
        if service == "auditd":
            return "lnx_auditd_"
        return "lnx_"
    if product == "macos":
        return MAC_CAT.get(category, "macos_")
    if product in PRODUCT:
        return PRODUCT[product]
    if category == "proxy":
        return "proxy_"
    if category == "webserver":
        return "web_"
    if category in ("firewall", "dns"):
        return f"net_{category}_"
    return ""


def _slug(text: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", text.lower())).strip("_")[:80]


def _date_ok(v: Any) -> bool:
    if isinstance(v, (date, datetime)):
        return True
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", str(v or "")))


def _as_date(v: Any):
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    try:
        return datetime.strptime(str(v), "%Y-%m-%d").date()
    except ValueError:
        return None


def check_rule(name: str, content: str) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []

    def add(level, cid, text):
        checks.append({"level": level, "id": cid, "text": text})

    if "\t" in content:
        add("error", "tabs", "Uses tab characters. Use spaces.")
    lines = content.split("\n")
    trailing = [i + 1 for i, l in enumerate(lines) if l != l.rstrip()]
    if trailing:
        add("warn", "trailing_space", f"Trailing spaces on line {', '.join(map(str, trailing[:5]))}")
    if content and not content.endswith("\n"):
        add("warn", "newline", "File should end with a new line")
    indents = {len(l) - len(l.lstrip(" ")) for l in lines if l.strip() and not l.lstrip().startswith("#") and not l.lstrip().startswith("- ")}
    indents.discard(0)
    if indents and min(indents) != 4:
        add("warn", "indent", f"SigmaHQ uses 4 space indent. This file uses {min(indents)}.")
    try:
        docs = [d for d in yaml.safe_load_all(content) if d is not None]
    except yaml.YAMLError as exc:
        add("error", "yaml", f"YAML error: {exc}")
        return {"name": name, "checks": checks, "score": 0, "suggested_name": "", "ok": False}
    if not docs or not isinstance(docs[0], dict):
        add("error", "yaml", "No rule found")
        return {"name": name, "checks": checks, "score": 0, "suggested_name": "", "ok": False}
    if len(docs) > 1:
        add("warn", "multi_doc", "SigmaHQ keeps one rule per file")
    doc = docs[0]
    is_corr = "correlation" in doc
    for key in REQUIRED:
        if key in ("logsource", "detection") and is_corr:
            continue
        if key not in doc or doc.get(key) in (None, "", []):
            add("error", f"missing_{key}", f"Missing {key}")
    for key in RECOMMENDED:
        if key not in doc or not doc.get(key):
            add("warn", f"missing_{key}", f"Add {key}")
    keys = [k for k in doc.keys() if k in ORDER]
    want = sorted(keys, key=ORDER.index)
    if keys != want:
        add("warn", "order", "Fields are not in SigmaHQ order: " + ", ".join(want))
    unknown = [k for k in doc.keys() if k not in ORDER]
    if unknown:
        add("info", "custom_fields", "Custom fields SigmaHQ does not use: " + ", ".join(map(str, unknown[:6])))
    title = str(doc.get("title") or "")
    if title:
        if len(title) > 110:
            add("error", "title_length", f"Title is {len(title)} characters. Keep it at 110 or less.")
        if title.endswith("."):
            add("warn", "title_dot", "Title should not end with a period")
        if title[0].islower():
            add("warn", "title_case", "Title should start with a capital letter")
        if re.match(r"(?i)^(detects?|rule|sigma)\b", title):
            add("warn", "title_start", "Title should name the behavior, not start with Detects or Rule")
    rid = doc.get("id")
    if rid:
        try:
            u = uuid.UUID(str(rid))
            if u.version != 4:
                add("warn", "id_version", "id should be a version 4 UUID")
        except ValueError:
            add("error", "id_format", "id is not a valid UUID")
    status = str(doc.get("status") or "")
    if status and status not in STATUS:
        add("error", "status", f"Unknown status {status}")
    elif status in ("experimental", "stable"):
        add("info", "status_new", "New rules sent to SigmaHQ should use status: test")
    desc = str(doc.get("description") or "")
    if desc:
        if not re.match(r"^Detects\b", desc.strip()):
            add("warn", "description_start", "Description should start with Detects")
        if len(desc.strip()) < 16:
            add("warn", "description_short", "Description is too short")
        if "Sigma Forge" in desc:
            add("warn", "description_tool", "Description mentions Sigma Forge. Write what the rule finds and why.")
    author = doc.get("author")
    if author and str(author).strip().lower() in ("sigma forge", "unknown", "me"):
        add("warn", "author", "Put your real name or handle as author")
    for key in ("date", "modified"):
        if key in doc and not _date_ok(doc[key]):
            add("error", f"{key}_format", f"{key} must be YYYY-MM-DD")
    d1, d2 = _as_date(doc.get("date")), _as_date(doc.get("modified"))
    if d1 and d2 and d2 < d1:
        add("error", "modified_before", "modified is before date")
    if d1 and d1 > date.today():
        add("warn", "date_future", "date is in the future")
    tags = doc.get("tags") or []
    if tags and not isinstance(tags, list):
        add("error", "tags_list", "tags must be a list")
        tags = []
    has_tid = has_tactic = False
    for t in tags:
        s = str(t)
        if s != s.lower():
            add("error", "tag_case", f"Tag {s} must be lowercase")
        if not re.match(r"^[a-z0-9_.-]+$", s.lower()):
            add("error", "tag_format", f"Tag {s} has bad characters")
        if re.match(r"^attack\.t\d{4}", s.lower()):
            has_tid = True
        if s.lower().removeprefix("attack.").replace("-", "_") in TACTICS:
            has_tactic = True
    if len(set(map(str, tags))) != len(tags):
        add("warn", "tag_dupe", "Duplicate tags")
    if has_tid and not has_tactic:
        add("warn", "tag_tactic", "Add the ATT&CK tactic tag too, like attack.execution")
    if not has_tid and not is_corr:
        add("info", "tag_technique", "No ATT&CK technique tag")
    refs = doc.get("references") or []
    if refs and isinstance(refs, list):
        for r in refs:
            if not re.match(r"^https?://", str(r)):
                add("warn", "reference_url", f"Reference is not a URL: {str(r)[:60]}")
    fps = doc.get("falsepositives")
    if fps is not None and not isinstance(fps, list):
        add("error", "falsepositives_list", "falsepositives must be a list")
    level = str(doc.get("level") or "")
    if level and level not in LEVELS:
        add("error", "level", f"Unknown level {level}")
    det = doc.get("detection") if isinstance(doc.get("detection"), dict) else {}
    for k in det:
        if k == "condition" or k == "timeframe":
            continue
        if not re.match(r"^(selection|filter|keywords?)(_[a-z0-9_]+)?$", str(k)):
            add("info", "detection_name", f"Detection {k}: SigmaHQ names them selection_*, filter_main_*, filter_optional_*")
            break
    for k in det:
        if str(k).startswith("filter") and not re.match(r"^filter_(main|optional)_", str(k)) and k != "filter":
            add("info", "filter_name", f"Filter {k}: SigmaHQ uses filter_main_* and filter_optional_*")
            break
    cond = det.get("condition")
    if isinstance(cond, list):
        add("warn", "condition_list", "Use one condition string, not a list")
    if isinstance(cond, str) and re.search(r"\b(all|1) of them\b", cond):
        add("info", "of_them", "SigmaHQ prefers named groups over 'of them'")
    ls = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    suggested = ""
    base = name.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0]
    if not re.match(r"^[a-z0-9_]+\.yml$", base):
        add("error", "filename_format", "File name must be lowercase snake case ending in .yml")
    pre = prefix_for(ls) if not is_corr else ""
    if pre:
        if not stem.startswith(pre):
            rest = re.sub(r"^(proc_creation|net_connection|file_event|registry_set|image_load|dns_query|posh_ps|posh_pm|win_security|win_system)_(win_|lnx_|macos_)?", "", _slug(stem))
            suggested = pre + (rest or _slug(title))
            add("error", "filename_prefix", f"File name should start with {pre}")
    elif not re.match(r"^[a-z0-9_]+\.yml$", base):
        suggested = _slug(stem or title)
    if suggested:
        suggested = suggested[:100] + ".yml"
    errors = sum(1 for c in checks if c["level"] == "error")
    warns = sum(1 for c in checks if c["level"] == "warn")
    score = max(0, 100 - errors * 15 - warns * 5)
    return {"name": name, "title": title, "checks": checks, "errors": errors, "warnings": warns, "score": score, "ok": errors == 0, "suggested_name": suggested}


class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def fix_rule(name: str, content: str) -> Dict[str, Any]:
    docs = [d for d in yaml.safe_load_all(content) if d is not None]
    if not docs or not isinstance(docs[0], dict):
        raise ValueError("No rule found")
    changes = []
    out_docs = []
    for doc in docs:
        keys = list(doc.keys())
        ordered = {k: doc[k] for k in sorted(keys, key=lambda k: ORDER.index(k) if k in ORDER else len(ORDER))}
        if list(ordered.keys()) != keys:
            changes.append("Put fields in SigmaHQ order")
        if isinstance(ordered.get("tags"), list):
            low = list(dict.fromkeys(str(t).lower() for t in ordered["tags"]))
            if low != ordered["tags"]:
                changes.append("Made tags lowercase and removed duplicates")
            ordered["tags"] = low
        if ordered.get("status") in ("experimental",):
            ordered["status"] = "test"
            changes.append("Set status to test")
        for key in ("date", "modified"):
            v = ordered.get(key)
            if isinstance(v, (date, datetime)):
                ordered[key] = _as_date(v).isoformat()
        if "falsepositives" not in ordered and "detection" in ordered:
            ordered["falsepositives"] = ["Unknown"]
            changes.append("Added falsepositives")
        out_docs.append(ordered)
    text = yaml.dump_all(out_docs, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=4096, indent=4, default_flow_style=False)
    text = re.sub(r"^(\s*\w+): '(\d{4}-\d{2}-\d{2})'$", r"\1: \2", text, flags=re.M)
    text = "\n".join(l.rstrip() for l in text.split("\n"))
    if not text.endswith("\n"):
        text += "\n"
    if text != content:
        changes.append("Used 4 space indent and removed trailing spaces")
    base = name.rsplit("/", 1)[-1]
    res = check_rule(name, text)
    if "#" in content:
        changes.append("Comments were removed")
    return {"content": text, "changes": list(dict.fromkeys(changes)), "suggested_name": res["suggested_name"] or base, "check": res}


def check_inputs(items) -> Dict[str, Any]:
    rows = [check_rule(i.name, i.content) for i in items]
    return {"rules": rows, "ready": sum(1 for r in rows if r["ok"] and not r["warnings"]), "total": len(rows)}
