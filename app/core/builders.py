import re
import uuid
from datetime import date
from typing import Any, Dict, List

import yaml

from app.core.attack import load_attack
from app.core.sysmon import TYPES

LEVELS = ["informational", "low", "medium", "high", "critical"]
OPS = {
    "equals": "", "contains": "|contains", "startswith": "|startswith", "endswith": "|endswith", "re": "|re", "cidr": "|cidr",
    "gt": "|gt", "gte": "|gte", "lt": "|lt", "lte": "|lte", "exists": "|exists", "windash": "|contains|windash", "base64offset": "|base64offset|contains",
}

EXTRA = [
    {"id": "windows/ps_script", "product": "windows", "category": "ps_script", "label": "PowerShell script block (4104)", "fields": ["ScriptBlockText", "Path", "ScriptBlockId"]},
    {"id": "windows/ps_module", "product": "windows", "category": "ps_module", "label": "PowerShell module (4103)", "fields": ["Payload", "ContextInfo"]},
    {"id": "windows/security", "product": "windows", "service": "security", "label": "Windows Security log", "fields": ["EventID", "SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "WorkstationName", "ServiceName", "ServiceFileName", "TaskName", "TaskContent", "ObjectName", "ObjectType", "AccessMask", "ProcessName", "NewProcessName", "CommandLine", "ParentProcessName", "TicketEncryptionType", "Status", "AuthenticationPackageName", "PrivilegeList", "ShareName", "RelativeTargetName"]},
    {"id": "windows/system", "product": "windows", "service": "system", "label": "Windows System log", "fields": ["EventID", "Provider_Name", "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"]},
    {"id": "windows/windefend", "product": "windows", "service": "windefend", "label": "Microsoft Defender", "fields": ["EventID", "ThreatName", "Path", "ProcessName", "Severity Name", "Action Name"]},
    {"id": "linux/process_creation", "product": "linux", "category": "process_creation", "label": "Linux process creation", "fields": ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "CurrentDirectory", "LogonId", "ProcessId"]},
    {"id": "linux/network_connection", "product": "linux", "category": "network_connection", "label": "Linux network connection", "fields": ["Image", "DestinationIp", "DestinationPort", "DestinationHostname", "SourceIp", "Initiated", "User"]},
    {"id": "linux/file_event", "product": "linux", "category": "file_event", "label": "Linux file event", "fields": ["Image", "TargetFilename", "User"]},
    {"id": "linux/auditd", "product": "linux", "service": "auditd", "label": "Linux auditd", "fields": ["type", "exe", "comm", "a0", "a1", "a2", "a3", "key", "name", "nametype", "syscall", "uid", "auid", "SYSCALL", "proctitle"]},
    {"id": "macos/process_creation", "product": "macos", "category": "process_creation", "label": "macOS process creation", "fields": ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "CurrentDirectory"]},
    {"id": "aws/cloudtrail", "product": "aws", "service": "cloudtrail", "label": "AWS CloudTrail", "fields": ["eventName", "eventSource", "awsRegion", "sourceIPAddress", "userAgent", "errorCode", "errorMessage", "userIdentity.type", "userIdentity.arn", "userIdentity.userName", "requestParameters.userName", "requestParameters.bucketName", "responseElements.ConsoleLogin"]},
    {"id": "azure/signinlogs", "product": "azure", "service": "signinlogs", "label": "Azure sign in logs", "fields": ["ResultType", "ResultDescription", "AppDisplayName", "UserPrincipalName", "IPAddress", "Location", "ClientAppUsed", "AuthenticationRequirement", "ConditionalAccessStatus", "RiskLevelDuringSignIn"]},
    {"id": "azure/activitylogs", "product": "azure", "service": "activitylogs", "label": "Azure activity logs", "fields": ["operationName", "OperationNameValue", "status", "ActivityStatusValue", "ResourceProviderValue", "Caller"]},
    {"id": "m365/audit", "product": "m365", "service": "audit", "label": "Microsoft 365 audit", "fields": ["Operation", "Workload", "UserId", "ClientIP", "ResultStatus", "ObjectId"]},
    {"id": "okta/okta", "product": "okta", "service": "okta", "label": "Okta system log", "fields": ["eventtype", "displaymessage", "outcome.result", "outcome.reason", "actor.alternateid", "client.ipaddress"]},
    {"id": "webserver", "category": "webserver", "label": "Web server access log", "fields": ["cs-method", "cs-uri-stem", "cs-uri-query", "sc-status", "c-useragent", "c-ip", "cs-referer", "cs-host"]},
    {"id": "proxy", "category": "proxy", "label": "Web proxy", "fields": ["c-uri", "c-uri-extension", "c-uri-query", "cs-host", "cs-method", "c-useragent", "sc-status", "r-dns", "c-ip"]},
    {"id": "dns", "category": "dns", "label": "DNS server log", "fields": ["query", "answer", "QueryType", "record_type", "src_ip"]},
    {"id": "firewall", "category": "firewall", "label": "Firewall", "fields": ["src_ip", "dst_ip", "src_port", "dst_port", "action", "protocol"]},
]
LABELS = {
    "process_creation": "Process creation", "network_connection": "Network connection", "file_event": "File created", "file_delete": "File deleted",
    "registry_set": "Registry value set", "registry_add": "Registry key created", "registry_delete": "Registry deleted", "registry_event": "Registry any",
    "image_load": "DLL loaded", "dns_query": "DNS query", "pipe_created": "Named pipe", "process_access": "Process access (LSASS and more)",
    "create_remote_thread": "Remote thread", "driver_load": "Driver loaded", "wmi_event": "WMI event", "create_stream_hash": "Alternate data stream",
    "raw_access_thread": "Raw disk read", "process_tampering": "Process tampering", "file_change": "File time changed",
}


def taxonomy() -> Dict[str, Any]:
    cats = []
    for cat, (_tag, eid, fields) in TYPES.items():
        if cat not in LABELS:
            continue
        cats.append({"id": f"windows/{cat}", "product": "windows", "category": cat, "label": f"Windows {LABELS[cat].lower()} (Sysmon {eid})",
                     "fields": [f for f in fields if f not in ("RuleName", "UtcTime")]})
    cats.extend(EXTRA)
    return {"logsources": cats, "ops": list(OPS.keys()), "levels": LEVELS}


def _tactics(tid: str) -> List[str]:
    t = load_attack().get("techniques", {}).get(tid.upper()) or {}
    return [x.replace("-", "_") for x in t.get("tactics", [])]


def _tags(tids: List[str]) -> List[str]:
    tags: List[str] = []
    for raw in tids:
        tid = str(raw).strip().upper()
        if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
            continue
        for tac in _tactics(tid):
            tag = "attack." + tac.replace("_", "-")
            if tag not in tags:
                tags.append(tag)
    for raw in tids:
        tid = str(raw).strip().upper()
        if re.match(r"^T\d{4}(\.\d{3})?$", tid):
            tag = "attack." + tid.lower()
            if tag not in tags:
                tags.append(tag)
    return tags


def _value(op: str, v: str):
    v = str(v)
    if op in ("gt", "gte", "lt", "lte"):
        try:
            return int(v)
        except ValueError:
            return float(v)
    if op == "exists":
        return v.strip().lower() not in ("false", "no", "0")
    return v


def _block(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for it in items:
        field = str(it.get("field") or "").strip()
        op = str(it.get("op") or "equals")
        if not field or op not in OPS:
            continue
        if not re.match(r"^[A-Za-z0-9_.\- ]+$", field):
            raise ValueError(f"Bad field name: {field}")
        vals = [x for x in (it.get("values") or []) if str(x).strip() != ""]
        if op == "exists" and not vals:
            vals = ["true"]
        if not vals:
            continue
        key = field + OPS[op]
        if it.get("all") and len(vals) > 1 and op not in ("equals", "exists"):
            key += "|all"
        conv = [_value(op, v) for v in vals]
        if key in out:
            prev = out[key] if isinstance(out[key], list) else [out[key]]
            conv = prev + conv
        out[key] = conv[0] if len(conv) == 1 else conv
    return out


def build_from_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    title = str(spec.get("title") or "").strip() or "New detection"
    ls = {k: str(v) for k, v in (spec.get("logsource") or {}).items() if k in ("product", "category", "service") and v}
    if not ls:
        raise ValueError("Pick a log source")
    det: Dict[str, Any] = {}
    sel_names: List[str] = []
    for i, s in enumerate(spec.get("selections") or []):
        block = _block(s.get("items") or [])
        if not block:
            continue
        name = re.sub(r"[^a-z0-9_]", "_", str(s.get("name") or "").lower()).strip("_")
        name = "selection_" + name if name and not name.startswith("selection") else (name or ("selection" if i == 0 else f"selection_{i + 1}"))
        while name in det:
            name += "_2"
        det[name] = block
        sel_names.append(name)
    if not sel_names:
        raise ValueError("Add at least one field and value to match")
    filt_names: List[str] = []
    for i, f in enumerate(spec.get("filters") or []):
        block = _block(f.get("items") or [])
        if not block:
            continue
        name = re.sub(r"[^a-z0-9_]", "_", str(f.get("name") or "").lower()).strip("_") or f"main_{i + 1}"
        name = name if name.startswith("filter_") else "filter_" + name
        while name in det:
            name += "_2"
        det[name] = block
        filt_names.append(name)
    join = "1 of" if spec.get("join") == "any" else "all of"
    if spec.get("condition"):
        cond = str(spec["condition"])
    else:
        if len(sel_names) == 1:
            cond = sel_names[0]
        elif all(n.startswith("selection_") for n in sel_names):
            cond = f"{join} selection_*"
        else:
            cond = (" or " if join == "1 of" else " and ").join(sel_names)
            if len(sel_names) > 1:
                cond = f"({cond})"
        if filt_names:
            cond += " and not 1 of filter_*" if all(n.startswith("filter_") for n in filt_names) else " and not (" + " or ".join(filt_names) + ")"
    det["condition"] = cond
    rule: Dict[str, Any] = {
        "title": title[:200],
        "id": str(uuid.uuid4()),
        "status": "test",
        "description": str(spec.get("description") or "").strip() or f"Detects {title}.",
        "references": [str(r) for r in (spec.get("references") or []) if str(r).strip()],
        "author": str(spec.get("author") or "").strip() or "Sigma Forge user",
        "date": date.today().isoformat(),
        "tags": _tags(spec.get("techniques") or []),
        "logsource": ls,
        "detection": det,
        "falsepositives": [str(x) for x in (spec.get("falsepositives") or []) if str(x).strip()] or ["Unknown"],
        "level": spec.get("level") if spec.get("level") in LEVELS else "medium",
    }
    for k in ("references", "tags"):
        if not rule[k]:
            rule.pop(k)
    text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=4096)
    return {"yaml": text, "errors": _validate(text), "name": _fname(title, ls)}


def _fname(title: str, ls: Dict[str, str]) -> str:
    from app.core.sigmahq import prefix_for

    slug = re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", title.lower())).strip("_")[:70] or "rule"
    return prefix_for(ls) + slug + ".yml"


def _validate(text: str) -> List[str]:
    from app.core.parsing import parse_file

    errors = []
    try:
        for p in parse_file("rule.yml", text):
            if p.error:
                errors.append(p.error)
            elif p.rule is not None:
                _ = [c.parsed for c in p.rule.detection.parsed_condition]
    except Exception as exc:
        errors.append(str(exc))
    return errors


CORR_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")


def build_correlation(spec: Dict[str, Any], rules: List[Any]) -> Dict[str, Any]:
    ctype = spec.get("type")
    if ctype not in CORR_TYPES:
        raise ValueError("Pick a correlation type")
    if not rules:
        raise ValueError("Pick at least one rule")
    if ctype.startswith("temporal") and len(rules) < 2:
        raise ValueError("Temporal correlation needs two or more rules")
    timespan = str(spec.get("timespan") or "10m").strip()
    if not re.match(r"^\d+[smhdwMy]$", timespan):
        raise ValueError("Timespan must look like 30s, 10m, 1h or 2d")
    refs = []
    updated = []
    docs = []
    for r in rules:
        try:
            doc = yaml.safe_load(r.content)
        except yaml.YAMLError as exc:
            raise ValueError(f"{r.name}: {exc}")
        if not isinstance(doc, dict) or "detection" not in doc:
            raise ValueError(f"{r.name} is not a detection rule")
        ref = doc.get("name") or ""
        if not ref:
            base = re.sub(r"[^a-z0-9_]+", "_", str(doc.get("title") or r.name).lower()).strip("_")[:60] or "rule"
            ref = base
            new = {}
            for k, v in doc.items():
                new[k] = v
                if k == "id":
                    new["name"] = ref
            if "name" not in new:
                new = {"name": ref, **new}
            doc = new
            updated.append({"name": r.name, "content": yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=4096)})
        refs.append(str(ref))
        docs.append(doc)
    corr: Dict[str, Any] = {"type": ctype, "rules": refs}
    group = [str(g).strip() for g in (spec.get("group_by") or []) if str(g).strip()]
    if group:
        corr["group-by"] = group
    corr["timespan"] = timespan
    op = spec.get("op") if spec.get("op") in ("gt", "gte", "lt", "lte", "eq") else "gte"
    try:
        count = int(spec.get("count") or 1)
    except (TypeError, ValueError):
        raise ValueError("Count must be a number")
    if ctype in ("event_count", "value_count"):
        cond: Dict[str, Any] = {op: count}
        if ctype == "value_count":
            field = str(spec.get("field") or "").strip()
            if not field:
                raise ValueError("value_count needs a field to count")
            cond = {"field": field, op: count}
        corr["condition"] = cond
    if spec.get("generate"):
        corr["generate"] = True
    title = str(spec.get("title") or "").strip() or {
        "event_count": f"Many {docs[0].get('title', 'events')}", "value_count": f"Many distinct values in {docs[0].get('title', 'events')}",
        "temporal": "Related events close in time", "temporal_ordered": "Events in order",
    }[ctype]
    tags = []
    for d in docs:
        for t in d.get("tags") or []:
            if t not in tags:
                tags.append(t)
    out = {
        "title": title[:200],
        "id": str(uuid.uuid4()),
        "status": "test",
        "description": str(spec.get("description") or "").strip() or f"Detects {title} within {timespan}.",
        "author": str(spec.get("author") or "").strip() or "Sigma Forge user",
        "date": date.today().isoformat(),
    }
    if tags:
        out["tags"] = tags
    out["correlation"] = corr
    out["falsepositives"] = ["Unknown"]
    out["level"] = spec.get("level") if spec.get("level") in LEVELS else "high"
    text = yaml.safe_dump(out, sort_keys=False, allow_unicode=True, width=4096)
    bundle = yaml.safe_dump_all(docs + [out], sort_keys=False, allow_unicode=True, width=4096)
    errors = _validate(bundle)
    return {"yaml": text, "bundle": bundle, "updated": updated, "refs": refs, "errors": errors, "name": re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:70] + ".yml"}
