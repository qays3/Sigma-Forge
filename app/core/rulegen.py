import re
import uuid
from datetime import date
from typing import Any, Dict, List, Optional

import yaml

from app.core.logtest import _flatten, _strip_wrapper

PATH_FIELDS = {"image", "parentimage", "targetfilename", "imageloaded", "sourceimage", "targetimage", "originalfilename", "imagepath", "exe", "a0"}
TEXT_FIELDS = {"commandline", "parentcommandline", "scriptblocktext", "payload", "details", "destination", "a1", "a2", "message", "c-uri", "cs-uri-query"}
PRIORITY = [
    "Image", "OriginalFileName", "CommandLine", "ParentImage", "TargetFilename", "TargetObject", "Details", "QueryName",
    "DestinationIp", "DestinationPort", "ImageLoaded", "TargetImage", "SourceImage", "GrantedAccess", "PipeName",
    "ScriptBlockText", "Payload", "ServiceName", "ImagePath", "TargetUserName", "LogonType", "Status", "eventSource",
    "eventName", "OperationName", "Operation", "c-useragent", "cs-host", "c-uri", "dst_port", "type", "a0", "a1", "a2", "EventID",
]
SKIP = {"timestamp", "utctime", "processguid", "processid", "eventrecordid", "execution_processid", "execution_threadid", "rulename",
        "hashes", "logonid", "logonguid", "_generated_for", "version", "level", "task", "opcode", "keywords", "security_userid",
        "provider_guid", "parentprocessguid", "parentprocessid", "sourceprocessguid", "targetprocessguid", "currentdirectory"}
STOP = {"the", "and", "for", "with", "from", "exe", "c:", "-c", "/c", "-e"}


def _tokens(text: str) -> List[str]:
    parts = re.findall(r"[^\s\"']+", text)
    scored = []
    for p in parts:
        low = p.lower().strip(",;")
        if len(low) < 3 or low in STOP:
            continue
        score = len(low)
        if low.startswith(("-", "/")):
            score += 10
        if any(ch in low for ch in ".:\\/=$"):
            score += 6
        scored.append((score, p.strip(",;")))
    scored.sort(key=lambda x: -x[0])
    picked = []
    for _, p in scored:
        if p not in picked:
            picked.append(p)
        if len(picked) >= 3:
            break
    return picked


def _item(name: str, value: Any):
    low = name.lower()
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit() and len(value) < 8):
        return name, int(value) if not isinstance(value, float) else value
    text = str(value)
    if low in PATH_FIELDS and ("\\" in text or "/" in text):
        sep = "\\" if "\\" in text else "/"
        return f"{name}|endswith", sep + text.split(sep)[-1]
    if low in TEXT_FIELDS and len(text) > 40:
        toks = _tokens(text)
        if len(toks) > 1:
            return f"{name}|contains|all", toks
        if toks:
            return f"{name}|contains", toks[0]
    return name, text


def available_fields(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    flat: Dict[str, Any] = {}
    _flatten(_strip_wrapper(dict(event)), (), flat)
    out = []
    for low, (name, value) in flat.items():
        if low in SKIP or "." in name and name.split(".")[0] in ("logsource",):
            continue
        if isinstance(value, (dict, list)):
            continue
        out.append({"name": name, "value": value})
    rank = {p.lower(): i for i, p in enumerate(PRIORITY)}
    out.sort(key=lambda f: (rank.get(f["name"].lower(), 999), f["name"].lower()))
    return out


def build_rule(event: Dict[str, Any], logsource: Optional[Dict[str, str]], fields: Optional[List[str]] = None, title: str = "") -> Dict[str, Any]:
    event = dict(event)
    declared = event.pop("logsource", None)
    ls = {k: v for k, v in (logsource or declared or {}).items() if v}
    avail = available_fields(event)
    names = {f["name"]: f["value"] for f in avail}
    if fields:
        chosen = [f for f in fields if f in names]
    else:
        rank = {p.lower(): i for i, p in enumerate(PRIORITY)}
        chosen = [f["name"] for f in avail if f["name"].lower() in rank][:4]
        if ls.get("category") and len(chosen) > 1:
            chosen = [c for c in chosen if c.lower() != "eventid"] or chosen
    if not chosen:
        raise ValueError("Pick at least one field to build the rule from")
    selection = {}
    for name in chosen:
        key, value = _item(name, names[name])
        selection[key] = value
    main = names.get("Image") or names.get("CommandLine") or names.get("QueryName") or names.get("eventName") or ""
    if not title:
        base = str(main).replace("\\", "/").split("/")[-1][:60] if main else "Event"
        title = f"Suspicious {base}" if base else "Rule From Event"
    rule = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": "Built from an event by Sigma Forge. Check the values and add filters before you deploy it.",
        "author": "Sigma Forge",
        "date": date.today().isoformat(),
        "tags": [],
        "logsource": ls or {"product": "windows"},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": ["Unknown"],
        "level": "medium",
    }
    rule.pop("tags")
    text = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False)
    return {"yaml": text, "fields": avail, "chosen": chosen}


def add_filter(content: str, title: str, filters: List[Dict[str, Any]]) -> str:
    docs = list(yaml.safe_load_all(content))
    target = None
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("detection"), dict) and (not title or doc.get("title") == title):
            target = doc
            break
    if target is None:
        for doc in docs:
            if isinstance(doc, dict) and isinstance(doc.get("detection"), dict):
                target = doc
                break
    if target is None:
        raise ValueError("No detection found in this rule")
    det = target["detection"]
    name = "filter_sf_noise"
    n = 2
    while name in det:
        name = f"filter_sf_noise_{n}"
        n += 1
    block: Dict[str, Any] = {}
    for f in filters:
        field, value = str(f["field"]), f["value"]
        if field in block:
            prev = block[field] if isinstance(block[field], list) else [block[field]]
            block[field] = prev + [value]
        else:
            block[field] = value
    cond = det.get("condition", "selection")
    if isinstance(cond, list):
        cond = [f"({c}) and not {name}" for c in cond]
    else:
        cond = f"({cond}) and not {name}"
    new_det = {k: v for k, v in det.items() if k != "condition"}
    new_det[name] = block
    new_det["condition"] = cond
    target["detection"] = new_det
    fps = target.get("falsepositives") or []
    if "Noise from the baseline logs, filtered by Sigma Forge" not in fps:
        target["falsepositives"] = list(fps) + ["Noise from the baseline logs, filtered by Sigma Forge"]
    return yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False)
