import re
from typing import Any, Dict, List, Tuple

from app.core.logtest import LogDatabase, _rule_fields, load_events
from app.core.parsing import parse_inputs
from app.core.querygen import FIELD_MAP

IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]{3,}:[0-9a-f:]+$", re.I)
SHAPES = {
    "path_exe": (re.compile(r"[\\/][^\\/]+\.(exe|dll|sys|bat|cmd|ps1|com|scr)$", re.I), {"image", "parentimage", "targetimage", "sourceimage", "imageloaded", "servicefilename", "imagepath"}),
    "ip": (IP, {"destinationip", "sourceip", "ipaddress", "src_ip", "dst_ip", "clientip"}),
    "port": (re.compile(r"^\d{1,5}$"), {"destinationport", "sourceport", "port", "dst_port", "src_port"}),
    "hash": (re.compile(r"(md5|sha1|sha256)=|^[0-9a-f]{32,64}$", re.I), {"hashes", "hash", "md5", "sha1", "sha256", "imphash"}),
    "user": (re.compile(r"^[^\\\s]+\\[^\\\s]+$|^[^@\s]+@[^@\s]+$"), {"user", "targetusername", "subjectusername", "parentuser", "sourceuser", "targetuser", "accountname"}),
    "cmd": (re.compile(r"\s-{1,2}\w|\s/\w|\.exe\"?\s", re.I), {"commandline", "parentcommandline", "processcommandline"}),
    "reg": (re.compile(r"^(HKLM|HKCU|HKU|HKCR|\\REGISTRY\\)", re.I), {"targetobject", "objectname", "registrykey"}),
    "domain": (re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+\.?$", re.I), {"queryname", "destinationhostname", "dns.question.name", "hostname"}),
}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _reverse() -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for foreign, (target, _kind) in FIELD_MAP.items():
        out.setdefault(target.lower(), []).append(foreign)
    return out


def _shape_of(field: str) -> str:
    low = field.lower()
    for name, (_rx, owners) in SHAPES.items():
        if low in owners:
            return name
    return ""


def _shape_rate(values: List[Any], shape: str) -> float:
    if not values or not shape:
        return 0.0
    rx = SHAPES[shape][0]
    good = sum(1 for v in values if rx.search(str(v)))
    return good / len(values)


def suggest(rule_inputs, files: List[Tuple[str, bytes]]) -> Dict[str, Any]:
    events = load_events(files)
    db = LogDatabase(events)
    columns = db.columns
    samples: Dict[str, List[Any]] = {}
    for ev in events[:3000]:
        for k, v in (ev.get("values") or {}).items():
            bucket = samples.setdefault(k, [])
            if len(bucket) < 40 and v not in ("", None):
                bucket.append(v)
    reverse = _reverse()
    norm_cols: Dict[str, List[str]] = {}
    tail_cols: Dict[str, List[str]] = {}
    for low, name in columns.items():
        norm_cols.setdefault(_norm(name), []).append(name)
        tail_cols.setdefault(_norm(name.split(".")[-1]), []).append(name)
    wanted: List[str] = []
    for p in parse_inputs(rule_inputs):
        for f in _rule_fields(p.rule):
            if f and f not in wanted:
                wanted.append(f)
    rows = []
    mapping: Dict[str, str] = {}
    for field in wanted:
        low = field.lower()
        if low in columns:
            rows.append({"field": field, "present": True, "suggestions": []})
            continue
        cands: Dict[str, Dict[str, Any]] = {}

        def add(name, score, why):
            cur = cands.get(name)
            if cur is None or cur["score"] < score:
                cands[name] = {"name": name, "score": score, "why": why}

        for foreign in reverse.get(low, []):
            if foreign.lower() in columns:
                add(columns[foreign.lower()], 0.9, "Known name for this field in ECS, CIM or Sentinel")
        n = _norm(field)
        for name in norm_cols.get(n, []):
            add(name, 0.85, "Same name with different case or separators")
        for name in tail_cols.get(n, []):
            add(name, 0.75, "Same name at the end of a nested path")
        if len(n) >= 5:
            for nc, names in norm_cols.items():
                if nc != n and (nc.endswith(n) or n.endswith(nc)) and len(nc) >= 5:
                    for name in names:
                        add(name, 0.6, "Similar name")
        shape = _shape_of(field)
        if shape:
            for lowcol, name in columns.items():
                rate = _shape_rate(samples.get(lowcol, []), shape)
                if rate >= 0.8:
                    base = cands.get(name, {}).get("score", 0)
                    add(name, min(0.95, max(base + 0.1, 0.45 + rate * 0.1)), "Values look right for this field" if not base else cands[name]["why"] + ", values look right")
        best = sorted(cands.values(), key=lambda c: (-c["score"], "." not in c["name"]))[:4]
        for c in best:
            vals = samples.get(c["name"].lower(), [])
            c["sample"] = str(vals[0])[:120] if vals else ""
            c["score"] = round(c["score"], 2)
        if best and best[0]["score"] >= 0.6:
            mapping[field] = best[0]["name"]
        rows.append({"field": field, "present": False, "suggestions": best})
    return {
        "events": len(events),
        "log_fields": len(columns),
        "fields": rows,
        "mapping": mapping,
        "missing": sum(1 for r in rows if not r["present"]),
        "matched": len(mapping),
    }
