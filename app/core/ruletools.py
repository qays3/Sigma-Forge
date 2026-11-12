import ipaddress
import json
import re
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR, ConditionValueExpression
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from app.core.parsing import parse_inputs

MAX_IOCS = 2000
FILE_EXT = ("exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "jse", "hta", "scr", "lnk", "docm", "xlsm", "iso", "img", "msi", "jar", "sys", "py", "sh", "elf", "zip", "rar", "7z")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
ORDER = ["title", "id", "related", "name", "status", "description", "references", "author", "date", "modified", "tags", "logsource",
         "detection", "correlation", "fields", "falsepositives", "level"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
MODIFIER_FIX = {
    "endwith": "endswith", "endswidth": "endswith", "ends_with": "endswith", "endswiths": "endswith", "endwiths": "endswith",
    "startwith": "startswith", "starts_with": "startswith", "startswiths": "startswith", "beginswith": "startswith",
    "contain": "contains", "contians": "contains", "containts": "contains", "include": "contains", "includes": "contains",
    "regex": "re", "regexp": "re", "containsall": "contains|all", "contains_all": "contains|all", "base64_offset": "base64offset",
    "wide": "utf16le", "cased": "cased", "all": "all",
}


def _dump(docs: List[Any]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False)


def _ordered(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: doc[k] for k in ORDER if k in doc}
    out.update({k: v for k, v in doc.items() if k not in out})
    return out


def refang(text: str) -> str:
    t = text
    for a, b in (("hxxps", "https"), ("hxxp", "http"), ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@")):
        t = re.sub(re.escape(a), b, t, flags=re.I)
    return t


def parse_iocs(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {"ipv4": [], "cidr": [], "ipv6": [], "domain": [], "url": [], "md5": [], "sha1": [], "sha256": [], "file": []}
    skipped: List[str] = []
    seen = set()
    for raw in re.split(r"[\s,;|\"'<>]+", refang(text or "")):
        tok = raw.strip().strip("()[]{}").rstrip(".")
        if not tok or tok in seen:
            continue
        seen.add(tok)
        low = tok.lower()
        if re.match(r"^https?://", low):
            found["url"].append(tok)
            continue
        if re.fullmatch(r"[a-f0-9]{32}", low):
            found["md5"].append(low)
            continue
        if re.fullmatch(r"[a-f0-9]{40}", low):
            found["sha1"].append(low)
            continue
        if re.fullmatch(r"[a-f0-9]{64}", low):
            found["sha256"].append(low)
            continue
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                found["cidr"].append(str(net))
                continue
            ip = ipaddress.ip_address(tok)
            found["ipv6" if ip.version == 6 else "ipv4"].append(str(ip))
            continue
        except ValueError:
            pass
        if "." in low and low.rsplit(".", 1)[-1] in FILE_EXT and not low.startswith("www."):
            found["file"].append(tok.replace("/", "\\").split("\\")[-1])
            continue
        if DOMAIN_RE.match(low):
            found["domain"].append(low)
            continue
        if len(tok) > 3:
            skipped.append(tok)
    for k in found:
        found[k] = found[k][:MAX_IOCS]
    found["skipped"] = skipped[:200]
    return found


def _rule(title: str, desc: str, logsource: Dict[str, str], detection: Dict[str, Any], tags: List[str], fps: List[str], level: str = "high") -> Dict[str, Any]:
    out = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": desc,
        "author": "Sigma Forge",
        "date": date.today().isoformat(),
    }
    if tags:
        out["tags"] = tags
    out.update({"logsource": logsource, "detection": detection, "falsepositives": fps, "level": level})
    return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:50] or "iocs"


def ioc_rules(text: str, name: str = "") -> Dict[str, Any]:
    iocs = parse_iocs(text)
    label = name.strip() or "IOC list"
    slug = _slug(label)
    rules: List[Tuple[str, Dict[str, Any]]] = []
    ips = iocs["ipv4"] + iocs["ipv6"]
    if ips or iocs["cidr"]:
        sel: Dict[str, Any] = {}
        cond = []
        if ips:
            sel["selection_ip"] = {"DestinationIp": ips}
            cond.append("selection_ip")
        if iocs["cidr"]:
            sel["selection_net"] = {"DestinationIp|cidr": iocs["cidr"]}
            cond.append("selection_net")
        sel["condition"] = " or ".join(cond) if len(cond) > 1 else cond[0]
        rules.append((f"{slug}_network.yml", _rule(f"Connection To {label} IP Addresses", f"Detects network connections to {len(ips) + len(iocs['cidr'])} IP addresses or ranges from {label}.",
                                                    {"category": "network_connection", "product": "windows"}, sel, ["attack.command-and-control", "attack.t1071"],
                                                    ["Shared hosting, CDN or cloud addresses in the list"])))
    if iocs["domain"]:
        doms = iocs["domain"]
        rules.append((f"{slug}_dns.yml", _rule(f"DNS Query For {label} Domains", f"Detects DNS lookups of {len(doms)} domains from {label}, including their sub domains.",
                                                {"category": "dns_query", "product": "windows"},
                                                {"selection_exact": {"QueryName": doms}, "selection_sub": {"QueryName|endswith": ["." + d for d in doms]}, "condition": "1 of selection_*"},
                                                ["attack.command-and-control", "attack.t1071.004"], ["Domains that were later cleaned or sold"])))
    if iocs["domain"] or iocs["url"]:
        det: Dict[str, Any] = {}
        cond = []
        if iocs["domain"]:
            det["selection_host"] = {"cs-host|endswith": iocs["domain"]}
            cond.append("selection_host")
        if iocs["url"]:
            det["selection_url"] = {"c-uri|contains": [re.sub(r"^https?://", "", u, flags=re.I) for u in iocs["url"]]}
            cond.append("selection_url")
        det["condition"] = " or ".join(cond) if len(cond) > 1 else cond[0]
        rules.append((f"{slug}_proxy.yml", _rule(f"Web Request To {label} Sites", f"Detects proxy requests to domains or URLs from {label}.",
                                                  {"category": "proxy"}, det, ["attack.command-and-control", "attack.t1071.001"], ["Security scanners that visit known bad sites"])))
    hashes = [f"MD5={h}" for h in iocs["md5"]] + [f"SHA1={h}" for h in iocs["sha1"]] + [f"SHA256={h}" for h in iocs["sha256"]]
    if hashes:
        rules.append((f"{slug}_hashes.yml", _rule(f"Process With {label} File Hash", f"Detects processes whose file hash is in {label}. Needs Sysmon with hashing turned on.",
                                                   {"category": "process_creation", "product": "windows"}, {"selection": {"Hashes|contains": hashes}, "condition": "selection"},
                                                   ["attack.execution", "attack.t1204"], ["None expected"], "critical")))
    if iocs["file"]:
        files = ["\\" + f for f in iocs["file"]]
        rules.append((f"{slug}_files.yml", _rule(f"File Names From {label}", f"Detects processes or new files with {len(files)} file names from {label}.",
                                                  {"category": "process_creation", "product": "windows"},
                                                  {"selection_image": {"Image|endswith": files}, "selection_original": {"OriginalFileName": iocs["file"]}, "condition": "1 of selection_*"},
                                                  ["attack.execution", "attack.t1204.002"], ["Real tools with the same file name"], "medium")))
    yara_text = ""
    strings = [(f"$d{i}", d) for i, d in enumerate(iocs["domain"][:300])] + [(f"$u{i}", re.sub(r"^https?://", "", u, flags=re.I)) for i, u in enumerate(iocs["url"][:300])] + [(f"$i{i}", ip) for i, ip in enumerate(iocs["ipv4"][:300])]
    hash_terms = [f'hash.md5(0, filesize) == "{h}"' for h in iocs["md5"][:500]] + [f'hash.sha1(0, filesize) == "{h}"' for h in iocs["sha1"][:500]] + [f'hash.sha256(0, filesize) == "{h}"' for h in iocs["sha256"][:500]]
    ident = re.sub(r"[^A-Za-z0-9_]", "_", label.title().replace(" ", "_"))[:40] or "IOC_List"
    if ident[0].isdigit():
        ident = "IOC_" + ident
    blocks = []
    if hash_terms:
        blocks.append(f'rule {ident}_Hashes\n{{\n    meta:\n        description = "Files whose hash is in {label}"\n        author = "Sigma Forge"\n        date = "{date.today().isoformat()}"\n    condition:\n        ' + "\n        or ".join(hash_terms) + "\n}")
    if strings:
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
        lines = "\n".join(f'        {k} = "{esc(v)}" ascii wide nocase' for k, v in strings)
        blocks.append(f'rule {ident}_Network_Strings\n{{\n    meta:\n        description = "Files that contain domains, URLs or IPs from {label}"\n        author = "Sigma Forge"\n        date = "{date.today().isoformat()}"\n    strings:\n{lines}\n    condition:\n        any of them\n}}')
    if blocks:
        yara_text = ('import "hash"\n\n' if hash_terms else "") + "\n\n".join(blocks) + "\n"
    counts = {k: len(v) for k, v in iocs.items() if k != "skipped"}
    return {
        "sigma": [{"name": n, "content": _dump([d])} for n, d in rules],
        "yara": {"name": f"{slug}.yar", "content": yara_text} if yara_text else None,
        "counts": counts,
        "total": sum(counts.values()),
        "skipped": iocs["skipped"],
    }


def _sval(v) -> str:
    if isinstance(v, SigmaString):
        parts = []
        for p in v.s:
            if p == SpecialChars.WILDCARD_MULTI:
                parts.append("*")
            elif p == SpecialChars.WILDCARD_SINGLE:
                parts.append("?")
            else:
                parts.append(str(p))
        return "".join(parts)
    return str(v)


def _leaf(field: Optional[str], value) -> Tuple[str, str, str]:
    name = field or "the event"
    if isinstance(value, SigmaExpansion):
        return name, "is one of", ", ".join(f'"{_sval(x)}"' for x in value.values)
    if isinstance(value, SigmaRegularExpression):
        return name, "matches the pattern", f'"{value.regexp.original if hasattr(value.regexp, "original") else value.regexp}"'
    if isinstance(value, SigmaCIDRExpression):
        return name, "is in the network", str(getattr(value, "cidr", value))
    if isinstance(value, SigmaCompareExpression):
        op = {"LT": "is less than", "LTE": "is at most", "GT": "is greater than", "GTE": "is at least"}.get(getattr(value.op, "name", ""), "compares to")
        return name, op, str(value.number.number if hasattr(value.number, "number") else value.number)
    if isinstance(value, SigmaNull):
        return name, "is empty", ""
    if isinstance(value, SigmaExists):
        return name, "exists" if value.exists else "does not exist", ""
    if isinstance(value, SigmaFieldReference):
        return name, "equals the field", value.field
    if isinstance(value, (SigmaNumber, SigmaBool)):
        return name, "is", str(value)
    s = _sval(value)
    if field is None:
        core = s.strip("*")
        return "the event", "contains", f'"{core}"'
    lead, tail = s.startswith("*"), s.endswith("*") and not s.endswith("\\*")
    core = s[1 if lead else 0: len(s) - (1 if tail else 0)]
    if "*" in core or "?" in core:
        return name, "looks like", f'"{s}"'
    if lead and tail:
        return name, "contains", f'"{core}"'
    if lead:
        return name, "ends with", f'"{core}"'
    if tail:
        return name, "starts with", f'"{core}"'
    return name, "is", f'"{core}"'


def _render(node, depth: int = 0) -> str:
    if isinstance(node, (ConditionFieldEqualsValueExpression, ConditionValueExpression)):
        f, op, v = _leaf(getattr(node, "field", None), node.value)
        return f"{f} {op} {v}".strip()
    if isinstance(node, ConditionNOT):
        inner = _render(node.args[0], depth + 1)
        return f"not ({inner})" if " and " in inner or " or " in inner else f"not {inner}"
    if isinstance(node, ConditionOR):
        leaves = [_leaf(getattr(a, "field", None), a.value) for a in node.args if isinstance(a, (ConditionFieldEqualsValueExpression, ConditionValueExpression))]
        if len(leaves) == len(node.args) and len({(f, op) for f, op, _ in leaves}) == 1:
            f, op, _ = leaves[0]
            vals = [v for _, _, v in leaves]
            shown = ", ".join(vals[:6]) + (f" and {len(vals) - 6} more" if len(vals) > 6 else "")
            return f"{f} {op} any of {shown}"
        text = " or ".join(_render(a, depth + 1) for a in node.args)
        return f"({text})" if depth else text
    if isinstance(node, ConditionAND):
        text = " and ".join(_render(a, depth + 1) for a in node.args)
        return f"({text})" if depth else text
    return str(node)


def explain_rule(rule) -> List[str]:
    out = []
    ls = rule.logsource
    where = " / ".join(x for x in (ls.product, ls.service, ls.category) if x) or "any log"
    out.append(f"Looks at {where} events.")
    for cond in rule.detection.parsed_condition:
        try:
            out.append("Fires when " + _render(cond.parsed) + ".")
        except Exception as exc:
            out.append(f"Could not explain the condition: {exc}")
    fps = [str(f) for f in (rule.falsepositives or []) if str(f).strip().lower() not in ("unknown", "none")]
    level = getattr(rule.level, "name", "").lower() if rule.level else ""
    if level:
        out.append(f"Raises a {level} alert.")
    if fps:
        out.append("May also fire on: " + "; ".join(fps[:3]) + ".")
    return out


def explain_correlation(corr) -> List[str]:
    kind = getattr(corr.type, "name", "").lower()
    refs = []
    for r in getattr(corr, "rules", []) or []:
        target = getattr(r, "rule", None)
        refs.append(getattr(target, "title", None) or str(getattr(r, "reference", r)))
    names = ", ".join(f'"{x}"' for x in refs) or "the referenced rules"
    span = getattr(corr.timespan, "seconds", 0) if getattr(corr, "timespan", None) else 0
    window = f"{span // 60} minutes" if span and span % 60 == 0 else f"{span} seconds"
    group = ", ".join(corr.group_by or []) or "nothing"
    cond = getattr(corr, "condition", None)
    count = ""
    if cond is not None:
        op = {"GTE": "at least", "GT": "more than", "LTE": "at most", "LT": "less than", "EQ": "exactly"}.get(getattr(cond.op, "name", ""), "")
        count = f"{op} {cond.count}"
        if getattr(cond, "fieldref", None):
            count += f" different {cond.fieldref} values"
    if kind == "event_count":
        main = f"Fires when {names} matches {count} events within {window}, grouped by {group}."
    elif kind == "value_count":
        main = f"Fires when {names} matches events with {count} within {window}, grouped by {group}."
    elif kind == "temporal":
        main = f"Fires when all of {names} match within {window}, grouped by {group}."
    elif kind == "temporal_ordered":
        main = f"Fires when {names} match in this order within {window}, grouped by {group}."
    else:
        main = f"Correlates {names} within {window}."
    return ["Looks at alerts from other rules.", main]


def explain_inputs(items) -> List[Dict[str, Any]]:
    out = []
    for p in parse_inputs(items):
        if p.error:
            out.append({"key": p.key, "title": "", "lines": [], "error": p.error})
            continue
        if p.kind == "correlation" and p.correlation is not None:
            out.append({"key": p.key, "title": p.correlation.title, "lines": explain_correlation(p.correlation), "error": ""})
        elif p.rule is not None:
            out.append({"key": p.key, "title": p.rule.title, "lines": explain_rule(p.rule), "error": ""})
    return out


def _fix_key(key: str) -> Tuple[str, Optional[str]]:
    parts = [p.strip() for p in str(key).split("|")]
    field, mods = parts[0], parts[1:]
    fixed = []
    changed = False
    for m in mods:
        low = m.lower()
        new = MODIFIER_FIX.get(low, low)
        if new != m:
            changed = True
        fixed.extend(new.split("|"))
    out = "|".join([field] + fixed)
    return out, (out if changed or out != key else None)


def autofix(content: str, name: str = "") -> Dict[str, Any]:
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        raise ValueError(f"The YAML is broken, fix it by hand first: {exc}")
    changes: List[str] = []
    out_docs = []
    for doc in docs:
        if not isinstance(doc, dict):
            out_docs.append(doc)
            continue
        is_rule = isinstance(doc.get("detection"), dict)
        is_corr = isinstance(doc.get("correlation"), dict)
        if not (is_rule or is_corr):
            out_docs.append(doc)
            continue
        title = str(doc.get("title") or "").strip()
        if not title:
            stem = re.sub(r"\.ya?ml$", "", name.split("/")[-1]) if name else "new rule"
            title = stem.replace("_", " ").title()
            doc["title"] = title
            changes.append("Added a title from the file name")
        try:
            uuid.UUID(str(doc.get("id", "")))
        except ValueError:
            doc["id"] = str(uuid.uuid4())
            changes.append("Added a new UUID id")
        status = str(doc.get("status") or "").lower()
        if status not in STATUSES:
            doc["status"] = "experimental"
            changes.append("Set status to experimental")
        elif status != doc.get("status"):
            doc["status"] = status
            changes.append("Made the status lower case")
        if not str(doc.get("description") or "").strip():
            doc["description"] = f"Detects {title[0].lower() + title[1:]}." if title else "Describe what this rule finds."
            changes.append("Added a description from the title")
        if not str(doc.get("author") or "").strip():
            doc["author"] = "Sigma Forge"
            changes.append("Added an author")
        for key in ("date", "modified"):
            val = doc.get(key)
            if key == "date" and not val:
                doc["date"] = date.today().isoformat()
                changes.append("Added today's date")
            elif isinstance(val, str) and re.fullmatch(r"\d{4}[/.]\d{2}[/.]\d{2}", val.strip()):
                doc[key] = re.sub(r"[/.]", "-", val.strip())
                changes.append(f"Changed the {key} format to YYYY-MM-DD")
            elif hasattr(val, "isoformat") and not isinstance(val, str):
                doc[key] = val.isoformat()
        for key in ("references", "falsepositives"):
            val = doc.get(key)
            if isinstance(val, str):
                doc[key] = [val]
                changes.append(f"Turned {key} into a list")
        if is_rule and not doc.get("falsepositives"):
            doc["falsepositives"] = ["Unknown"]
            changes.append("Added a false positives entry, replace it with real cases")
        tags = doc.get("tags")
        if isinstance(tags, list):
            new_tags = []
            for t in tags:
                t2 = str(t).strip().lower().replace(" ", "_")
                t2 = re.sub(r"^attack\.(t\d{4})(\.\d{3})?$", lambda m: "attack." + m.group(1) + (m.group(2) or ""), t2)
                t2 = t2.replace("attack.defense_evasion", "attack.defense-evasion").replace("attack.command_and_control", "attack.command-and-control")
                t2 = t2.replace("attack.privilege_escalation", "attack.privilege-escalation").replace("attack.credential_access", "attack.credential-access")
                t2 = t2.replace("attack.initial_access", "attack.initial-access").replace("attack.lateral_movement", "attack.lateral-movement")
                if t2 not in new_tags:
                    new_tags.append(t2)
            if new_tags != tags:
                doc["tags"] = new_tags
                changes.append("Cleaned the tags (lower case, no repeats)")
        if is_rule:
            level = str(doc.get("level") or "").lower()
            if level not in LEVELS:
                doc["level"] = "medium"
                changes.append("Set level to medium")
            elif level != doc.get("level"):
                doc["level"] = level
                changes.append("Made the level lower case")
            ls = doc.get("logsource")
            if isinstance(ls, dict):
                lowered = {k: (v.lower().strip() if isinstance(v, str) else v) for k, v in ls.items()}
                if lowered != ls:
                    doc["logsource"] = lowered
                    changes.append("Made the log source lower case")
            det = doc["detection"]
            new_det = {}
            for sel, body in det.items():
                if sel == "condition":
                    new_det[sel] = body
                    continue
                if isinstance(body, dict):
                    nb = {}
                    for k, v in body.items():
                        fixed, note = _fix_key(k)
                        if note and fixed != k:
                            changes.append(f"Fixed modifier {k} to {fixed}")
                        nb[fixed] = v
                    new_det[sel] = nb
                elif isinstance(body, list):
                    nl = []
                    for item in body:
                        if isinstance(item, dict):
                            ni = {}
                            for k, v in item.items():
                                fixed, note = _fix_key(k)
                                if note and fixed != k:
                                    changes.append(f"Fixed modifier {k} to {fixed}")
                                ni[fixed] = v
                            nl.append(ni)
                        else:
                            nl.append(item)
                    new_det[sel] = nl
                else:
                    new_det[sel] = body
            cond = new_det.get("condition")
            if isinstance(cond, str):
                c2 = re.sub(r"\s+", " ", cond).strip()
                c2 = re.sub(r"\b(AND|OR|NOT|ALL OF|1 OF)\b", lambda m: m.group(1).lower(), c2)
                if c2 != cond:
                    new_det["condition"] = c2
                    changes.append("Cleaned the condition text")
            if "condition" not in new_det:
                sels = [k for k in new_det]
                new_det["condition"] = sels[0] if len(sels) == 1 else "1 of " + (sels[0].split("_")[0] + "*" if sels else "selection")
                changes.append("Added a missing condition")
            doc["detection"] = new_det
        reordered = _ordered(doc)
        if list(reordered) != list(doc):
            changes.append("Put the fields in the usual Sigma order")
        out_docs.append(reordered)
    text = _dump(out_docs)
    return {"content": text, "changes": list(dict.fromkeys(changes)), "changed": text.strip() != content.strip()}


def _norm_doc(text: str) -> Optional[str]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    if not docs:
        return None
    doc = dict(docs[0])
    for k in ("modified", "date", "author"):
        doc.pop(k, None)
    return json.dumps(doc, sort_keys=True, default=str)


def library_updates(items) -> Dict[str, Any]:
    from app.core import library

    index = library.load_index()
    if not index:
        return {"available": False, "updates": [], "checked": 0}
    by_id = {r["id"]: r for r in index["rules"] if r.get("id")}
    updates = []
    checked = 0
    for item in items:
        name, content = item.name, item.content
        if name.startswith("sigmahq/"):
            rel = name[len("sigmahq/"):]
        else:
            rel = ""
        try:
            docs = [d for d in yaml.safe_load_all(content) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        if not docs:
            continue
        doc = docs[0]
        rid = str(doc.get("id") or "")
        entry = by_id.get(rid)
        if entry is None and rel:
            entry = next((r for r in index["rules"] if r["path"] == rel), None)
        if entry is None:
            continue
        checked += 1
        try:
            lib = library.read_rules([entry["path"]])[0]["content"]
        except Exception:
            continue
        if _norm_doc(lib) == _norm_doc(content):
            continue
        local_date = str(doc.get("modified") or doc.get("date") or "")
        updates.append({
            "name": name,
            "path": entry["path"],
            "title": entry["title"],
            "local_date": local_date,
            "library_date": entry.get("date", ""),
            "newer": bool(entry.get("date")) and str(entry.get("date")) > local_date,
            "library_content": lib,
        })
    updates.sort(key=lambda u: (not u["newer"], u["title"].lower()))
    return {"available": True, "updates": updates, "checked": checked, "release": index.get("release", "")}


ALLOW_MODS = {"equals": "", "contains": "contains", "startswith": "startswith", "endswith": "endswith"}


def clean_allowlist(entries) -> List[Dict[str, str]]:
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        field = str(e.get("field") or "").strip()
        value = str(e.get("value") or "")
        if not field or not value or not re.fullmatch(r"[A-Za-z0-9_.@\-]{1,120}", field):
            continue
        mod = str(e.get("match") or "equals").lower()
        if mod not in ALLOW_MODS:
            mod = "equals"
        scope = str(e.get("scope") or "").strip().lower()[:60]
        out.append({"field": field, "value": value[:500], "match": mod, "scope": scope})
    return out[:500]


def _scope_ok(scope: str, ls: Dict[str, Any]) -> bool:
    if not scope:
        return True
    vals = {str(v).lower() for v in (ls or {}).values() if v}
    return all(part in vals for part in scope.replace("/", " ").split())


def apply_allowlist(items, entries):
    entries = clean_allowlist(entries)
    if not entries:
        return items
    from app.schemas import RuleInput

    out = []
    for item in items:
        try:
            docs = list(yaml.safe_load_all(item.content))
        except yaml.YAMLError:
            out.append(item)
            continue
        changed = False
        for doc in docs:
            if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
                continue
            ls = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
            use = [e for e in entries if _scope_ok(e["scope"], ls)]
            if not use:
                continue
            groups: Dict[str, List[str]] = {}
            for e in use:
                key = e["field"] + (f"|{ALLOW_MODS[e['match']]}" if ALLOW_MODS[e["match"]] else "")
                groups.setdefault(key, []).append(e["value"])
            det = doc["detection"]
            cond = det.get("condition", "selection")
            names = []
            new_det = {k: v for k, v in det.items() if k != "condition"}
            for i, (key, vals) in enumerate(groups.items(), 1):
                nm = f"filter_sf_allow_{i}"
                while nm in new_det:
                    nm += "_x"
                new_det[nm] = {key: vals if len(vals) > 1 else vals[0]}
                names.append(nm)
            tail = " and ".join(f"not {n}" for n in names)
            new_det["condition"] = [f"({c}) and {tail}" for c in cond] if isinstance(cond, list) else f"({cond}) and {tail}"
            doc["detection"] = new_det
            changed = True
        out.append(RuleInput(name=item.name, content=_dump(docs)) if changed else item)
    return out
