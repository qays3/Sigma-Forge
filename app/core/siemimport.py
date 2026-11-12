import json
import re
from typing import Any, Dict, List, Tuple

import yaml

from app.core.querygen import QueryError, convert_query

SPLUNK_SEV = {"1": "informational", "2": "informational", "3": "low", "4": "medium", "5": "high", "6": "critical"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
ELASTIC_LANG = {"kuery": "lucene", "lucene": "lucene", "eql": "eql", "esql": "esql"}
MAX_RULES = 500


def _level(value: Any) -> str:
    v = str(value or "").strip().lower()
    if v in SPLUNK_SEV:
        return SPLUNK_SEV[v]
    if v in ("info", "information", "informational"):
        return "informational"
    return v if v in LEVELS else "medium"


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return (s or "rule")[:80]


def parse_splunk(text: str) -> List[Dict[str, Any]]:
    out = []
    current = None
    key = None
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if key is not None:
            cont = stripped.endswith("\\")
            current[key] += " " + stripped.rstrip("\\").strip()
            if not cont:
                key = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^\[(.+)\]$", stripped)
        if m:
            current = {"_name": m.group(1).strip()}
            out.append(current)
            continue
        if current is None or "=" not in stripped:
            continue
        k, _, v = stripped.partition("=")
        k = k.strip()
        v = v.strip()
        cont = v.endswith("\\")
        current[k] = v.rstrip("\\").strip()
        if cont:
            key = k
    rules = []
    for st in out:
        q = st.get("search", "").strip()
        if not q or st["_name"].lower() == "default":
            continue
        techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", st.get("action.correlationsearch.annotations", "") + " " + st.get("description", ""))
        rules.append({
            "name": st["_name"],
            "query": q,
            "language": "splunk",
            "level": _level(st.get("alert.severity") or st.get("action.notable.param.severity")),
            "description": st.get("description", ""),
            "techniques": techniques,
            "disabled": str(st.get("disabled", "0")).strip() in ("1", "true"),
        })
    return rules


def _sentinel_one(obj: Dict[str, Any]) -> Dict[str, Any]:
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else obj
    q = props.get("query") or ""
    if not q:
        return {}
    techniques = list(props.get("techniques") or []) + list(props.get("relevantTechniques") or [])
    return {
        "name": props.get("displayName") or props.get("name") or "Sentinel rule",
        "query": q,
        "language": "kql",
        "level": _level(props.get("severity")),
        "description": props.get("description", ""),
        "techniques": [t for t in techniques if re.match(r"^T\d{4}", str(t))],
        "disabled": props.get("enabled") is False,
    }


def parse_sentinel(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            data = list(yaml.safe_load_all(stripped))
        except yaml.YAMLError as exc:
            raise ValueError(f"Not valid JSON or YAML: {exc}")
    items: List[Any] = []
    if isinstance(data, dict):
        if isinstance(data.get("resources"), list):
            items = data["resources"]
        elif isinstance(data.get("value"), list):
            items = data["value"]
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    out = []
    for it in items:
        if isinstance(it, dict):
            r = _sentinel_one(it)
            if r:
                out.append(r)
    return out


def parse_elastic(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    items: List[Any] = []
    if stripped.startswith("["):
        items = json.loads(stripped)
    else:
        for n, line in enumerate(stripped.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {n} is not valid JSON: {exc.msg}")
    out = []
    for it in items:
        if not isinstance(it, dict) or not it.get("query"):
            continue
        techniques = []
        for th in it.get("threat") or []:
            for t in th.get("technique") or []:
                techniques.append(t.get("id", ""))
                for s in t.get("subtechnique") or []:
                    techniques.append(s.get("id", ""))
        out.append({
            "name": it.get("name") or "Elastic rule",
            "query": it["query"],
            "language": ELASTIC_LANG.get(str(it.get("language") or "kuery").lower(), "lucene"),
            "level": _level(it.get("severity")),
            "description": it.get("description", ""),
            "techniques": [t for t in techniques if t],
            "disabled": it.get("enabled") is False,
        })
    return out


def detect_kind(name: str, text: str) -> str:
    low = name.lower()
    s = text.lstrip()
    if low.endswith(".conf") or re.search(r"^\[[^\]]+\]\s*$", s, re.M) and re.search(r"^\s*search\s*=", s, re.M):
        return "splunk"
    if low.endswith(".ndjson"):
        return "elastic"
    if '"rule_id"' in s or '"risk_score"' in s or ('"language"' in s and '"query"' in s and "displayName" not in s):
        return "elastic"
    if "displayName" in s or "alertRules" in s or "queryFrequency" in s or "relevantTechniques" in s:
        return "sentinel"
    return "splunk" if "search" in s else "sentinel"


def import_rules(files: List[Tuple[str, str]], kind: str = "auto", include_disabled: bool = False) -> Dict[str, Any]:
    found: List[Dict[str, Any]] = []
    errors = []
    for name, text in files:
        k = kind if kind in ("splunk", "sentinel", "elastic") else detect_kind(name, text)
        try:
            parsed = {"splunk": parse_splunk, "sentinel": parse_sentinel, "elastic": parse_elastic}[k](text)
        except (ValueError, TypeError) as exc:
            errors.append({"name": name, "error": str(exc)})
            continue
        for r in parsed:
            r["source"] = name
            r["kind"] = k
        found.extend(parsed)
    rules = []
    failed = []
    skipped = 0
    used = set()
    for r in found[:MAX_RULES]:
        if r.get("disabled") and not include_disabled:
            skipped += 1
            continue
        try:
            res = convert_query(r["query"][:20000], r["language"], r["name"][:300], r["level"])
        except QueryError as exc:
            failed.append({"name": r["name"], "source": r["source"], "kind": r["kind"], "error": str(exc), "query": r["query"][:400]})
            continue
        doc = yaml.safe_load(res["yaml"])
        if r.get("description"):
            doc["description"] = str(r["description"])[:1500].rstrip() + f" Imported from {r['kind'].title()} by Sigma Forge."
        tags = sorted({f"attack.{t.lower()}" for t in r.get("techniques", []) if re.match(r"^T\d{4}(\.\d{3})?$", str(t))})
        if tags:
            ordered = {}
            for key, value in doc.items():
                ordered[key] = value
                if key == "date":
                    ordered["tags"] = tags
            if "tags" not in ordered:
                ordered["tags"] = tags
            doc = ordered
        text_yaml = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=200)
        fname = _slug(r["name"]) + ".yml"
        base = fname[:-4]
        i = 2
        while fname in used:
            fname = f"{base}_{i}.yml"
            i += 1
        used.add(fname)
        rules.append({
            "name": fname,
            "title": r["name"],
            "content": text_yaml,
            "kind": r["kind"],
            "source": r["source"],
            "language": res["language_name"],
            "warnings": res.get("warnings", []),
            "error": res.get("error", ""),
            "level": doc.get("level", "medium"),
        })
    return {
        "rules": rules,
        "failed": failed,
        "errors": errors,
        "found": len(found),
        "converted": len(rules),
        "skipped": skipped,
        "truncated": len(found) > MAX_RULES,
    }
