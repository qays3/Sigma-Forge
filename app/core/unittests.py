import json
from typing import Any, Dict, List

from app.core.logtest import LogInputError, run_test

MAX_CASES = 100
MAX_RULES = 300


def _clean(cases: Any) -> Dict[str, List[Any]]:
    out = {"match": [], "nomatch": []}
    if not isinstance(cases, dict):
        return out
    for kind in out:
        items = cases.get(kind) or []
        if isinstance(items, dict):
            items = [items]
        for it in items[:MAX_CASES]:
            if isinstance(it, str):
                try:
                    it = json.loads(it)
                except ValueError:
                    continue
            if isinstance(it, dict) and it:
                out[kind].append(it)
    return out


def _label(event: Dict[str, Any]) -> str:
    for key in ("CommandLine", "Image", "TargetFilename", "QueryName", "TargetObject", "ScriptBlockText", "EventID"):
        if key in event:
            return f"{key}: {str(event[key])[:80]}"
    k = next(iter(event), "")
    return f"{k}: {str(event.get(k, ''))[:80]}" if k else "event"


def run_units(rule_inputs, tests: Dict[str, Any], mode: str = "off", options=None) -> Dict[str, Any]:
    by_name = {}
    for r in rule_inputs:
        by_name.setdefault(r.name, r)
    rows = []
    for name, raw in list(tests.items())[:MAX_RULES]:
        rule = by_name.get(name)
        cases = _clean(raw)
        if rule is None:
            continue
        total = len(cases["match"]) + len(cases["nomatch"])
        if not total:
            continue
        events = [json.loads(json.dumps(e)) for e in cases["match"] + cases["nomatch"]]
        blob = "\n".join(json.dumps(e, default=str) for e in events).encode()
        row = {"name": name, "title": "", "status": "ok", "message": "", "passed": 0, "failed": 0, "cases": []}
        try:
            res = run_test([rule], [("cases.jsonl", blob)], mode, max_samples=0, options=options, keep_rows=True)
        except LogInputError as exc:
            row.update(status="error", message=str(exc))
            rows.append(row)
            continue
        hit = set()
        titles = []
        errors = []
        for entry in res["results"]:
            titles.append(entry["title"])
            if entry["status"] in ("failed", "error"):
                errors.append(entry["message"])
            hit.update(entry.get("rows") or [])
        row["title"] = " / ".join(t for t in titles if t)
        if errors and not hit:
            row.update(status="error", message=errors[0])
        m = len(cases["match"])
        for i, ev in enumerate(cases["match"] + cases["nomatch"]):
            kind = "match" if i < m else "nomatch"
            fired = i in hit
            ok = fired if kind == "match" else not fired
            row["cases"].append({"kind": kind, "index": i if i < m else i - m, "ok": ok, "fired": fired, "label": _label(ev)})
            row["passed" if ok else "failed"] += 1
        rows.append(row)
    passed = sum(r["passed"] for r in rows)
    failed = sum(r["failed"] for r in rows)
    return {
        "rules": rows,
        "passed": passed,
        "failed": failed,
        "rules_ok": sum(1 for r in rows if not r["failed"] and r["status"] == "ok"),
        "rules_failed": sum(1 for r in rows if r["failed"] or r["status"] != "ok"),
    }
