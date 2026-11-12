from typing import Dict, List

from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from app.core.attack import split_attack_tags, technique_issues
from app.core.parsing import ParsedRule

OFFLINE_UNSAFE = {"attacktag", "d3_fendtag", "duplicate_filename", "filename_length"}


def _validator() -> SigmaValidator:
    chosen = [v for k, v in core_validators.items() if k not in OFFLINE_UNSAFE]
    return SigmaValidator(chosen)


def _logsource(rule) -> Dict[str, str]:
    ls = rule.logsource
    return {"product": ls.product or "", "category": ls.category or "", "service": ls.service or ""}


def _text(value) -> str:
    if value is None:
        return ""
    return str(value)


def _severity(issue) -> str:
    sev = getattr(issue, "severity", None)
    name = getattr(sev, "name", str(sev or "medium"))
    return name.lower()


def _issue_message(issue) -> str:
    return getattr(issue, "description", None) or type(issue).__name__


def describe(parsed: ParsedRule) -> Dict:
    base = {
        "key": parsed.key,
        "file": parsed.file,
        "index": parsed.index,
        "kind": parsed.kind,
        "error": parsed.error,
        "issues": [],
    }
    if parsed.kind == "correlation" and parsed.correlation is not None:
        return _describe_correlation(parsed, base)
    rule = parsed.rule
    if rule is None:
        base.update({"title": parsed.file, "id": "", "status": "", "level": "", "logsource": {"product": "", "category": "", "service": ""},
                     "tags": [], "techniques": [], "tactics": [], "description": "", "author": "", "date": "", "references": [],
                     "falsepositives": [], "detections": [], "conditions": []})
        return base

    techniques, tactics = split_attack_tags(rule.tags)
    base.update({
        "title": rule.title or parsed.file,
        "id": _text(rule.id),
        "status": rule.status.name.lower() if rule.status else "",
        "level": rule.level.name.lower() if rule.level else "",
        "logsource": _logsource(rule),
        "tags": [str(t) for t in rule.tags],
        "techniques": techniques,
        "tactics": tactics,
        "description": _text(rule.description),
        "author": _text(rule.author),
        "date": _text(rule.date),
        "references": [str(r) for r in rule.references or []],
        "falsepositives": [str(f) for f in rule.falsepositives or []],
        "detections": list(rule.detection.detections.keys()) if rule.detection else [],
        "conditions": [str(c) for c in rule.detection.condition] if rule.detection else [],
    })
    for message in technique_issues(techniques):
        base["issues"].append({"severity": "medium", "message": message})
    return base


def _describe_correlation(parsed: ParsedRule, base: Dict) -> Dict:
    corr = parsed.correlation
    techniques, tactics = split_attack_tags(corr.tags)
    refs = [str(r.reference) for r in corr.rules]
    cond = corr.condition
    op = getattr(getattr(cond, "op", None), "name", "").lower()
    ctype = getattr(corr.type, "name", str(corr.type)).lower()
    group = ", ".join(corr.group_by or []) or "none"
    timespan = getattr(corr.timespan, "spec", "")
    base.update({
        "title": corr.title or parsed.file,
        "id": _text(corr.id),
        "status": corr.status.name.lower() if corr.status else "",
        "level": corr.level.name.lower() if corr.level else "",
        "logsource": {"product": "correlation", "category": ctype, "service": ""},
        "tags": [str(t) for t in corr.tags],
        "techniques": techniques,
        "tactics": tactics,
        "description": _text(corr.description),
        "author": _text(corr.author),
        "date": _text(corr.date),
        "references": [str(r) for r in corr.references or []],
        "falsepositives": [str(f) for f in corr.falsepositives or []],
        "detections": refs,
        "conditions": [f"{ctype} {op} {getattr(cond, 'count', '')} within {timespan} grouped by {group}"],
    })
    return base


def analyze(parsed_rules: List[ParsedRule]) -> Dict:
    validator = _validator()
    rows = [describe(p) for p in parsed_rules]
    by_key = {r["key"]: r for r in rows}
    rule_map = {}

    for parsed in parsed_rules:
        if parsed.rule is None or parsed.error:
            continue
        rule_map[id(parsed.rule)] = parsed.key
        try:
            issues = validator.validate_rule(parsed.rule)
        except Exception as exc:
            issues = []
            by_key[parsed.key]["issues"].append({"severity": "low", "message": f"Validator failed: {exc}"})
        for issue in issues:
            by_key[parsed.key]["issues"].append({"severity": _severity(issue), "message": _issue_message(issue)})

    try:
        final_issues = validator.finalize()
    except Exception:
        final_issues = []
    for issue in final_issues:
        for rule in getattr(issue, "rules", []) or []:
            key = rule_map.get(id(rule))
            if key:
                by_key[key]["issues"].append({"severity": _severity(issue), "message": _issue_message(issue)})

    for r in rows:
        r["quality"] = quality(r)
    valid = [r for r in rows if not r["error"]]
    grades = _count([{"g": r["quality"]["grade"]} for r in valid], "g")
    summary = {
        "quality": round(sum(r["quality"]["score"] for r in valid) / len(valid)) if valid else 0,
        "grades": grades,
        "correlations": sum(1 for r in valid if r["kind"] == "correlation"),
        "files": len({r["file"] for r in rows}),
        "rules": len(rows),
        "valid": len(valid),
        "errors": len(rows) - len(valid),
        "with_issues": sum(1 for r in valid if r["issues"]),
        "levels": _count(valid, "level"),
        "statuses": _count(valid, "status"),
        "products": _count_nested(valid, "product"),
        "categories": _count_nested(valid, "category"),
    }
    return {"summary": summary, "rules": rows}


GENERIC_FP = {"", "unknown", "none", "n/a", "na", "-", "unlikely"}


def quality(r: Dict) -> Dict:
    if r.get("error"):
        return {"score": 0, "grade": "F", "checks": [{"id": "parse", "label": "Rule parses", "ok": False, "points": 0, "max": 100}]}
    import re

    title = r.get("title") or ""
    rid = r.get("id") or ""
    desc = r.get("description") or ""
    fps = [f for f in r.get("falsepositives") or [] if f.strip().lower() not in GENERIC_FP]
    issues = r.get("issues") or []
    serious = [i for i in issues if i.get("severity") in ("high", "critical", "medium")]
    conditions = " ".join(r.get("conditions") or []).lower()
    detections = r.get("detections") or []
    has_filter = "not" in conditions or any(str(d).startswith("filter") for d in detections) or r.get("kind") == "correlation"
    checks = [
        ("title", "Clear title (10 or more characters)", len(title) >= 10, 8),
        ("id", "Valid UUID id", bool(re.fullmatch(r"[0-9a-fA-F-]{36}", rid)), 6),
        ("description", "Description explains the detection (40 or more characters)", len(desc) >= 40, 12),
        ("references", "At least one reference", bool(r.get("references")), 10),
        ("author", "Author set", bool(r.get("author")), 4),
        ("date", "Date set", bool(r.get("date")), 4),
        ("level", "Level set", bool(r.get("level")), 6),
        ("status", "Status is test or stable", r.get("status") in ("test", "stable"), 6),
        ("attack", "Tagged with an ATT&CK technique", bool(r.get("techniques")), 14),
        ("falsepositives", "Real false positives listed (not Unknown)", bool(fps), 10),
        ("filters", "Filters out known noise", has_filter, 8),
        ("clean", "No medium or higher findings from the checks", not serious, 12),
    ]
    out = []
    score = 0
    for cid, label, ok, pts in checks:
        score += pts if ok else 0
        out.append({"id": cid, "label": label, "ok": bool(ok), "points": pts if ok else 0, "max": pts})
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "checks": out}


def _count(rows, field):
    out: Dict[str, int] = {}
    for r in rows:
        value = r.get(field) or "none"
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _count_nested(rows, field):
    out: Dict[str, int] = {}
    for r in rows:
        value = r["logsource"].get(field) or "none"
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
