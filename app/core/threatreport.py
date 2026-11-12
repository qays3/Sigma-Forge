import re
from typing import Any, Dict, List

from app.core.attack import load_attack, resolve_technique, split_attack_tags
from app.core.parsing import parse_inputs
from app.core.ruletools import parse_iocs

TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
MAX_TEXT = 1_000_000


def _names() -> List[tuple]:
    known = load_attack().get("techniques", {})
    out = []
    for tid, t in known.items():
        name = t.get("name", "")
        if len(name) >= 10:
            out.append((tid, name, re.compile(r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])", re.I)))
    return out


def analyze(text: str, rule_inputs, per_technique: int = 4) -> Dict[str, Any]:
    text = (text or "")[:MAX_TEXT]
    known = load_attack().get("techniques", {})
    found: Dict[str, Dict[str, Any]] = {}
    for m in TID.finditer(text):
        raw = m.group(0).upper()
        tid = resolve_technique(raw) or raw
        slot = found.setdefault(tid, {"id": tid, "how": "id", "count": 0, "context": ""})
        slot["count"] += 1
        if not slot["context"]:
            a, b = max(0, m.start() - 80), min(len(text), m.end() + 80)
            slot["context"] = re.sub(r"\s+", " ", text[a:b]).strip()
    by_id = {(known.get(t) or {}).get("name", "").lower() for t in found}
    for tid, name, rx in _names():
        if name.lower() in by_id and tid not in found:
            continue
        m = rx.search(text)
        if not m:
            continue
        slot = found.setdefault(tid, {"id": tid, "how": "name", "count": 0, "context": ""})
        slot["count"] += len(rx.findall(text))
        if not slot["context"]:
            a, b = max(0, m.start() - 80), min(len(text), m.end() + 80)
            slot["context"] = re.sub(r"\s+", " ", text[a:b]).strip()
    have: Dict[str, List[Dict[str, Any]]] = {}
    for p in parse_inputs(rule_inputs or []):
        rule = p.rule
        if rule is None or p.error:
            continue
        tids, _ = split_attack_tags(rule.tags)
        for t in tids:
            have.setdefault(t.upper(), []).append({"title": rule.title, "key": p.key, "file": p.file})
    try:
        from app.core.library import suggestions

        sugg = suggestions(list(found.keys()), per_technique)
    except Exception:
        sugg = {}
    rows = []
    for tid, slot in found.items():
        info = known.get(tid) or {}
        exact = have.get(tid, [])
        related = []
        if not exact:
            parent = tid.split(".")[0]
            for t, rules in have.items():
                if t == parent or t.startswith(parent + "."):
                    related.extend(rules)
        state = "covered" if exact else ("partial" if related else "gap")
        rows.append({
            "id": tid,
            "name": info.get("name", ""),
            "tactics": info.get("tactics", []),
            "url": info.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"),
            "found_by": slot["how"],
            "mentions": slot["count"],
            "context": slot["context"][:220],
            "state": state,
            "rules": (exact or related)[:6],
            "library": sugg.get(tid, []),
            "known": bool(info),
        })
    order = {"gap": 0, "partial": 1, "covered": 2}
    rows.sort(key=lambda r: (order[r["state"]], -r["mentions"], r["id"]))
    iocs = parse_iocs(text)
    skipped = iocs.pop("skipped", [])
    ioc_total = sum(len(v) for v in iocs.values())
    total = len(rows)
    covered = sum(1 for r in rows if r["state"] == "covered")
    return {
        "techniques": rows,
        "iocs": iocs,
        "ioc_total": ioc_total,
        "summary": {
            "techniques": total,
            "covered": covered,
            "partial": sum(1 for r in rows if r["state"] == "partial"),
            "gap": sum(1 for r in rows if r["state"] == "gap"),
            "score": round(covered * 100 / total) if total else 0,
            "library_ready": sum(1 for r in rows if r["library"]),
        },
        "unparsed": len(skipped),
    }
