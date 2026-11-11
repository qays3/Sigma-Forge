from typing import Dict, List

from app.core.attack import load_attack, resolve_technique, split_attack_tags
from app.core.parsing import ParsedRule

LEVEL_WEIGHT = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def coverage(parsed_rules: List[ParsedRule]) -> Dict:
    attack = load_attack()
    known = attack.get("techniques", {})
    techniques: Dict[str, Dict] = {}
    tactic_counts: Dict[str, int] = {}
    total = 0
    tagged = 0
    unknown: Dict[str, int] = {}
    revoked_used: Dict[str, str] = {}
    sources: Dict[str, Dict] = {}

    for parsed in parsed_rules:
        rule = parsed.rule
        if rule is None or parsed.error:
            continue
        total += 1
        tids, tactics = split_attack_tags(rule.tags)
        if tids:
            tagged += 1
        for tactic in tactics:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        ref = {
            "key": parsed.key,
            "title": rule.title,
            "level": rule.level.name.lower() if rule.level else "",
            "id": str(rule.id) if rule.id else "",
        }
        label = logsource_label(rule.logsource)
        src = sources.setdefault(label, {"label": label, "product": rule.logsource.product or "", "category": rule.logsource.category or "",
                                         "service": rule.logsource.service or "", "rules": 0, "techniques": set(), "tactics": set(), "levels": {}})
        src["rules"] += 1
        lvl = ref["level"] or "none"
        src["levels"][lvl] = src["levels"].get(lvl, 0) + 1
        src["tactics"].update(tactics)
        for original in tids:
            src["techniques"].add(resolve_technique(original))
        for original in tids:
            tid = resolve_technique(original)
            if known and tid not in known:
                unknown[original] = unknown.get(original, 0) + 1
            elif tid != original:
                revoked_used[original] = tid
            entry = techniques.setdefault(tid, {"id": tid, "name": known.get(tid, {}).get("name", ""), "count": 0, "rules": []})
            entry["count"] += 1
            entry["rules"].append(ref)

    rollup: Dict[str, int] = {}
    for tid, entry in techniques.items():
        parent = tid.split(".")[0]
        rollup[parent] = rollup.get(parent, 0) + entry["count"]

    parents_total = sum(1 for t in known.values() if not t.get("parent"))
    covered_parents = sum(1 for tid in rollup if tid in known)
    tactic_cover = []
    for tactic in attack.get("tactics", []):
        ids = tactic["techniques"]
        hit = sum(1 for tid in ids if rollup.get(tid))
        tactic_cover.append({"short": tactic["short"], "name": tactic["name"], "id": tactic["id"], "total": len(ids), "covered": hit,
                             "rules": tactic_counts.get(tactic["short"], 0)})

    return {
        "attack_version": attack.get("version", ""),
        "rules_total": total,
        "rules_tagged": tagged,
        "techniques": techniques,
        "rollup": rollup,
        "tactics": tactic_cover,
        "tactic_tags": tactic_counts,
        "parents_total": parents_total,
        "parents_covered": covered_parents,
        "unknown": unknown,
        "revoked": revoked_used,
        "logsources": sorted(({**v, "techniques": sorted(v["techniques"]), "tactics": sorted(v["tactics"])} for v in sources.values()),
                             key=lambda x: (-x["rules"], x["label"])),
    }


def logsource_label(ls) -> str:
    parts = [ls.product, ls.category or ls.service] if ls is not None else []
    if ls is not None and ls.category and ls.service:
        parts.append(ls.service)
    label = " / ".join(str(p) for p in parts if p)
    return label or "any"


def gaps(parsed_rules: List[ParsedRule], limit: int = 40) -> Dict:
    from app.core import library

    cov = coverage(parsed_rules)
    index = library.load_index()
    if not index:
        return {"available": False, "techniques": [], "logsources": []}
    known = load_attack().get("techniques", {})
    covered = set(cov["techniques"])
    covered_parents = set(cov["rollup"])
    counts = library.technique_counts()
    missing = [tid for tid in counts if tid not in covered and tid in known]
    missing.sort(key=lambda t: (-counts[t], t))
    top = missing[:limit]
    picks = library.suggestions(top, per_technique=5)
    techniques = []
    for tid in top:
        tactics = [t for t in known[tid].get("tactics", [])] if known.get(tid) else []
        techniques.append({"id": tid, "name": known[tid]["name"], "library_rules": counts[tid], "parent_covered": tid.split(".")[0] in covered_parents,
                           "tactics": tactics, "suggestions": picks.get(tid, [])})
    wanted = set(missing)
    by_source: Dict[str, Dict] = {}
    for rule in index["rules"]:
        hit = [t for t in rule["techniques"] if t in wanted]
        if not hit:
            continue
        parts = [rule["product"], rule["category"] or rule["service"]]
        label = " / ".join(p for p in parts if p) or "any"
        entry = by_source.setdefault(label, {"label": label, "product": rule["product"], "category": rule["category"], "service": rule["service"],
                                             "rules": 0, "techniques": set()})
        entry["rules"] += 1
        entry["techniques"].update(hit)
    sources = sorted(({**v, "techniques": len(v["techniques"])} for v in by_source.values()), key=lambda x: (-x["techniques"], -x["rules"]))[:24]
    return {"available": True, "release": index.get("release", ""), "missing": len(missing), "techniques": techniques, "logsources": sources}


def navigator_layer(parsed_rules: List[ParsedRule], name: str, colors: List[str]) -> Dict:
    cov = coverage(parsed_rules)
    attack = load_attack()
    version = (attack.get("version") or "17").split(".")[0]
    gradient = colors if len(colors) >= 2 else ["#0A1120", "#B06CFF"]
    entries = []
    max_score = 1
    for tid, entry in sorted(cov["techniques"].items()):
        score = entry["count"]
        max_score = max(max_score, score)
        comment = "; ".join(r["title"] for r in entry["rules"][:25])
        tech = attack.get("techniques", {}).get(tid, {})
        tactics = tech.get("tactics") or [None]
        for tactic in tactics:
            item = {"techniqueID": tid, "score": score, "comment": comment, "enabled": True, "showSubtechniques": "." in tid}
            if tactic:
                item["tactic"] = tactic
            entries.append(item)
    return {
        "name": name,
        "versions": {"attack": version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Generated by Sigma Forge from {cov['rules_total']} Sigma rules",
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": gradient, "minValue": 0, "maxValue": max_score},
        "legendItems": [],
        "metadata": [{"name": "source", "value": "Sigma Forge"}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
