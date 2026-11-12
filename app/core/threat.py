import json
from functools import lru_cache
from typing import Dict, List, Optional

from app.config import DATA_DIR
from app.core.attack import load_attack, resolve_technique
from app.core.coverage import coverage, logsource_label
from app.core.parsing import ParsedRule

GROUPS_FILE = DATA_DIR / "attack" / "groups.json"
ATOMICS_FILE = DATA_DIR / "atomic" / "atomics.json"


@lru_cache(maxsize=1)
def load_groups() -> List[Dict]:
    if not GROUPS_FILE.exists():
        return []
    return json.loads(GROUPS_FILE.read_text(encoding="utf-8")).get("groups", [])


@lru_cache(maxsize=1)
def load_atomics() -> Dict[str, List[Dict]]:
    if not ATOMICS_FILE.exists():
        return {}
    raw = json.loads(ATOMICS_FILE.read_text(encoding="utf-8")).get("techniques", {})
    out: Dict[str, List[Dict]] = {}
    for tid, tests in raw.items():
        new = resolve_technique(tid)
        out.setdefault(new, [])
        seen = {t["guid"] for t in out[new]}
        out[new].extend(t for t in tests if t["guid"] not in seen)
    return out


def groups_index() -> List[Dict]:
    return [{"id": g["id"], "name": g["name"], "aliases": g["aliases"], "techniques": len(g["techniques"])} for g in load_groups()]


def atomic_tests(tid: str) -> Dict:
    data = load_atomics()
    tests = data.get(tid, [])
    subs = []
    if "." not in tid:
        for key, value in data.items():
            if key.startswith(tid + "."):
                subs.append({"id": key, "count": len(value)})
    return {
        "technique": tid,
        "tests": tests,
        "subs": sorted(subs, key=lambda s: s["id"]),
        "url": f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{tid}/{tid}.md",
    }


def atomic_counts() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for tid, tests in load_atomics().items():
        out[tid] = out.get(tid, 0) + len(tests)
        if "." in tid:
            parent = tid.split(".")[0]
            out[parent] = out.get(parent, 0) + len(tests)
    return out


def group_coverage(cov: Dict, gid: str) -> Optional[Dict]:
    group = next((g for g in load_groups() if g["id"].lower() == gid.lower() or g["name"].lower() == gid.lower()), None)
    if group is None:
        return None
    known = load_attack().get("techniques", {})
    covered = set(cov["techniques"])
    parents_with_rules = set(cov["rollup"])
    rows = []
    for tid in group["techniques"]:
        info = known.get(tid, {})
        parent = tid.split(".")[0]
        if tid in covered:
            state = "covered"
        elif "." in tid and parent in covered:
            state = "partial"
        elif "." not in tid and tid in parents_with_rules:
            state = "partial"
        else:
            state = "missing"
        rows.append({"id": tid, "name": info.get("name", tid), "tactics": info.get("tactics", []), "state": state, "parent": parent})
    n = len(rows)
    full = sum(1 for r in rows if r["state"] == "covered")
    part = sum(1 for r in rows if r["state"] == "partial")
    parents: Dict[str, str] = {}
    rank = {"covered": 2, "partial": 1, "missing": 0}
    for r in rows:
        cur = parents.get(r["parent"])
        if cur is None or rank[r["state"]] > rank[cur]:
            parents[r["parent"]] = r["state"]
    return {
        "id": group["id"],
        "name": group["name"],
        "aliases": group["aliases"],
        "description": group["description"],
        "url": group["url"],
        "total": n,
        "covered": full,
        "partial": part,
        "missing": n - full - part,
        "percent": round((full + part * 0.5) * 100 / n) if n else 0,
        "techniques": sorted(rows, key=lambda r: ({"missing": 0, "partial": 1, "covered": 2}[r["state"]], r["id"])),
        "parents": parents,
    }


def filter_ready(parsed_rules: List[ParsedRule], collected: List[str]) -> List[ParsedRule]:
    wanted = set(collected)
    out = []
    for p in parsed_rules:
        if p.rule is None or p.error:
            continue
        label = logsource_label(p.rule.logsource)
        if label == "any" or label in wanted:
            out.append(p)
    return out


def readiness(parsed_rules: List[ParsedRule], collected: List[str]) -> Dict:
    full = coverage(parsed_rules)
    ready_rules = filter_ready(parsed_rules, collected)
    ready = coverage(ready_rules)
    known = load_attack().get("techniques", {})
    blind = sorted(set(full["rollup"]) - set(ready["rollup"]))
    return {
        "ready": ready,
        "summary": {
            "collected": len(collected),
            "sources_total": len(full["logsources"]),
            "rules_total": full["rules_total"],
            "rules_ready": ready["rules_total"],
            "techniques_on_paper": full["parents_covered"],
            "techniques_ready": ready["parents_covered"],
            "parents_total": full["parents_total"],
            "blind": [{"id": t, "name": known.get(t, {}).get("name", t)} for t in blind[:60]],
            "blind_count": len(blind),
            "missing_sources": [s["label"] for s in full["logsources"] if s["label"] not in set(collected) and s["label"] != "any"],
        },
    }
