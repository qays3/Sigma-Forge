import argparse
import json
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "attack" / "attack.json"
GROUPS_OUTPUT = OUTPUT.with_name("groups.json")

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None, ""


def load_bundle(source):
    if source.startswith("http://") or source.startswith("https://"):
        print(f"Downloading {source}")
        with urllib.request.urlopen(source, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    print(f"Reading {source}")
    return json.loads(Path(source).read_text(encoding="utf-8"))


def build(bundle):
    objects = bundle.get("objects", [])
    version = ""
    tactics = {}
    techniques = {}

    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "x-mitre-tactic":
            tid, url = external_id(obj)
            short = obj.get("x_mitre_shortname")
            if tid and short:
                tactics[short] = {"id": tid, "short": short, "name": obj.get("name", short), "url": url, "techniques": []}

    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if "enterprise-attack" not in obj.get("x_mitre_domains", ["enterprise-attack"]):
            continue
        tid, url = external_id(obj)
        if not tid:
            continue
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {
            "id": tid,
            "name": obj.get("name", tid),
            "url": url,
            "tactics": phases,
            "parent": tid.split(".")[0] if "." in tid else None,
            "subs": [],
        }

    stix_to_id = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            tid, _ = external_id(obj)
            if tid:
                stix_to_id[obj["id"]] = tid
    revoked = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            old = stix_to_id.get(obj.get("source_ref"))
            new = stix_to_id.get(obj.get("target_ref"))
            if old and new and old not in techniques:
                revoked[old] = new

    for tid, tech in techniques.items():
        parent = tech["parent"]
        if parent and parent in techniques:
            techniques[parent]["subs"].append(tid)

    for tech in techniques.values():
        tech["subs"].sort()
        if tech["parent"]:
            continue
        for phase in tech["tactics"]:
            if phase in tactics:
                tactics[phase]["techniques"].append(tech["id"])

    for tactic in tactics.values():
        tactic["techniques"].sort(key=lambda t: techniques[t]["name"].lower())

    ordered = [tactics[s] for s in TACTIC_ORDER if s in tactics]
    ordered += [t for s, t in tactics.items() if s not in TACTIC_ORDER]
    return {"version": version, "tactics": ordered, "techniques": techniques, "revoked": dict(sorted(revoked.items()))}


def first_sentence(text, limit=260):
    import re

    text = " ".join((text or "").split())
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s*\(Citation:[^)]*\)", "", text)
    end = text.find(". ")
    if 0 < end < limit:
        return text[: end + 1]
    return text[:limit].rstrip() + ("..." if len(text) > limit else "")


def build_groups(bundle, techniques):
    objects = bundle.get("objects", [])
    stix_tech = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            tid, _ = external_id(obj)
            if tid and tid in techniques:
                stix_tech[obj["id"]] = tid
    groups = {}
    for obj in objects:
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        gid, url = external_id(obj)
        if not gid:
            continue
        aliases = [a for a in obj.get("aliases", []) if a != obj.get("name")]
        groups[obj["id"]] = {"id": gid, "name": obj.get("name", gid), "aliases": aliases[:8], "url": url,
                             "description": first_sentence(obj.get("description", "")), "techniques": set()}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        group = groups.get(obj.get("source_ref"))
        tid = stix_tech.get(obj.get("target_ref"))
        if group is not None and tid:
            group["techniques"].add(tid)
    out = []
    for g in groups.values():
        if not g["techniques"]:
            continue
        g["techniques"] = sorted(g["techniques"])
        out.append(g)
    out.sort(key=lambda g: g["name"].lower())
    return out


def main():
    parser = argparse.ArgumentParser(description="Build the compact MITRE ATT&CK Enterprise data file used by Sigma Forge")
    parser.add_argument("--source", default=SOURCE_URL, help="URL or local path of enterprise-attack.json (STIX 2.1 bundle)")
    parser.add_argument("--output", default=str(OUTPUT), help="Where to write the compact attack.json")
    args = parser.parse_args()

    try:
        bundle = load_bundle(args.source)
    except Exception as exc:
        print(f"Failed to load ATT&CK data: {exc}", file=sys.stderr)
        return 1

    data = build(bundle)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    groups = build_groups(bundle, data["techniques"])
    out.with_name("groups.json").write_text(json.dumps({"version": data["version"], "groups": groups}, separators=(",", ":")), encoding="utf-8")
    print(f"{len(groups)} threat groups -> {out.with_name('groups.json')}")
    print(f"ATT&CK v{data['version']}: {len(data['tactics'])} tactics, {len(data['techniques'])} techniques, {len(data['revoked'])} revoked mappings -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
