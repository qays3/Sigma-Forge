import json
import re
from functools import lru_cache
from typing import Dict, List, Tuple

from app.config import ATTACK_FILE

TECHNIQUE_TAG = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)
OTHER_ID_TAG = re.compile(r"^[gs]\d{4}$", re.IGNORECASE)


@lru_cache(maxsize=1)
def load_attack() -> Dict:
    if not ATTACK_FILE.exists():
        return {"version": "", "tactics": [], "techniques": {}}
    return json.loads(ATTACK_FILE.read_text(encoding="utf-8"))


def attack_available() -> bool:
    return bool(load_attack().get("techniques"))


def split_attack_tags(tags) -> Tuple[List[str], List[str]]:
    techniques: List[str] = []
    tactics: List[str] = []
    for tag in tags or []:
        if str(getattr(tag, "namespace", "")).lower() != "attack":
            continue
        name = str(getattr(tag, "name", "")).strip()
        if TECHNIQUE_TAG.match(name):
            tid = name.upper()
            if tid not in techniques:
                techniques.append(tid)
        elif OTHER_ID_TAG.match(name):
            continue
        else:
            short = name.lower().replace("_", "-")
            if short not in tactics:
                tactics.append(short)
    return techniques, tactics


def technique_name(tid: str) -> str:
    tech = load_attack().get("techniques", {}).get(tid)
    return tech["name"] if tech else ""


def replacement(tid: str) -> str:
    return load_attack().get("revoked", {}).get(tid, "")


def resolve_technique(tid: str) -> str:
    known = load_attack().get("techniques", {})
    if tid in known:
        return tid
    return replacement(tid) or tid


def technique_issues(techniques: List[str]) -> List[str]:
    known = load_attack().get("techniques", {})
    if not known:
        return []
    messages = []
    for tid in techniques:
        if tid in known:
            continue
        new = replacement(tid)
        if new:
            messages.append(f"ATT&CK technique {tid} was revoked. It is now {new} ({technique_name(new)})")
        else:
            messages.append(f"ATT&CK technique {tid} is not in the local ATT&CK data (unknown or deprecated)")
    return messages
