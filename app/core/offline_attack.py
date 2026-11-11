from functools import lru_cache
from typing import Any, Dict

from app.core.attack import load_attack

LEGACY_TACTICS = (("TA0005", "defense-evasion"),)


class _Tactics(dict):
    def items(self):
        yield from super().items()
        yield from LEGACY_TACTICS


@lru_cache(maxsize=1)
def attack_data() -> Dict[str, Any]:
    attack = load_attack()
    tactics = _Tactics((t["id"], t["short"]) for t in attack.get("tactics", []))
    techniques = {tid: t["name"] for tid, t in attack.get("techniques", {}).items()}
    mapping = {tid: list(t.get("tactics", [])) for tid, t in attack.get("techniques", {}).items()}
    for old, new in attack.get("revoked", {}).items():
        if new in techniques and old not in techniques:
            techniques[old] = techniques[new]
            mapping[old] = mapping.get(new, [])
    return {
        "mitre_attack_version": attack.get("version") or "unknown",
        "mitre_attack_tactics": tactics,
        "mitre_attack_techniques": techniques,
        "mitre_attack_techniques_tactics_mapping": mapping,
        "mitre_attack_intrusion_sets": {},
        "mitre_attack_software": {},
        "mitre_attack_datasources": {},
        "mitre_attack_mitigations": {},
    }


def install() -> None:
    if not load_attack().get("techniques"):
        return
    try:
        from sigma.data import mitre_attack
    except ImportError:
        return
    mitre_attack._get_cached_data = attack_data
