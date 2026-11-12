from typing import Any, Dict, List, Optional, Tuple

from app.core.attack import load_attack, resolve_technique, split_attack_tags

MAX_ITEMS = 1500
LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
HOST_KEYS = ("computer", "host.name", "hostname", "host", "devicename", "dest", "agent.hostname", "workstationname", "recipientaccountid")
USER_KEYS = ("user", "targetusername", "subjectusername", "user.name", "username", "accountname", "useridentity.arn", "userprincipalname")
SUMMARY_KEYS = (
    "commandline", "processcommandline", "scriptblocktext", "queryname", "targetobject", "targetfilename", "imageloaded",
    "destinationip", "servicename", "imagepath", "eventname", "image", "c-uri", "message",
)
GUID_KEYS = ("processguid",)
PARENT_GUID_KEYS = ("parentprocessguid",)
PID_KEYS = ("processid", "newprocessid")
PARENT_PID_KEYS = ("parentprocessid", "processid_parent", "creatorprocessid")
IMAGE_KEYS = ("image", "newprocessname", "folderpath", "process.executable")
CMD_KEYS = ("commandline", "processcommandline", "process.command_line")
PARENT_IMAGE_KEYS = ("parentimage", "parentprocessname", "initiatingprocessfolderpath", "process.parent.executable")
PARENT_CMD_KEYS = ("parentcommandline", "initiatingprocesscommandline", "process.parent.command_line")


def _first(values: Dict[str, Any], keys) -> str:
    for key in keys:
        value = values.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def tactic_order() -> List[Tuple[str, str]]:
    return [(t["short"], t["name"]) for t in load_attack().get("tactics", [])]


def rule_attack(rule) -> Tuple[List[str], List[str]]:
    if rule is None:
        return [], []
    tids, tactics = split_attack_tags(rule.tags)
    known = load_attack().get("techniques", {})
    tids = [resolve_technique(t) for t in tids]
    found = list(tactics)
    for tid in tids:
        for tac in (known.get(tid) or known.get(tid.split(".")[0]) or {}).get("tactics", []):
            if tac not in found:
                found.append(tac)
    order = [s for s, _ in tactic_order()]
    found.sort(key=lambda t: order.index(t) if t in order else 99)
    return tids, found


def build_timeline(events: List[Dict[str, Any]], hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    items = []
    seen = set()
    for hit in sorted(hits, key=lambda h: -LEVEL_RANK.get(h["level"] or "", 0)):
        for idx in hit["rows"]:
            ev = events[idx]
            v = ev.get("values", {})
            key = (idx, hit["key"])
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "ts": ev.get("ts") or "",
                "host": _first(v, HOST_KEYS) or ev["source"],
                "user": _first(v, USER_KEYS),
                "rule": hit["title"],
                "key": hit["key"],
                "level": hit["level"] or "",
                "tactics": hit["tactics"],
                "techniques": hit["techniques"],
                "summary": _first(v, SUMMARY_KEYS)[:220],
                "source": ev["source"],
                "event": idx,
            })
            if len(items) >= MAX_ITEMS:
                break
        if len(items) >= MAX_ITEMS:
            break
    items.sort(key=lambda i: (i["ts"] or "9999", i["host"], i["rule"]))
    names = dict(tactic_order())
    order = [s for s, _ in tactic_order()]
    hosts: Dict[str, Dict[str, Any]] = {}
    for it in items:
        h = hosts.setdefault(it["host"], {"host": it["host"], "first": it["ts"], "last": it["ts"], "hits": 0, "tactics": [], "rules": set(), "top": ""})
        h["hits"] += 1
        if it["ts"]:
            h["first"] = min(filter(None, [h["first"], it["ts"]]))
            h["last"] = max(filter(None, [h["last"], it["ts"]]))
        for tac in it["tactics"]:
            if tac not in h["tactics"]:
                h["tactics"].append(tac)
        h["rules"].add(it["rule"])
        if LEVEL_RANK.get(it["level"], 0) > LEVEL_RANK.get(h["top"], 0):
            h["top"] = it["level"]
    host_list = []
    for h in hosts.values():
        h["tactics"].sort(key=lambda t: order.index(t) if t in order else 99)
        host_list.append({**h, "rules": len(h["rules"]), "stage": names.get(h["tactics"][-1], h["tactics"][-1]) if h["tactics"] else ""})
    host_list.sort(key=lambda h: (-LEVEL_RANK.get(h["top"], 0), -len(h["tactics"]), -h["hits"]))
    used = sorted({t for it in items for t in it["tactics"]}, key=lambda t: order.index(t) if t in order else 99)
    return {
        "items": items,
        "truncated": len(items) >= MAX_ITEMS,
        "hosts": host_list,
        "tactics": [{"short": t, "name": names.get(t, t)} for t in used],
    }


class ProcessIndex:
    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
        self.by_guid: Dict[str, int] = {}
        self.by_pid: Dict[Tuple[str, str], int] = {}
        self.children: Dict[str, List[int]] = {}
        self.children_pid: Dict[Tuple[str, str], List[int]] = {}
        for idx, ev in enumerate(events):
            v = ev.get("values", {})
            image = _first(v, IMAGE_KEYS)
            if not image:
                continue
            host = _first(v, HOST_KEYS)
            guid = _first(v, GUID_KEYS).lower()
            pid = _norm_pid(_first(v, PID_KEYS))
            if guid and guid not in self.by_guid:
                self.by_guid[guid] = idx
            if pid and (host, pid) not in self.by_pid:
                self.by_pid[(host, pid)] = idx
            pguid = _first(v, PARENT_GUID_KEYS).lower()
            ppid = _norm_pid(_first(v, PARENT_PID_KEYS))
            if pguid:
                self.children.setdefault(pguid, []).append(idx)
            elif ppid:
                self.children_pid.setdefault((host, ppid), []).append(idx)

    def node(self, idx: int) -> Dict[str, Any]:
        ev = self.events[idx]
        v = ev.get("values", {})
        return {
            "image": _first(v, IMAGE_KEYS),
            "cmd": _first(v, CMD_KEYS)[:400],
            "pid": _first(v, PID_KEYS),
            "user": _first(v, USER_KEYS),
            "ts": ev.get("ts") or "",
            "event": idx,
        }

    def parent_of(self, idx: int) -> Optional[int]:
        v = self.events[idx].get("values", {})
        host = _first(v, HOST_KEYS)
        pguid = _first(v, PARENT_GUID_KEYS).lower()
        if pguid and pguid in self.by_guid and self.by_guid[pguid] != idx:
            return self.by_guid[pguid]
        ppid = _norm_pid(_first(v, PARENT_PID_KEYS))
        if ppid and (host, ppid) in self.by_pid and self.by_pid[(host, ppid)] != idx:
            return self.by_pid[(host, ppid)]
        return None

    def lineage(self, idx: int) -> Optional[Dict[str, Any]]:
        v = self.events[idx].get("values", {})
        if not _first(v, IMAGE_KEYS):
            return None
        ancestors = []
        seen = {idx}
        cur = idx
        for _ in range(10):
            parent = self.parent_of(cur)
            if parent is None or parent in seen:
                break
            ancestors.insert(0, self.node(parent))
            seen.add(parent)
            cur = parent
        if not ancestors:
            pimg = _first(v, PARENT_IMAGE_KEYS)
            if pimg:
                ancestors.append({"image": pimg, "cmd": _first(v, PARENT_CMD_KEYS)[:400], "pid": _first(v, PARENT_PID_KEYS), "user": "", "ts": "", "event": None, "guess": True})
        guid = _first(v, GUID_KEYS).lower()
        kids = list(self.children.get(guid, [])) if guid else []
        if not kids:
            pid = _norm_pid(_first(v, PID_KEYS))
            if pid:
                kids = list(self.children_pid.get((_first(v, HOST_KEYS), pid), []))
        kids = [k for k in kids if k != idx][:20]
        return {"ancestors": ancestors, "self": self.node(idx), "children": [self.node(k) for k in kids]}


def _norm_pid(value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return ""
    try:
        return str(int(value, 16)) if value.startswith("0x") else str(int(value))
    except ValueError:
        return value
