import io
import json
import shutil
import threading
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional

import yaml

from app.config import SIGMAHQ_DIR, SIGMAHQ_URL
from app.core.attack import resolve_technique

INDEX_FILE = "index.json"
RULES_DIR = "rules"
MAX_ZIP_BYTES = 80 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
LEVELS = ["informational", "low", "medium", "high", "critical"]

_lock = threading.Lock()
_state = {"running": False, "error": "", "started": 0.0}
_cache: Dict[str, object] = {"mtime": None, "index": None}


class LibraryError(ValueError):
    pass


def _root() -> Path:
    return Path(SIGMAHQ_DIR)


def _index_path() -> Path:
    return _root() / INDEX_FILE


def load_index() -> Optional[Dict]:
    path = _index_path()
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    if _cache["mtime"] != mtime:
        _cache["index"] = json.loads(path.read_text(encoding="utf-8"))
        _cache["mtime"] = mtime
    return _cache["index"]


def status() -> Dict:
    index = load_index()
    base = {"syncing": _state["running"], "error": _state["error"], "source": SIGMAHQ_URL}
    if not index:
        return {**base, "available": False, "rules": 0, "release": "", "synced_at": ""}
    rules = index["rules"]
    return {
        **base,
        "available": True,
        "rules": len(rules),
        "release": index.get("release", ""),
        "synced_at": index.get("synced_at", ""),
        "groups": index.get("groups", {}),
        "products": _facet(rules, "product"),
        "levels": {lvl: sum(1 for r in rules if r["level"] == lvl) for lvl in LEVELS},
        "techniques": len({t for r in rules for t in r["techniques"]}),
    }


def _facet(rules: List[Dict], key: str, top: int = 40) -> List[Dict]:
    counts: Dict[str, int] = {}
    for rule in rules:
        value = rule.get(key) or ""
        if value:
            counts[value] = counts.get(value, 0) + 1
    return [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])[:top]]


def _safe_member(name: str) -> Optional[str]:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return None
    if path.suffix.lower() not in (".yml", ".yaml"):
        return None
    parts = list(path.parts)
    for i, part in enumerate(parts):
        if part.startswith("rules"):
            return "/".join(parts[i:])
    return None


def _tags(doc: Dict) -> Dict[str, List[str]]:
    techniques: List[str] = []
    tactics: List[str] = []
    for tag in doc.get("tags") or []:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        name = tag[7:]
        if name[:1] == "t" and name[1:5].isdigit():
            tid = resolve_technique(name.upper())
            if tid not in techniques:
                techniques.append(tid)
        elif name[:1] in ("g", "s") and name[1:5].isdigit():
            continue
        elif name not in tactics:
            tactics.append(name.replace("_", "-"))
    return {"techniques": techniques, "tactics": tactics}


def _entry(path: str, text: str) -> Optional[Dict]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    if not docs:
        return None
    doc = next((d for d in docs if "detection" in d or "correlation" in d), docs[0])
    ls = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    tags = _tags(doc)
    description = str(doc.get("description") or "").strip().replace("\n", " ")
    return {
        "path": path,
        "group": path.split("/")[0],
        "title": str(doc.get("title") or PurePosixPath(path).stem),
        "id": str(doc.get("id") or ""),
        "level": str(doc.get("level") or "").lower(),
        "status": str(doc.get("status") or "").lower(),
        "product": str(ls.get("product") or "").lower(),
        "category": str(ls.get("category") or "").lower(),
        "service": str(ls.get("service") or "").lower(),
        "correlation": "correlation" in doc,
        "techniques": tags["techniques"],
        "tactics": tags["tactics"],
        "description": description[:280],
        "author": str(doc.get("author") or "")[:120],
        "date": str(doc.get("modified") or doc.get("date") or ""),
    }


def install_zip(data: bytes, release: str = "") -> Dict:
    if len(data) > MAX_ZIP_BYTES:
        raise LibraryError("The archive is too large")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise LibraryError("The file is not a zip archive")
    root = _root()
    staging = root.with_name(root.name + ".new")
    if staging.exists():
        shutil.rmtree(staging)
    (staging / RULES_DIR).mkdir(parents=True)
    rules = []
    groups: Dict[str, int] = {}
    for info in archive.infolist():
        if info.is_dir() or info.file_size > MAX_FILE_BYTES:
            continue
        rel = _safe_member(info.filename)
        if rel is None:
            continue
        raw = archive.read(info)
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
        entry = _entry(rel, text)
        if entry is None:
            continue
        dest = staging / RULES_DIR / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        rules.append(entry)
        groups[entry["group"]] = groups.get(entry["group"], 0) + 1
    if not rules:
        shutil.rmtree(staging, ignore_errors=True)
        raise LibraryError("No Sigma rules found in the archive")
    rules.sort(key=lambda r: r["path"])
    index = {"release": release, "synced_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "groups": groups, "rules": rules}
    (staging / INDEX_FILE).write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    old = root.with_name(root.name + ".old")
    if old.exists():
        shutil.rmtree(old)
    if root.exists():
        root.rename(old)
    staging.rename(root)
    shutil.rmtree(old, ignore_errors=True)
    _cache["mtime"] = None
    return status()


class _Recorder(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.seen: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.seen.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _release_from(urls: List[str]) -> str:
    for url in urls:
        parts = url.split("?")[0].split("/")
        if "download" in parts:
            i = parts.index("download")
            if i + 2 < len(parts) and parts[i + 1] != "latest":
                return parts[i + 1]
    return ""


def _download() -> None:
    try:
        recorder = _Recorder()
        opener = urllib.request.build_opener(recorder)
        request = urllib.request.Request(SIGMAHQ_URL, headers={"User-Agent": "sigma-forge"})
        with opener.open(request, timeout=120) as response:
            data = response.read(MAX_ZIP_BYTES + 1)
        install_zip(data, _release_from(recorder.seen))
        _state["error"] = ""
    except LibraryError as exc:
        _state["error"] = str(exc)
    except Exception as exc:
        _state["error"] = f"Download failed: {exc}. You can download sigma_all_rules.zip yourself and upload it."
    finally:
        _state["running"] = False


def start_sync() -> Dict:
    with _lock:
        if not _state["running"]:
            _state.update(running=True, error="", started=time.time())
            threading.Thread(target=_download, daemon=True).start()
    return status()


def _match(rule: Dict, q: str) -> bool:
    if not q:
        return True
    hay = " ".join((rule["title"], rule["id"], rule["path"], rule["description"], " ".join(rule["techniques"]))).lower()
    return all(word in hay for word in q.lower().split())


def search(q: str = "", technique: str = "", level: str = "", product: str = "", category: str = "", service: str = "",
           status_filter: str = "", group: str = "", limit: int = 50, offset: int = 0) -> Dict:
    index = load_index()
    if not index:
        raise LibraryError("The SigmaHQ library is not synced yet")
    technique = technique.upper().strip()
    out = []
    for rule in index["rules"]:
        if technique and not any(t == technique or t.startswith(technique + ".") for t in rule["techniques"]):
            continue
        if level and rule["level"] != level:
            continue
        if product and rule["product"] != product:
            continue
        if category and rule["category"] != category:
            continue
        if service and rule["service"] != service:
            continue
        if status_filter and rule["status"] != status_filter:
            continue
        if group and rule["group"] != group:
            continue
        if not _match(rule, q):
            continue
        out.append(rule)
    limit = max(1, min(limit, 200))
    return {"total": len(out), "offset": offset, "limit": limit, "rules": out[offset:offset + limit]}


def read_rules(paths: Iterable[str]) -> List[Dict]:
    index = load_index()
    if not index:
        raise LibraryError("The SigmaHQ library is not synced yet")
    known = {r["path"] for r in index["rules"]}
    base = (_root() / RULES_DIR).resolve()
    out = []
    for rel in paths:
        if rel not in known:
            raise LibraryError(f"Unknown library rule: {rel}")
        path = (base / rel).resolve()
        if base not in path.parents:
            raise LibraryError(f"Unknown library rule: {rel}")
        out.append({"name": f"sigmahq/{rel}", "content": path.read_text(encoding="utf-8")})
    return out


def suggestions(technique_ids: Iterable[str], per_technique: int = 6) -> Dict[str, List[Dict]]:
    index = load_index()
    if not index:
        return {}
    wanted = set(technique_ids)
    out: Dict[str, List[Dict]] = {}
    rank = {lvl: i for i, lvl in enumerate(reversed(LEVELS))}
    status_rank = {"stable": 0, "test": 1, "experimental": 2}
    for rule in index["rules"]:
        for tid in rule["techniques"]:
            if tid in wanted:
                out.setdefault(tid, []).append(rule)
    for tid in out:
        out[tid].sort(key=lambda r: (status_rank.get(r["status"], 3), rank.get(r["level"], 9), r["title"]))
        out[tid] = [_brief(r) for r in out[tid][:per_technique]]
    return out


def _brief(rule: Dict) -> Dict:
    return {k: rule[k] for k in ("path", "title", "level", "status", "product", "category", "service", "techniques")}


def technique_counts() -> Dict[str, int]:
    index = load_index()
    if not index:
        return {}
    counts: Dict[str, int] = {}
    for rule in index["rules"]:
        for tid in rule["techniques"]:
            counts[tid] = counts.get(tid, 0) + 1
    return counts
