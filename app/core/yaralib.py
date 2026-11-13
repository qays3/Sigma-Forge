import io
import json
import re
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from app.config import STATE_DIR

PACKAGES = {
    "core": "Core: high quality rules, low false positives, fast",
    "extended": "Extended: core plus more threat hunting rules",
    "full": "Full: every rule that passed the checks",
}
URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{pkg}.zip"
DIR = STATE_DIR / "yaraforge"
MAX_ZIP_BYTES = 120 * 1024 * 1024
MODULES = ("pe", "elf", "math", "hash", "dotnet", "magic", "cuckoo", "time", "console", "string")

_lock = threading.Lock()
_state = {"running": False, "error": "", "package": ""}
_cache: Dict[str, object] = {"mtime": None, "index": None, "content": None}

RULE_RE = re.compile(r"^((?:private\s+|global\s+)*)rule\s+([A-Za-z_]\w*)\s*(?::\s*([^{\n]*))?\s*\{", re.M)
META_RE = re.compile(r'^\s*([A-Za-z_]\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+)|(true|false))\s*$', re.M)
REPO_RE = re.compile(r"^\s*\*\s*Repository Name:\s*(.+?)\s*$", re.M)
WORD_RE = re.compile(r"\b[A-Za-z_]\w*\b")
CLOSE_RE = re.compile(r"^\}[ \t]*$", re.M)


class YaraLibError(ValueError):
    pass


def _index_path() -> Path:
    return DIR / "index.json"


def _content_path() -> Path:
    return DIR / "content.json"


def load_index() -> Optional[Dict]:
    path = _index_path()
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    if _cache["mtime"] != mtime:
        _cache["index"] = json.loads(path.read_text(encoding="utf-8"))
        _cache["content"] = None
        _cache["mtime"] = mtime
    return _cache["index"]


def _contents() -> Dict[str, str]:
    if load_index() is None:
        raise YaraLibError("Sync the YARA library first")
    if _cache["content"] is None:
        _cache["content"] = json.loads(_content_path().read_text(encoding="utf-8"))
    return _cache["content"]


def _facet(rules: List[Dict], key: str, top: int = 60) -> List[Dict]:
    counts: Dict[str, int] = {}
    for r in rules:
        vals = r[key] if isinstance(r[key], list) else [r[key]]
        for v in vals:
            if v:
                counts[v] = counts.get(v, 0) + 1
    return [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0].lower()))[:top]]


def status() -> Dict:
    index = load_index()
    base = {"syncing": _state["running"], "error": _state["error"], "packages": PACKAGES, "syncing_package": _state["package"]}
    if not index:
        return {**base, "available": False, "rules": 0}
    rules = index["rules"]
    return {**base, "available": True, "rules": len(rules), "package": index.get("package", ""), "release": index.get("release", ""),
            "synced_at": index.get("synced_at", ""), "repos": _facet(rules, "repo"), "tags": _facet(rules, "tags", 40)}


def _end(text: str, start: int) -> int:
    depth = 0
    i = start
    n = len(text)
    in_str = False
    in_re = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif in_re:
            if c == "\\":
                i += 2
                continue
            if c == "/":
                in_re = False
        elif c == '"':
            in_str = True
        elif c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def parse(text: str) -> List[Dict]:
    repos = [(m.start(), m.group(1)) for m in REPO_RE.finditer(text)]
    out = []
    for m in RULE_RE.finditer(text):
        start = m.start()
        close = CLOSE_RE.search(text, m.end())
        nxt = RULE_RE.search(text, m.end())
        end = close.end() if close and (not nxt or close.start() < nxt.start()) else _end(text, m.end() - 1)
        body = text[start:end]
        repo = ""
        for pos, name in repos:
            if pos < start:
                repo = name
            else:
                break
        meta: Dict[str, str] = {}
        sec = re.search(r"\bmeta\s*:(.*?)(?:\n\s*(?:strings|condition)\s*:)", body, re.S)
        if sec:
            for mm in META_RE.finditer(sec.group(1)):
                key = mm.group(1)
                val = mm.group(2) if mm.group(2) is not None else (mm.group(3) or mm.group(4) or "")
                meta.setdefault(key, val.replace('\\"', '"'))
        tags = [t for t in (m.group(3) or "").split() if t]
        for t in (meta.get("tags") or "").split(","):
            t = t.strip()
            if t and t not in tags:
                tags.append(t)
        cond = body.split("condition:", 1)[1] if "condition:" in body else ""

        def num(k):
            try:
                return int(meta.get(k, ""))
            except ValueError:
                return None

        out.append({
            "name": m.group(2), "private": "private" in (m.group(1) or ""), "repo": repo, "tags": tags[:12],
            "description": meta.get("description", "")[:400], "author": meta.get("author", "")[:120], "date": meta.get("date", "")[:20],
            "modified": meta.get("modified", "")[:20], "reference": meta.get("reference", "")[:300], "source_url": meta.get("source_url", "")[:400],
            "license_url": meta.get("license_url", "")[:300], "score": num("score"), "quality": num("quality"),
            "modules": sorted({mod for mod in MODULES if re.search(rf"\b{mod}\.", body)}),
            "words": sorted(set(WORD_RE.findall(cond)))[:200], "content": body,
        })
    return out


def install_zip(data: bytes, package: str = "", release: str = "") -> Dict:
    if len(data) > MAX_ZIP_BYTES:
        raise YaraLibError("The archive is too large")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise YaraLibError("The file is not a zip archive")
    text = ""
    for info in archive.infolist():
        if info.is_dir() or not info.filename.lower().endswith((".yar", ".yara")):
            continue
        text += archive.read(info).decode("utf-8", errors="replace") + "\n"
    if not text:
        raise YaraLibError("No .yar file found in the archive")
    rules = parse(text)
    if not rules:
        raise YaraLibError("No YARA rules found in the archive")
    if not package:
        m = re.search(r"^\s*\*\s*Name:\s*(\w+)", text, re.M)
        package = m.group(1) if m else "custom"
    if not release:
        m = re.search(r"^\s*\*\s*Creation Date:\s*([\d-]+)", text, re.M)
        release = m.group(1) if m else ""
    names = {r["name"] for r in rules}
    content = {}
    index_rules = []
    for r in rules:
        content[r["name"]] = r.pop("content")
        r["deps"] = [w for w in r.pop("words") if w in names and w != r["name"]]
        index_rules.append(r)
    index_rules.sort(key=lambda r: (r["repo"].lower(), r["name"].lower()))
    DIR.mkdir(parents=True, exist_ok=True)
    tmp_c = _content_path().with_suffix(".tmp")
    tmp_c.write_text(json.dumps(content, separators=(",", ":")), encoding="utf-8")
    tmp_c.replace(_content_path())
    index = {"package": package, "release": release, "synced_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "rules": index_rules}
    tmp_i = _index_path().with_suffix(".tmp")
    tmp_i.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    tmp_i.replace(_index_path())
    _cache["mtime"] = None
    return status()


def _download(package: str) -> None:
    try:
        req = urllib.request.Request(URL.format(pkg=package), headers={"User-Agent": "sigma-forge"})
        with urllib.request.urlopen(req, timeout=180) as res:
            data = res.read(MAX_ZIP_BYTES + 1)
        install_zip(data, package)
        _state["error"] = ""
    except YaraLibError as exc:
        _state["error"] = str(exc)
    except Exception as exc:
        _state["error"] = f"Download failed: {exc}. You can download yara-forge-rules-{package}.zip from github.com/YARAHQ/yara-forge/releases and upload it."
    finally:
        _state["running"] = False
        _state["package"] = ""


def start_sync(package: str = "core") -> Dict:
    if package not in PACKAGES:
        raise YaraLibError("Pick core, extended or full")
    with _lock:
        if not _state["running"]:
            _state.update(running=True, error="", package=package)
            threading.Thread(target=_download, args=(package,), daemon=True).start()
    return status()


def search(q: str = "", repo: str = "", tag: str = "", min_score: int = 0, sort: str = "", limit: int = 50, offset: int = 0) -> Dict:
    index = load_index()
    if not index:
        raise YaraLibError("Sync the YARA library first")
    words = q.lower().split()
    out = []
    for r in index["rules"]:
        if repo and r["repo"] != repo:
            continue
        if tag and tag not in r["tags"]:
            continue
        if min_score and (r["score"] or 0) < min_score:
            continue
        if words:
            hay = " ".join((r["name"], r["description"], r["author"], r["repo"], " ".join(r["tags"]), r["reference"])).lower()
            if not all(w in hay for w in words):
                continue
        out.append(r)
    if sort == "score":
        out.sort(key=lambda r: -(r["score"] or 0))
    elif sort == "date":
        out.sort(key=lambda r: r["modified"] or r["date"], reverse=True)
    return {"total": len(out), "offset": offset, "rules": out[offset:offset + limit]}


def read_rules(names: Iterable[str]) -> List[Dict]:
    content = _contents()
    index = {r["name"]: r for r in load_index()["rules"]}
    out = []
    for name in names:
        r = index.get(name)
        if not r:
            continue
        order: List[str] = []
        seen = set()

        def walk(n):
            if n in seen or n not in index:
                return
            seen.add(n)
            for d in index[n].get("deps", []):
                walk(d)
            order.append(n)

        walk(name)
        mods = sorted({m for n in order for m in index[n]["modules"]})
        head = "".join(f'import "{m}"\n' for m in mods)
        text = (head + "\n" if head else "") + "\n\n".join(content[n] for n in order) + "\n"
        out.append({**r, "content": text, "rules": order})
    return out
