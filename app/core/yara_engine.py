import re
from typing import Dict, List, Tuple

MAX_SCAN_BYTES = 64 * 1024 * 1024
TIMEOUT = 30


class YaraError(ValueError):
    pass


def _yara():
    try:
        import yara
    except ImportError:
        raise YaraError("YARA support needs the yara-python package. Run setup again to install it.")
    return yara


def available() -> Dict:
    try:
        y = _yara()
        return {"available": True, "version": getattr(y, "YARA_VERSION", "")}
    except YaraError as exc:
        return {"available": False, "version": "", "message": str(exc)}


RULE_RE = re.compile(r"^\s*(?:(private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^{]+))?\{", re.M)


def _outline(text: str) -> List[Dict]:
    out = []
    for m in RULE_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"name": m.group(2), "tags": (m.group(3) or "").split(), "line": line})
    return out


def check(files: List[Tuple[str, str]]) -> Dict:
    yara = _yara()
    results = []
    for name, text in files:
        entry = {"name": name, "ok": True, "error": "", "line": None, "rules": [], "warnings": []}
        try:
            compiled = yara.compile(source=text, error_on_warning=False)
            details = []
            for r in compiled:
                meta = dict(r.meta) if hasattr(r, "meta") else {}
                details.append({"name": r.identifier, "tags": list(r.tags), "meta": {k: str(v) for k, v in meta.items()}})
            outline = {o["name"]: o for o in _outline(text)}
            for d in details:
                d["line"] = outline.get(d["name"], {}).get("line")
                d["strings"] = _count_strings(text, d["line"])
            entry["rules"] = details
        except yara.SyntaxError as exc:
            msg = str(exc)
            m = re.search(r"line (\d+)", msg)
            entry.update(ok=False, error=msg, line=int(m.group(1)) if m else None)
        except yara.Error as exc:
            entry.update(ok=False, error=str(exc))
        results.append(entry)
    return {"files": results, "rules": sum(len(f["rules"]) for f in results), "errors": sum(1 for f in results if not f["ok"])}


def _count_strings(text: str, line) -> int:
    if not line:
        return 0
    lines = text.splitlines()[line - 1:]
    count = 0
    in_strings = False
    for ln in lines[1:]:
        s = ln.strip()
        if s.startswith("strings:"):
            in_strings = True
            continue
        if s.startswith("condition:") or s.startswith("rule ") or s.startswith("}"):
            break
        if in_strings and s.startswith("$"):
            count += 1
    return count


def _preview(data: bytes) -> Dict[str, str]:
    chunk = data[:64]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return {"text": text, "hex": chunk.hex(" ")}


def scan(rule_files: List[Tuple[str, str]], targets: List[Tuple[str, bytes]]) -> Dict:
    yara = _yara()
    total = sum(len(d) for _, d in targets)
    if total > MAX_SCAN_BYTES:
        raise YaraError(f"Files are {total // 1048576} MB. The limit is {MAX_SCAN_BYTES // 1048576} MB.")
    sources = {}
    for i, (name, text) in enumerate(rule_files):
        ns = re.sub(r"[^A-Za-z0-9_]", "_", name) or f"rules_{i}"
        sources[f"{ns}_{i}"] = text
    try:
        compiled = yara.compile(sources=sources, error_on_warning=False)
    except yara.SyntaxError as exc:
        raise YaraError(f"Rule error: {exc}")
    files = []
    hits_total = 0
    for name, data in targets:
        try:
            matches = compiled.match(data=data, timeout=TIMEOUT)
        except yara.TimeoutError:
            files.append({"name": name, "size": len(data), "matches": [], "error": "Scan timed out"})
            continue
        except yara.Error as exc:
            files.append({"name": name, "size": len(data), "matches": [], "error": str(exc)})
            continue
        out = []
        for m in matches:
            strings = []
            for s in m.strings:
                for inst in s.instances[:5]:
                    strings.append({"id": s.identifier, "offset": inst.offset, **_preview(inst.matched_data)})
                if len(strings) >= 25:
                    break
            out.append({"rule": m.rule, "tags": list(m.tags), "meta": {k: str(v) for k, v in m.meta.items()}, "strings": strings,
                        "string_hits": sum(len(s.instances) for s in m.strings)})
        hits_total += len(out)
        files.append({"name": name, "size": len(data), "matches": out, "error": ""})
    return {"files": files, "summary": {"files": len(files), "matched_files": sum(1 for f in files if f["matches"]), "matches": hits_total}}


def _compile_sources(rule_files: List[Tuple[str, str]]):
    yara = _yara()
    sources = {}
    for i, (name, text) in enumerate(rule_files):
        ns = re.sub(r"[^A-Za-z0-9_]", "_", name) or f"rules_{i}"
        sources[f"{ns}_{i}"] = text
    try:
        return yara, yara.compile(sources=sources, error_on_warning=False)
    except yara.SyntaxError as exc:
        raise YaraError(f"Rule error: {exc}")


def _match_out(matches) -> List[Dict]:
    out = []
    for m in matches:
        strings = []
        for s in m.strings:
            for inst in s.instances[:5]:
                strings.append({"id": s.identifier, "offset": inst.offset, **_preview(inst.matched_data)})
            if len(strings) >= 25:
                break
        out.append({"rule": m.rule, "tags": list(m.tags), "meta": {k: str(v) for k, v in m.meta.items()}, "strings": strings,
                    "string_hits": sum(len(s.instances) for s in m.strings)})
    return out


def scan_paths(rule_files: List[Tuple[str, str]], paths: List[str], recursive: bool = True, max_files: int = 20000,
               max_size: int = 32 * 1024 * 1024, budget: int = 300, extensions=None) -> Dict:
    import json as _json
    import time as _time

    from app.core.hunt import walk_files

    yara, compiled = _compile_sources(rule_files)
    started = _time.monotonic()
    files, missing, errors = [], [], []
    scanned = 0
    truncated = ""
    skipped = {}
    for kind, path, size in walk_files(paths, recursive, max_files, max_size, extensions):
        if kind == "missing":
            missing.append(path)
            continue
        if kind == "limit":
            truncated = f"Stopped at {max_files} files"
            continue
        if kind == "skipped":
            skipped = _json.loads(path)
            continue
        if _time.monotonic() - started > budget:
            truncated = f"Stopped after {budget} seconds"
            break
        scanned += 1
        try:
            matches = compiled.match(filepath=path, timeout=10)
        except yara.TimeoutError:
            errors.append({"path": path, "error": "Scan timed out"})
            continue
        except yara.Error as exc:
            if len(errors) < 200:
                errors.append({"path": path, "error": str(exc)})
            continue
        if matches:
            files.append({"name": path, "size": size, "matches": _match_out(matches), "error": ""})
    return {
        "files": files,
        "missing": missing,
        "errors": errors[:200],
        "skipped": skipped,
        "truncated": truncated,
        "summary": {"scanned": scanned, "matched_files": len(files), "matches": sum(len(f["matches"]) for f in files),
                    "errors": len(errors), "seconds": round(_time.monotonic() - started, 1)},
    }


def scan_processes(rule_files: List[Tuple[str, str]], pids=None, budget: int = 240) -> Dict:
    import os as _os
    import time as _time

    from app.core.hunt import list_processes

    yara, compiled = _compile_sources(rule_files)
    procs = list_processes()
    if pids:
        wanted = {int(p) for p in pids}
        procs = [p for p in procs if p["pid"] in wanted]
    me = _os.getpid()
    started = _time.monotonic()
    found, errors = [], []
    scanned = 0
    denied = 0
    truncated = ""
    for p in procs:
        if p["pid"] in (0, 4, me):
            continue
        if _time.monotonic() - started > budget:
            truncated = f"Stopped after {budget} seconds"
            break
        scanned += 1
        try:
            matches = compiled.match(pid=p["pid"], timeout=15)
        except yara.TimeoutError:
            errors.append({"path": f'{p["name"]} ({p["pid"]})', "error": "Scan timed out"})
            continue
        except yara.Error as exc:
            text = str(exc)
            if "access" in text.lower() or "denied" in text.lower() or "could not attach" in text.lower():
                denied += 1
            elif len(errors) < 100:
                errors.append({"path": f'{p["name"]} ({p["pid"]})', "error": text})
            continue
        if matches:
            found.append({"name": f'{p["exe"] or p["name"]} (pid {p["pid"]})', "pid": p["pid"], "process": p["name"], "user": p["user"],
                          "size": 0, "matches": _match_out(matches), "error": ""})
    return {
        "files": found,
        "missing": [],
        "errors": errors,
        "skipped": {"no_access": denied, "too_big": 0},
        "truncated": truncated,
        "summary": {"scanned": scanned, "matched_files": len(found), "matches": sum(len(f["matches"]) for f in found),
                    "errors": len(errors), "denied": denied, "seconds": round(_time.monotonic() - started, 1)},
    }
