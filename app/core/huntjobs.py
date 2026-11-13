import json
import multiprocessing as mp
import queue
import threading
import time
import uuid
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from app.config import STATE_DIR

KINDS = ("live", "evtx", "yara", "procs")
DIR = STATE_DIR / "hunt"
_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}
_procs: Dict[str, Any] = {}


class JobError(Exception):
    pass


def _items(rules: List[Dict[str, str]]):
    return [SimpleNamespace(name=r["name"], content=r["content"]) for r in rules]


def _worker(kind: str, params: Dict[str, Any], q) -> None:
    try:
        if kind == "live":
            from app.core.hunt import collect
            from app.core.logtest import run_test
            from app.schemas import ConvertOptions

            q.put(("stage", f"Reading {len(params['channels'])} log{'' if len(params['channels']) == 1 else 's'}"))
            blobs, stats = collect(params["channels"], params["hours"], params["max_events"])
            if not blobs:
                raise JobError("; ".join(s["error"] for s in stats if s["error"]) or "No events found in that time range")
            q.put(("stage", f"Running {len(params['rules'])} rules on the events"))
            result = run_test(_items(params["rules"]), blobs, params.get("mode", "auto"), options=ConvertOptions())
            result["channels"] = stats
        elif kind == "evtx":
            from app.core.logtest import run_test
            from app.schemas import ConvertOptions

            q.put(("stage", f"Running {len(params['rules'])} rules on {len(params['files'])} files"))
            result = run_test(_items(params["rules"]), params["files"], params.get("mode", "auto"), options=ConvertOptions())
        elif kind == "yara":
            from app.core.yara_engine import scan_paths

            q.put(("stage", f"Scanning {len(params['paths'])} paths with YARA"))
            result = scan_paths(params["rules"], params["paths"], params["recursive"], params["max_files"], params["max_size"], extensions=params["extensions"])
        else:
            from app.core.yara_engine import scan_processes

            q.put(("stage", f"Scanning {len(params['pids'])} processes" if params["pids"] else "Scanning every running process"))
            result = scan_processes(params["rules"], params["pids"] or None)
        q.put(("done", result))
    except Exception as exc:
        q.put(("error", str(exc) or exc.__class__.__name__))


def _path(kind: str):
    return DIR / f"last_{kind}.json"


def _save(job: Dict[str, Any]) -> None:
    try:
        DIR.mkdir(parents=True, exist_ok=True)
        tmp = _path(job["kind"]).with_suffix(".tmp")
        tmp.write_text(json.dumps(job, default=str), encoding="utf-8")
        tmp.replace(_path(job["kind"]))
    except OSError:
        pass


def _load(kind: str) -> Optional[Dict[str, Any]]:
    try:
        job = json.loads(_path(kind).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if job.get("status") == "running":
        job.update(status="error", error="The server stopped while this scan was running")
    return job


def _finish(job: Dict[str, Any], **kw) -> None:
    with _lock:
        if job["status"] != "running":
            return
        job.update(kw, finished=time.time())
        _procs.pop(job["kind"], None)
    _save(job)


def _watch(job: Dict[str, Any], proc, q) -> None:
    while True:
        try:
            kind, data = q.get(timeout=0.5)
        except queue.Empty:
            if not proc.is_alive():
                try:
                    kind, data = q.get(timeout=1)
                except queue.Empty:
                    if job["status"] == "running":
                        _finish(job, status="error", error="The scan stopped without a result")
                    return
            else:
                continue
        if kind == "stage":
            job["stage"] = data
        elif kind == "done":
            _finish(job, status="done", stage="Done", result=data)
            break
        elif kind == "error":
            _finish(job, status="error", error=data)
            break
    proc.join(timeout=5)


def start(kind: str, params: Dict[str, Any], label: str = "", scope: str = "") -> Dict[str, Any]:
    if kind not in KINDS:
        raise JobError("Unknown scan")
    with _lock:
        cur = _jobs.get(kind)
        if cur and cur["status"] == "running":
            raise JobError("This scan is already running. Cancel it first.")
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        proc = ctx.Process(target=_worker, args=(kind, params, q), daemon=True)
        job = {"id": uuid.uuid4().hex[:12], "kind": kind, "status": "running", "stage": "Starting", "started": time.time(), "finished": None,
               "label": label, "scope": scope, "error": "", "result": None}
        _jobs[kind] = job
        proc.start()
        _procs[kind] = proc
    threading.Thread(target=_watch, args=(job, proc, q), daemon=True).start()
    return summary(job)


def cancel(kind: str) -> Dict[str, Any]:
    with _lock:
        job = _jobs.get(kind)
        proc = _procs.get(kind)
    if not job or job["status"] != "running":
        raise JobError("Nothing is running here")
    if proc is not None:
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
    _finish(job, status="cancelled", stage="Cancelled", error="")
    return summary(job)


def get(kind: str) -> Optional[Dict[str, Any]]:
    with _lock:
        job = _jobs.get(kind)
    if job is None:
        job = _load(kind)
        if job is not None:
            with _lock:
                _jobs.setdefault(kind, job)
    return job


def summary(job: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not job:
        return None
    return {k: v for k, v in job.items() if k != "result"} | {"has_result": job.get("result") is not None}


def all_jobs() -> Dict[str, Any]:
    return {k: summary(get(k)) for k in KINDS}


def clear(kind: str) -> None:
    with _lock:
        job = _jobs.get(kind)
        if job and job["status"] == "running":
            raise JobError("Cancel the scan first")
        _jobs.pop(kind, None)
    try:
        _path(kind).unlink()
    except OSError:
        pass
