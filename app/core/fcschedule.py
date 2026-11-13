import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import BASE_DIR, STATE_DIR

DIR = STATE_DIR / "firecheck"
FILE = DIR / "schedule.json"
MAX_HISTORY = 30
_lock = threading.Lock()
_thread: Optional[threading.Thread] = None
_running = False

DEFAULT = {"enabled": False, "every_hours": 24, "params": None, "webhook": {"kind": "slack", "url": ""}, "next_run": 0, "last": None, "history": [], "verdicts": {}}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def load() -> Dict[str, Any]:
    try:
        data = json.loads(FILE.read_text(encoding="utf-8"))
        return {**DEFAULT, **data}
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT))


def save(cfg: Dict[str, Any]) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(FILE)


def public(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load()
    p = cfg.get("params") or {}
    secrets = [k for k, v in (p.get("settings") or {}).items() if k in ("password", "token", "hec_token", "client_secret", "query_token", "ingest_token") and v]
    env = [k for k, v in (p.get("settings") or {}).items() if isinstance(v, str) and v.startswith("env:")]
    return {
        "enabled": cfg["enabled"], "every_hours": cfg["every_hours"], "next_run": cfg["next_run"], "running": _running,
        "platform": p.get("platform"), "target": p.get("target"), "mode": p.get("mode"), "rules": len(p.get("rules") or []),
        "logs": [f["name"] for f in p.get("logs") or []], "attack": bool(p.get("attack")), "sample": bool(p.get("sample")),
        "webhook": {"kind": (cfg.get("webhook") or {}).get("kind", "slack"), "set": bool((cfg.get("webhook") or {}).get("url"))},
        "stored_secrets": [k for k in secrets if k not in env], "env_secrets": env,
        "last": cfg.get("last"), "history": cfg.get("history", [])[:MAX_HISTORY],
    }


def update(enabled: bool, every_hours: int, params: Optional[Dict[str, Any]], kind: str, url: Optional[str]) -> Dict[str, Any]:
    with _lock:
        cfg = load()
        if params is not None:
            DIR.mkdir(parents=True, exist_ok=True)
            logs = []
            for i, (name, data) in enumerate(params.pop("files", []) or []):
                safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:80] or f"log{i}"
                path = DIR / f"log_{i}_{safe}"
                path.write_bytes(data)
                logs.append({"name": name, "path": path.name})
            for old in DIR.glob("log_*"):
                if old.name not in {l["path"] for l in logs}:
                    try:
                        old.unlink()
                    except OSError:
                        pass
            params["rules"] = [{"name": r.name, "content": r.content} for r in params["rules"]]
            params["logs"] = logs
            if params.get("platform") != (cfg.get("params") or {}).get("platform"):
                cfg["verdicts"] = {}
            cfg["params"] = params
        if enabled and not cfg.get("params"):
            raise ValueError("Run a fire check first, then schedule it")
        cfg["enabled"] = bool(enabled)
        cfg["every_hours"] = max(1, min(int(every_hours), 24 * 14))
        hook = dict(cfg.get("webhook") or {})
        hook["kind"] = kind if kind in ("slack", "teams", "discord", "webhook") else "webhook"
        if url is not None:
            hook["url"] = url.strip()
        cfg["webhook"] = hook
        cfg["next_run"] = time.time() + cfg["every_hours"] * 3600 if cfg["enabled"] else 0
        save(cfg)
    if cfg["enabled"]:
        ensure_thread()
    return public(cfg)


def _params(cfg: Dict[str, Any]) -> Dict[str, Any]:
    from app.schemas import RuleInput

    p = json.loads(json.dumps(cfg["params"]))
    p["rules"] = [RuleInput(**r) for r in p["rules"]]
    files = []
    for l in p.pop("logs", []) or []:
        path = DIR / l["path"]
        if path.is_file():
            files.append((l["name"], path.read_bytes()))
    if p.pop("sample", False):
        sample = BASE_DIR / "sample" / "logs" / "attack_chain_sysmon.jsonl"
        files.append((sample.name, sample.read_bytes()))
    p["files"] = files
    return p


def run_once() -> Dict[str, Any]:
    global _running
    from app.core.firecheck import run
    from app.core.scheduler import send

    with _lock:
        if _running:
            raise ValueError("A scheduled fire check is already running")
        _running = True
    entry: Dict[str, Any] = {"time": _now()}
    try:
        cfg = load()
        if not cfg.get("params"):
            raise ValueError("Nothing scheduled")
        job: Dict[str, Any] = {"status": "running", "params": _params(cfg), "stage": "", "done": 0, "total": 0, "error": "", "result": None}
        run(job)
        if job["status"] != "done":
            entry.update(status="error", error=job["error"])
            err = send(cfg, "Sigma Forge: scheduled fire check failed", [job["error"]], [])
            entry["sent"] = "ok" if not err else err
        else:
            res = job["result"]
            now = {r["key"]: {"verdict": r["verdict"], "title": r["title"]} for r in res["results"]}
            before = cfg.get("verdicts") or {}
            broke = [v["title"] for k, v in now.items() if before.get(k, {}).get("verdict") == "fires" and v["verdict"] in ("silent", "partial", "error")]
            fixed = [v["title"] for k, v in now.items() if before.get(k, {}).get("verdict") in ("silent", "partial", "error") and v["verdict"] == "fires"]
            entry.update(status="ok", score=res["score"], fired=res["fired"], should=res["should_fire"], silent=res["counts"].get("silent", 0),
                         errors=res["counts"].get("error", 0), slow=res.get("slow", 0), broke=broke[:50], fixed=fixed[:50])
            if broke or (not before and (res["counts"].get("silent") or res["counts"].get("error"))):
                lines = [f"{t} stopped firing" for t in broke[:20]] or [f'{res["counts"].get("silent", 0)} rules are silent, {res["counts"].get("error", 0)} have errors']
                lines += [f"{t} fires again" for t in fixed[:10]]
                err = send(cfg, f"Sigma Forge: fire score {res['score']}% on {res['platform_name']}", lines,
                           [{"rule": t, "level": "high", "summary": "stopped firing"} for t in broke[:20]])
                entry["sent"] = "ok" if not err else err
            elif fixed:
                err = send(cfg, f"Sigma Forge: {len(fixed)} rules fire again", [f"{t} fires again" for t in fixed[:20]], [])
                entry["sent"] = "ok" if not err else err
            with _lock:
                latest = load()
                latest["verdicts"] = now
                save(latest)
    except Exception as exc:
        entry.update(status="error", error=str(exc))
    finally:
        with _lock:
            latest = load()
            latest["last"] = entry
            latest["history"] = [entry] + latest.get("history", [])[: MAX_HISTORY - 1]
            if latest["enabled"]:
                latest["next_run"] = time.time() + latest["every_hours"] * 3600
            save(latest)
            _running = False
    return entry


def _loop() -> None:
    while True:
        try:
            cfg = load()
            if cfg["enabled"] and cfg["next_run"] and time.time() >= cfg["next_run"] and not _running:
                run_once()
        except Exception:
            pass
        time.sleep(30)


def ensure_thread() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, name="sigma-forge-firecheck", daemon=True)
        _thread.start()


def start_if_enabled() -> None:
    if load().get("enabled"):
        ensure_thread()
