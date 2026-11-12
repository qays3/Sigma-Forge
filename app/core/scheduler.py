import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import APP_NAME, DATA_DIR

FILE = DATA_DIR / "hunt_schedule.json"
LEVELS = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
KINDS = ("slack", "teams", "discord", "webhook")
MAX_SEEN = 20000

_lock = threading.Lock()
_thread: Optional[threading.Thread] = None
_running = False

DEFAULT = {
    "enabled": False,
    "every_minutes": 15,
    "channels": [],
    "rules": [],
    "min_level": "medium",
    "webhook": {"kind": "slack", "url": ""},
    "last_run": "",
    "next_run": 0,
    "seen": [],
    "history": [],
    "recent": [],
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load() -> Dict[str, Any]:
    try:
        data = json.loads(FILE.read_text(encoding="utf-8"))
        return {**DEFAULT, **data}
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT))


def save(cfg: Dict[str, Any]) -> None:
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    tmp.replace(FILE)


def public(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = cfg or load()
    hook = dict(cfg.get("webhook") or {})
    url = hook.get("url", "")
    hook["url_set"] = bool(url)
    hook["url"] = (url[:28] + "...") if len(url) > 32 else url
    return {
        "enabled": cfg["enabled"],
        "every_minutes": cfg["every_minutes"],
        "channels": cfg["channels"],
        "rule_count": len(cfg["rules"]),
        "min_level": cfg["min_level"],
        "webhook": hook,
        "last_run": cfg["last_run"],
        "next_run": cfg["next_run"],
        "history": cfg["history"][:30],
        "recent": cfg["recent"][:50],
        "running": _running,
    }


def update(enabled: bool, every_minutes: int, channels: List[str], rules: Optional[List[Dict[str, str]]], min_level: str,
           kind: str, url: Optional[str]) -> Dict[str, Any]:
    with _lock:
        cfg = load()
        cfg["enabled"] = bool(enabled)
        cfg["every_minutes"] = max(5, min(int(every_minutes), 1440))
        cfg["channels"] = list(channels)[:20]
        if rules is not None:
            cfg["rules"] = rules
        cfg["min_level"] = min_level if min_level in LEVELS else "medium"
        hook = cfg.get("webhook") or {}
        hook["kind"] = kind if kind in KINDS else "webhook"
        if url is not None:
            hook["url"] = url.strip()
        cfg["webhook"] = hook
        cfg["next_run"] = time.time() + 5 if cfg["enabled"] else 0
        save(cfg)
    ensure_thread()
    return public(cfg)


def _payload(kind: str, title: str, lines: List[str], hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    text = title + ("\n" + "\n".join(lines) if lines else "")
    if kind == "slack":
        return {"text": text}
    if kind == "discord":
        return {"content": text[:1900]}
    if kind == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": title, "title": title, "text": "<br>".join(lines) or title}
    return {"app": APP_NAME, "title": title, "hits": hits, "time": _now()}


def send(cfg: Dict[str, Any], title: str, lines: List[str], hits: List[Dict[str, Any]]) -> str:
    hook = cfg.get("webhook") or {}
    url = hook.get("url", "")
    if not url:
        return "No webhook set"
    if not url.lower().startswith(("https://", "http://")):
        return "The webhook must start with https://"
    body = json.dumps(_payload(hook.get("kind", "webhook"), title, lines, hits)).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": APP_NAME})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return "" if 200 <= resp.status < 300 else f"Webhook answered {resp.status}"
    except urllib.error.HTTPError as exc:
        return f"Webhook answered {exc.code}"
    except (urllib.error.URLError, OSError) as exc:
        return f"Webhook failed: {getattr(exc, 'reason', exc)}"


def fingerprint(item: Dict[str, Any]) -> str:
    raw = f'{item.get("key")}|{item.get("host")}|{item.get("ts")}|{item.get("summary")}'
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def run_once(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from app.core.hunt import collect
    from app.core.logtest import LogInputError, run_test
    from app.schemas import RuleInput

    global _running
    cfg = cfg or load()
    entry = {"time": _now(), "events": 0, "fired": 0, "new": 0, "error": "", "sent": ""}
    if not cfg["rules"] or not cfg["channels"]:
        entry["error"] = "Pick rules and logs first"
        return entry
    _running = True
    try:
        hours = cfg["every_minutes"] / 60 + 0.1
        blobs, stats = collect(cfg["channels"], hours, 50000)
        failed = [s["error"] for s in stats if s["error"]]
        if not blobs:
            entry["error"] = "; ".join(failed) or "No events in this window"
            return entry
        items = [RuleInput(name=r["name"], content=r["content"]) for r in cfg["rules"]]
        try:
            res = run_test(items, blobs, "auto")
        except LogInputError as exc:
            entry["error"] = str(exc)
            return entry
        entry["events"] = res["summary"]["events"]
        entry["fired"] = res["summary"]["matched_rules"]
        floor = LEVELS.get(cfg["min_level"], 3)
        seen = set(cfg.get("seen", []))
        fresh = []
        for it in res["timeline"]["items"]:
            if LEVELS.get(it["level"], 0) < floor:
                continue
            fp = fingerprint(it)
            if fp in seen:
                continue
            seen.add(fp)
            fresh.append(it)
        entry["new"] = len(fresh)
        if failed:
            entry["error"] = "; ".join(failed)[:300]
        if fresh:
            rules = {}
            for it in fresh:
                rules.setdefault((it["rule"], it["level"]), set()).add(it["host"])
            lines = [f'[{lvl.upper()}] {name} on {", ".join(sorted(h))[:120]}' for (name, lvl), h in sorted(rules.items(), key=lambda x: -LEVELS.get(x[0][1], 0))][:20]
            title = f'{APP_NAME}: {len(fresh)} new hit{"s" if len(fresh) != 1 else ""} from {len(rules)} rule{"s" if len(rules) != 1 else ""}'
            err = send(cfg, title, lines, [{k: it[k] for k in ("ts", "host", "user", "rule", "level", "tactics", "summary")} for it in fresh[:100]])
            entry["sent"] = "ok" if not err else err
        with _lock:
            latest = load()
            latest["seen"] = list(seen)[-MAX_SEEN:]
            latest["recent"] = ([{k: it[k] for k in ("ts", "host", "rule", "level", "summary")} for it in reversed(fresh)] + latest.get("recent", []))[:200]
            cfg.update({"seen": latest["seen"], "recent": latest["recent"]})
            save({**latest, "seen": latest["seen"], "recent": latest["recent"]})
        return entry
    finally:
        _running = False
        with _lock:
            latest = load()
            latest["last_run"] = entry["time"]
            latest["history"] = [entry] + latest.get("history", [])[:99]
            if latest["enabled"]:
                latest["next_run"] = time.time() + latest["every_minutes"] * 60
            save(latest)


def _loop() -> None:
    while True:
        try:
            cfg = load()
            if cfg["enabled"] and cfg["next_run"] and time.time() >= cfg["next_run"] and not _running:
                run_once(cfg)
        except Exception:
            pass
        time.sleep(20)


def ensure_thread() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_loop, name="sigma-forge-scheduler", daemon=True)
        _thread.start()


def start_if_enabled() -> None:
    if load().get("enabled"):
        ensure_thread()
