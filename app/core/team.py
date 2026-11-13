import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.config import STATE_DIR

DIR = STATE_DIR / "team"
AUTH = os.getenv("SIGMA_FORGE_AUTH", "0").strip().lower() in ("1", "true", "yes", "on")
REQUIRE_REVIEW = os.getenv("SIGMA_FORGE_REQUIRE_REVIEW", "0").strip().lower() in ("1", "true", "yes", "on")
_DEMO = os.getenv("SIGMA_FORGE_DEMO", "0").strip().lower() in ("1", "true", "yes", "on")
RATE_LIMIT = int(os.getenv("SIGMA_FORGE_RATE_LIMIT") or ("240" if (AUTH or _DEMO) else "0"))
SESSION_HOURS = int(os.getenv("SIGMA_FORGE_SESSION_HOURS", "12") or 12)
ROLES = ["viewer", "editor", "reviewer", "admin"]
ITER = 310000
COOKIE = "sf_session"
_lock = threading.RLock()


class TeamError(ValueError):
    def __init__(self, msg: str, code: int = 400):
        super().__init__(msg)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _path(name: str):
    return DIR / name


def _read(name: str, default):
    try:
        return json.loads(_path(name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write(name: str, data) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = _path(name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(_path(name))


def _secret() -> bytes:
    p = _path("secret.key")
    with _lock:
        if p.is_file():
            return p.read_bytes()
        DIR.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        p.write_bytes(key)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return key


def _hash(password: str, salt: bytes) -> str:
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER)).decode()


def users() -> Dict[str, Dict[str, Any]]:
    return _read("users.json", {})


def setup_needed() -> bool:
    return AUTH and not users()


def _check_password(pw: str) -> None:
    if len(pw) < 10:
        raise TeamError("Use a password with at least 10 characters")
    if pw.lower() == pw or pw.upper() == pw or not re.search(r"\d", pw):
        raise TeamError("Use upper and lower case letters and a number")


def _check_name(name: str) -> str:
    name = (name or "").strip().lower()
    if not re.match(r"^[a-z0-9._-]{2,40}$", name):
        raise TeamError("User names use 2 to 40 letters, numbers, dots, dashes or underscores")
    return name


def create_user(username: str, password: str, role: str, by: str = "") -> Dict[str, Any]:
    username = _check_name(username)
    if role not in ROLES:
        raise TeamError("Unknown role")
    _check_password(password)
    with _lock:
        all_users = users()
        if username in all_users:
            raise TeamError("That user already exists")
        salt = secrets.token_bytes(16)
        all_users[username] = {"hash": _hash(password, salt), "salt": base64.b64encode(salt).decode(), "role": role, "created": _now(), "by": by, "disabled": False, "ver": 1}
        _write("users.json", all_users)
    return public_user(username, all_users[username])


def public_user(name: str, u: Dict[str, Any]) -> Dict[str, Any]:
    return {"username": name, "role": u["role"], "created": u.get("created", ""), "disabled": bool(u.get("disabled")), "last_login": u.get("last_login", "")}


def update_user(username: str, role: Optional[str], disabled: Optional[bool], password: Optional[str], by: str) -> Dict[str, Any]:
    with _lock:
        all_users = users()
        u = all_users.get(username)
        if not u:
            raise TeamError("No such user", 404)
        if role is not None:
            if role not in ROLES:
                raise TeamError("Unknown role")
            u["role"] = role
        if disabled is not None:
            u["disabled"] = bool(disabled)
        if password:
            _check_password(password)
            salt = secrets.token_bytes(16)
            u["hash"], u["salt"] = _hash(password, salt), base64.b64encode(salt).decode()
        u["ver"] = int(u.get("ver", 1)) + 1
        admins = [n for n, x in all_users.items() if x["role"] == "admin" and not x.get("disabled")]
        if not admins:
            raise TeamError("Keep at least one active admin")
        _write("users.json", all_users)
    return public_user(username, u)


def delete_user(username: str, by: str) -> None:
    with _lock:
        all_users = users()
        if username not in all_users:
            raise TeamError("No such user", 404)
        if username == by:
            raise TeamError("You cannot delete yourself")
        all_users.pop(username)
        if not [n for n, x in all_users.items() if x["role"] == "admin" and not x.get("disabled")]:
            raise TeamError("Keep at least one active admin")
        _write("users.json", all_users)


def login(username: str, password: str) -> Tuple[str, Dict[str, Any]]:
    username = (username or "").strip().lower()
    u = users().get(username)
    if not u or u.get("disabled"):
        _hash(password or "x", b"0" * 16)
        raise TeamError("Wrong user name or password", 401)
    if not hmac.compare_digest(_hash(password or "", base64.b64decode(u["salt"])), u["hash"]):
        raise TeamError("Wrong user name or password", 401)
    with _lock:
        all_users = users()
        all_users[username]["last_login"] = _now()
        _write("users.json", all_users)
    return make_token(username, u), public_user(username, u)


def make_token(username: str, u: Dict[str, Any]) -> str:
    exp = int(time.time()) + SESSION_HOURS * 3600
    raw = f"{username}|{exp}|{u.get('ver', 1)}|{secrets.token_hex(8)}"
    sig = hmac.new(_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(raw.encode()).decode() + "." + sig


def session(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    try:
        raw = base64.urlsafe_b64decode(body.encode()).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    if not hmac.compare_digest(hmac.new(_secret(), raw.encode(), hashlib.sha256).hexdigest(), sig):
        return None
    try:
        name, exp, ver, _ = raw.split("|")
    except ValueError:
        return None
    if int(exp) < time.time():
        return None
    u = users().get(name)
    if not u or u.get("disabled") or str(u.get("ver", 1)) != ver:
        return None
    return {"username": name, "role": u["role"]}


def audit(user: str, action: str, detail: str = "", ip: str = "", status: int = 0) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"time": _now(), "user": user, "action": action, "detail": detail[:500], "ip": ip, "status": status}, ensure_ascii=False)
    with _lock:
        p = _path("audit.jsonl")
        with p.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if p.stat().st_size > 20 * 1048576:
            lines = p.read_text(encoding="utf-8").splitlines()[-50000:]
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_audit(limit: int = 500, user: str = "", action: str = "") -> List[Dict[str, Any]]:
    try:
        lines = _path("audit.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if user and e.get("user") != user:
            continue
        if action and action not in e.get("action", ""):
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


def _rid(name: str, content: str) -> str:
    return hashlib.sha256(f"{name}\n{content}".encode()).hexdigest()[:24]


def chash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:20]


def rules() -> Dict[str, Any]:
    data = _read("workspace.json", {"version": 0, "rules": []})
    return data


def add_rules(files: List[Dict[str, str]], by: str) -> Dict[str, Any]:
    with _lock:
        data = rules()
        items = {r["id"]: r for r in data["rules"]}
        by_content = {r["content"]: r for r in data["rules"]}
        added = 0
        for f in files:
            name, content = f["name"], f["content"]
            rid = _rid(name, content)
            if rid in items:
                continue
            same = by_content.get(content)
            if same:
                items.pop(same["id"], None)
            else:
                added += 1
            item = {"id": rid, "name": name, "content": content, "size": len(content), "added": int(time.time() * 1000), "by": by, "updated": _now()}
            items[rid] = item
            by_content[content] = item
        data["rules"] = sorted(items.values(), key=lambda r: r["name"])
        data["version"] += 1
        _write("workspace.json", data)
    return {"added": added, "version": data["version"]}


def replace_rule(old_id: str, name: str, content: str, by: str) -> Dict[str, Any]:
    with _lock:
        data = rules()
        data["rules"] = [r for r in data["rules"] if r["id"] != old_id and r["content"] != content]
        item = {"id": _rid(name, content), "name": name, "content": content, "size": len(content), "added": int(time.time() * 1000), "by": by, "updated": _now()}
        data["rules"].append(item)
        data["rules"].sort(key=lambda r: r["name"])
        data["version"] += 1
        _write("workspace.json", data)
    return item


def remove_rules(ids: List[str]) -> int:
    with _lock:
        data = rules()
        before = len(data["rules"])
        drop = set(ids)
        data["rules"] = [r for r in data["rules"] if r["id"] not in drop]
        data["version"] += 1
        _write("workspace.json", data)
        return before - len(data["rules"])


def clear_rules() -> None:
    with _lock:
        data = rules()
        data["rules"] = []
        data["version"] += 1
        _write("workspace.json", data)


def reviews() -> Dict[str, Dict[str, Any]]:
    return _read("reviews.json", {})


def review_state(name: str, content: str) -> Dict[str, Any]:
    r = reviews().get(name)
    if not r:
        return {"status": "none"}
    if r["hash"] != chash(content):
        return {"status": "outdated", "id": name, "was": r["status"]}
    return {"status": r["status"], "id": name, "by": r.get("decided_by", ""), "requested_by": r.get("requested_by", "")}


def request_review(name: str, content: str, note: str, by: str) -> Dict[str, Any]:
    with _lock:
        all_r = reviews()
        prev = all_r.get(name, {})
        thread = prev.get("thread", [])
        thread.append({"time": _now(), "user": by, "kind": "request", "text": note[:2000]})
        all_r[name] = {"name": name, "hash": chash(content), "content": content, "status": "pending", "requested_by": by, "requested": _now(),
                       "decided_by": "", "decided": "", "thread": thread[-100:], "previous": prev.get("content", "") if prev.get("status") == "approved" else prev.get("previous", "")}
        _write("reviews.json", all_r)
        return all_r[name]


def decide(name: str, decision: str, note: str, by: str, role: str) -> Dict[str, Any]:
    if role not in ("reviewer", "admin"):
        raise TeamError("Only reviewers and admins can decide", 403)
    if decision not in ("approved", "changes"):
        raise TeamError("Pick approve or request changes")
    with _lock:
        all_r = reviews()
        r = all_r.get(name)
        if not r:
            raise TeamError("No review for this rule", 404)
        if decision == "approved" and r["requested_by"] == by:
            raise TeamError("Someone else has to approve your own change", 403)
        r["status"] = decision
        r["decided_by"], r["decided"] = by, _now()
        r["thread"].append({"time": _now(), "user": by, "kind": decision, "text": note[:2000]})
        _write("reviews.json", all_r)
        return r


def comment(name: str, text: str, by: str) -> Dict[str, Any]:
    if not text.strip():
        raise TeamError("Write a comment first")
    with _lock:
        all_r = reviews()
        r = all_r.get(name)
        if not r:
            raise TeamError("No review for this rule", 404)
        r["thread"].append({"time": _now(), "user": by, "kind": "comment", "text": text[:2000]})
        _write("reviews.json", all_r)
        return r


def unapproved(items) -> List[str]:
    out = []
    all_r = reviews()
    for it in items:
        r = all_r.get(it.name)
        if not r or r["status"] != "approved" or r["hash"] != chash(it.content):
            out.append(it.name)
    return out


def cases() -> List[Dict[str, Any]]:
    return _read("cases.json", [])


def save_case(case: Dict[str, Any], by: str) -> Dict[str, Any]:
    if not isinstance(case, dict) or not re.match(r"^[\w-]{3,40}$", str(case.get("id", ""))):
        raise TeamError("Bad case")
    with _lock:
        items = cases()
        case = {**case, "updated_by": by}
        items = [c for c in items if c.get("id") != case["id"]]
        items.insert(0, case)
        _write("cases.json", items[:2000])
    return case


def delete_case(cid: str) -> None:
    with _lock:
        _write("cases.json", [c for c in cases() if c.get("id") != cid])


class RateLimiter:
    def __init__(self):
        self.hits: Dict[str, Deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.hits) > 20000:
                for k in list(self.hits)[:5000]:
                    self.hits.pop(k, None)
            return True


limiter = RateLimiter()

VIEWER_POST_OK = ("/api/analyze", "/api/convert", "/api/compare", "/api/coverage", "/api/test", "/api/rules/explain", "/api/rules/sigmahq", "/api/rules/unit",
                  "/api/querygen", "/api/wizard", "/api/correlation", "/api/threat", "/api/sysmon", "/api/mappings/suggest", "/api/purple", "/api/export",
                  "/api/generate-events", "/api/attacklogs", "/api/cases/report", "/api/hunt/report", "/api/report", "/api/rules/autofix", "/api/yara/check",
                  "/api/yara/scan", "/api/auth/", "/api/rules/ioc", "/api/library/updates", "/api/import/siem", "/api/ci/workflow", "/api/rules/add-filter")
ADMIN_ONLY = ("/api/team/users", "/api/team/audit")


def allowed(role: str, method: str, path: str) -> bool:
    if any(path.startswith(p) for p in ADMIN_ONLY):
        return role == "admin"
    if method in ("GET", "HEAD", "OPTIONS"):
        return True
    if role == "viewer":
        return any(path.startswith(p) for p in VIEWER_POST_OK)
    return True
