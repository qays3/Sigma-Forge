import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

API = "https://api.github.com"
REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
MAX_FILES = 200


class PushError(ValueError):
    pass


def _req(method: str, url: str, token: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "sigma-forge")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except ValueError:
            return exc.code, {"message": raw.decode("utf-8", "replace")[:300]}
    except urllib.error.URLError as exc:
        raise PushError(f"Could not reach GitHub: {exc.reason}")


def _msg(res: Any) -> str:
    if isinstance(res, dict):
        text = res.get("message", "")
        errs = res.get("errors")
        if isinstance(errs, list) and errs:
            first = errs[0]
            text += ": " + (first.get("message", "") if isinstance(first, dict) else str(first))
        return text
    return str(res)


def _safe_path(folder: str, name: str) -> str:
    parts = [p for p in (folder.strip("/") + "/" + name.strip("/")).split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise PushError(f"Bad file path: {name}")
    for p in parts:
        if not re.match(r"^[A-Za-z0-9 _.()+-]{1,200}$", p):
            raise PushError(f"Bad file path: {name}")
    return "/".join(parts)


def push(token: str, repo: str, files: List[Dict[str, str]], branch: str = "", base: str = "", folder: str = "rules",
         message: str = "", title: str = "", body: str = "", draft: bool = False) -> Dict[str, Any]:
    token = (token or "").strip()
    if not token:
        raise PushError("Add a GitHub token with repo or contents and pull request write access")
    repo = (repo or "").strip().removeprefix("https://github.com/").removesuffix(".git").strip("/")
    if not REPO.match(repo):
        raise PushError("Repository must look like owner/name")
    if not files:
        raise PushError("No rules to push")
    if len(files) > MAX_FILES:
        raise PushError(f"Too many files. The limit is {MAX_FILES}.")
    branch = (branch or f"sigma-forge/{time.strftime('%Y%m%d-%H%M%S')}").strip()
    if not BRANCH.match(branch) or ".." in branch or branch.endswith((".lock", "/")):
        raise PushError("Bad branch name")
    root = f"{API}/repos/{repo}"
    code, info = _req("GET", root, token)
    if code == 404:
        raise PushError("Repository not found, or the token cannot see it")
    if code != 200:
        raise PushError(f"GitHub said {code}: {_msg(info)}")
    base = (base or info.get("default_branch") or "main").strip()
    if not BRANCH.match(base):
        raise PushError("Bad base branch name")
    code, ref = _req("GET", f"{root}/git/ref/heads/{urllib.parse.quote(base, safe='/')}", token)
    if code != 200:
        raise PushError(f"Base branch {base} not found: {_msg(ref)}")
    sha = ref["object"]["sha"]
    code, made = _req("POST", f"{root}/git/refs", token, {"ref": f"refs/heads/{branch}", "sha": sha})
    created = code == 201
    if code not in (201, 422):
        raise PushError(f"Could not create branch {branch}: {_msg(made)}")
    msg = (message or "Add Sigma rules from Sigma Forge").strip()[:200]
    out_files = []
    for f in files:
        path = _safe_path(folder or "", f.get("name") or "rule.yml")
        q = urllib.parse.quote(path)
        code, cur = _req("GET", f"{root}/contents/{q}?ref={urllib.parse.quote(branch, safe='')}", token)
        payload = {
            "message": f"{msg}: {path.split('/')[-1]}",
            "content": base64.b64encode((f.get("content") or "").encode("utf-8")).decode(),
            "branch": branch,
        }
        action = "added"
        if code == 200 and isinstance(cur, dict) and cur.get("sha"):
            old = base64.b64decode(cur.get("content", "") or "").decode("utf-8", "replace") if cur.get("encoding") == "base64" else None
            if old is not None and old == (f.get("content") or ""):
                out_files.append({"path": path, "action": "same"})
                continue
            payload["sha"] = cur["sha"]
            action = "updated"
        code, put = _req("PUT", f"{root}/contents/{q}", token, payload)
        if code not in (200, 201):
            raise PushError(f"Could not write {path}: {_msg(put)}")
        out_files.append({"path": path, "action": action})
    changed = [f for f in out_files if f["action"] != "same"]
    pr_url = ""
    pr_number = None
    if changed or not created:
        pr_title = (title or f"Add {len(changed)} Sigma rule{'s' if len(changed) != 1 else ''}").strip()[:250]
        pr_body = (body or "Rules pushed from Sigma Forge.\n\n" + "\n".join(f"- `{f['path']}` {f['action']}" for f in out_files))[:60000]
        code, pr = _req("POST", f"{root}/pulls", token, {"title": pr_title, "head": branch, "base": base, "body": pr_body, "draft": bool(draft)})
        if code == 201:
            pr_url, pr_number = pr.get("html_url", ""), pr.get("number")
        elif code == 422:
            owner = repo.split("/")[0]
            code2, lst = _req("GET", f"{root}/pulls?head={urllib.parse.quote(owner + ':' + branch)}&state=open", token)
            if code2 == 200 and isinstance(lst, list) and lst:
                pr_url, pr_number = lst[0].get("html_url", ""), lst[0].get("number")
            elif not changed:
                pr_url = ""
            else:
                raise PushError(f"Files pushed, but the pull request failed: {_msg(pr)}")
        else:
            raise PushError(f"Files pushed, but the pull request failed: {_msg(pr)}")
    return {
        "repo": repo,
        "branch": branch,
        "base": base,
        "branch_created": created,
        "files": out_files,
        "changed": len(changed),
        "pr_url": pr_url,
        "pr_number": pr_number,
        "branch_url": f"https://github.com/{repo}/tree/{urllib.parse.quote(branch, safe='/')}",
    }
