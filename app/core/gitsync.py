import io
import json
import re
import urllib.error
import urllib.request
import zipfile
from pathlib import PurePosixPath
from typing import Dict, List, Optional

MAX_ZIP = 120 * 1024 * 1024
MAX_RULES = 5000
MAX_FILE = 512 * 1024
REPO_RE = re.compile(r"^(?:https?://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$")


class GitError(ValueError):
    pass


def parse_repo(repo: str, ref: str = "", path: str = "") -> Dict[str, str]:
    m = REPO_RE.match((repo or "").strip())
    if not m:
        raise GitError("Use owner/repo or a github.com link")
    owner, name, tree_ref, tree_path = m.groups()
    return {"owner": owner, "repo": name, "ref": (ref or tree_ref or "").strip(), "path": (path or tree_path or "").strip().strip("/")}


def _get(url: str, limit: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sigma-forge", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as res:
            data = res.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise GitError("Repository, branch or folder not found. Private repositories are not supported.")
        raise GitError(f"GitHub answered {exc.code}")
    except urllib.error.URLError as exc:
        raise GitError(f"Cannot reach GitHub: {exc.reason}")
    if len(data) > limit:
        raise GitError("The repository archive is too large")
    return data


def default_branch(owner: str, repo: str) -> Optional[str]:
    try:
        meta = json.loads(_get(f"https://api.github.com/repos/{owner}/{repo}", 2_000_000))
        return meta.get("default_branch")
    except (GitError, ValueError):
        return None


def fetch(repo: str, ref: str = "", path: str = "", kind: str = "sigma") -> Dict:
    yara = kind == "yara"
    exts = (".yar", ".yara") if yara else (".yml", ".yaml")
    spec = parse_repo(repo, ref, path)
    owner, name = spec["owner"], spec["repo"]
    branch = spec["ref"] or default_branch(owner, name) or "main"
    tried = [branch] if spec["ref"] else [branch] + [b for b in ("main", "master") if b != branch]
    data = None
    for b in tried:
        try:
            data = _get(f"https://github.com/{owner}/{name}/archive/refs/heads/{b}.zip", MAX_ZIP)
            branch = b
            break
        except GitError as exc:
            last = exc
    if data is None:
        raise last
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise GitError("GitHub did not return a zip archive")
    prefix = f"github/{owner}/{name}"
    want = spec["path"]
    rules: List[Dict[str, str]] = []
    skipped = 0
    for info in archive.infolist():
        if info.is_dir():
            continue
        parts = PurePosixPath(info.filename).parts[1:]
        if not parts or ".." in parts:
            continue
        rel = "/".join(parts)
        if want and not (rel == want or rel.startswith(want + "/")):
            continue
        if PurePosixPath(rel).suffix.lower() not in exts:
            continue
        if rel.startswith(".github/") or "/.github/" in rel:
            continue
        if info.file_size > MAX_FILE:
            skipped += 1
            continue
        try:
            text = archive.read(info).decode("utf-8-sig")
        except UnicodeDecodeError:
            skipped += 1
            continue
        if yara:
            if not re.search(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", text, re.M):
                continue
        elif "detection:" not in text and "correlation:" not in text:
            continue
        rules.append({"name": f"{prefix}/{rel}", "content": text})
        if len(rules) >= MAX_RULES:
            break
    if not rules:
        raise GitError(f"No {'YARA' if yara else 'Sigma'} rules found in that repository or folder")
    return {"owner": owner, "repo": name, "ref": branch, "path": want, "prefix": prefix + "/", "rules": rules, "skipped": skipped,
            "truncated": len(rules) >= MAX_RULES}
