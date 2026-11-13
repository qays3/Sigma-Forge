import difflib
import json
import re
import urllib.parse
from typing import Any, Dict, List, Tuple

from app.core.deploy import KINDS, DeployError, _auth, _base, _convert, _send

LIMIT = 400000


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _diff(want: str, have: str) -> List[str]:
    a = re.sub(r"\s+(and|or|AND|OR|\|)\s+", r"\n\1 ", want or "").splitlines()
    b = re.sub(r"\s+(and|or|AND|OR|\|)\s+", r"\n\1 ", have or "").splitlines()
    return [l for l in difflib.unified_diff(a, b, "workspace", "platform", lineterm="", n=1)][2:80]


def _get(url: str, headers: Dict[str, str], verify: bool) -> Any:
    code, text = _send("GET", url, headers, None, verify)
    if code >= 300:
        raise DeployError(f"{urllib.parse.urlsplit(url).netloc} said {code}: {text[:200]}")
    try:
        return json.loads(text)
    except ValueError:
        return text


def _get_full(url: str, headers: Dict[str, str], verify: bool) -> str:
    import ssl
    import urllib.request

    req = urllib.request.Request(url, headers=headers)
    ctx = None
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as res:
            return res.read(LIMIT).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise DeployError(f"{urllib.parse.urlsplit(url).netloc} said {exc.code}: {exc.read(300).decode('utf-8', 'replace')}")
    except urllib.error.URLError as exc:
        raise DeployError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}")


def _splunk(settings, verify) -> Dict[str, Dict[str, Any]]:
    base = _base(settings.get("url"))
    app = urllib.parse.quote(settings.get("app") or "search")
    owner = urllib.parse.quote(settings.get("owner") or "nobody")
    prefix = settings.get("prefix", "Sigma - ")
    headers = _auth(settings, "Bearer")
    url = f"{base}/servicesNS/{owner}/{app}/saved/searches?output_mode=json&count=0&search={urllib.parse.quote(f'name={json.dumps(prefix + chr(42))}')}"
    data = json.loads(_get_full(url, headers, verify))
    out = {}
    for e in data.get("entry", []):
        name = e.get("name", "")
        if prefix and not name.startswith(prefix):
            continue
        c = e.get("content", {})
        out[name[len(prefix):]] = {"query": c.get("search", ""), "enabled": str(c.get("disabled", "0")) in ("0", "false", "False"), "updated": e.get("updated", ""), "author": e.get("author", "")}
    return out


def _elastic(settings, verify) -> Dict[str, Dict[str, Any]]:
    base = _base(settings.get("url"))
    space = (settings.get("space") or "").strip()
    path = f"/s/{urllib.parse.quote(space)}" if space and space != "default" else ""
    headers = {**_auth(settings, "ApiKey"), "kbn-xsrf": "true"}
    out = {}
    page = 1
    while page < 40:
        data = json.loads(_get_full(f"{base}{path}/api/detection_engine/rules/_find?per_page=500&page={page}", headers, verify))
        items = data.get("data", [])
        for r in items:
            out[r.get("name", "")] = {"query": r.get("query", ""), "enabled": bool(r.get("enabled")), "updated": r.get("updated_at", ""), "author": r.get("updated_by", ""), "tags": r.get("tags", [])}
        if len(items) < 500:
            break
        page += 1
    return out


def _wazuh(settings, verify) -> Tuple[Dict[str, Dict[str, Any]], str]:
    base = _base(settings.get("url"))
    filename = (settings.get("filename") or "sigma_forge_rules.xml").strip()
    user = (settings.get("username") or "").strip()
    token = (settings.get("token") or "").strip()
    if not token:
        if not user:
            raise DeployError("Add the Wazuh API user and password, or a token")
        import base64

        raw = base64.b64encode(f"{user}:{settings.get('password') or ''}".encode()).decode()
        code, text = _send("POST", f"{base}/security/user/authenticate", {"Authorization": f"Basic {raw}"}, None, verify)
        if code >= 300:
            raise DeployError(f"Wazuh login failed ({code})")
        token = json.loads(text)["data"]["token"]
    xml = _get_full(f"{base}/rules/files/{urllib.parse.quote(filename)}?raw=true", {"Authorization": f"Bearer {token}"}, verify)
    return _wazuh_blocks(xml), filename


def _wazuh_blocks(xml: str) -> Dict[str, Dict[str, Any]]:
    out = {}
    for rid, attrs, block in re.findall(r'<rule id="(\d+)"([^>]*)>(.*?)</rule>', xml or "", flags=re.S):
        m = re.search(r"<description>Sigma: (.*?)</description>", block, flags=re.S)
        if not m:
            continue
        title = m.group(1).strip().replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        body = re.sub(r"<description>.*?</description>", "", block, flags=re.S)
        out[title] = {"query": _norm(body), "enabled": True, "id": rid, "updated": "", "author": ""}
    return out


def _sentinel(settings, verify) -> Dict[str, Dict[str, Any]]:
    sub, rg, ws = (settings.get(k, "").strip() for k in ("subscription", "resource_group", "workspace"))
    token = (settings.get("token") or "").strip()
    if not (sub and rg and ws and token):
        raise DeployError("Add the subscription id, resource group, workspace name and an Azure access token")
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}"
           f"/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01")
    out = {}
    while url:
        data = json.loads(_get_full(url, {"Authorization": f"Bearer {token}"}, True))
        for r in data.get("value", []):
            p = r.get("properties", {})
            if p.get("query"):
                out[p.get("displayName", "")] = {"query": p.get("query", ""), "enabled": bool(p.get("enabled")), "updated": p.get("lastModifiedUtc", ""), "author": ""}
        url = data.get("nextLink")
    return out


def check(items, kind: str, target: str, settings: Dict[str, Any], options, mapping, sigma_only: bool = True) -> Dict[str, Any]:
    if kind not in KINDS:
        raise DeployError(f"Unknown platform: {kind}")
    verify = bool(settings.get("verify_tls", True))
    result = _convert(items, kind, target, options, mapping)
    want: Dict[str, Dict[str, Any]] = {}
    if kind == "wazuh":
        want = {t: {"query": v["query"]} for t, v in _wazuh_blocks(result.get("bundle") or "").items()}
    else:
        for row in result["results"]:
            if row["error"] or not row["queries"]:
                continue
            q = row["queries"][0] if len(row["queries"]) == 1 else "\n".join(row["queries"])
            if kind == "elastic":
                try:
                    q = json.loads(row["queries"][0]).get("query", q)
                except (ValueError, AttributeError):
                    pass
            want[row["title"]] = {"query": q}
    if kind == "splunk":
        have = _splunk(settings, verify)
    elif kind == "elastic":
        have = _elastic(settings, verify)
    elif kind == "sentinel":
        have = _sentinel(settings, verify)
    else:
        have, _ = _wazuh(settings, verify)
    rows = []
    for title, w in sorted(want.items()):
        h = have.get(title)
        if not h:
            rows.append({"title": title, "state": "missing", "query": w["query"][:3000]})
            continue
        same = _norm(w["query"]) == _norm(h["query"])
        rows.append({"title": title, "state": "same" if same else "changed", "enabled": h.get("enabled"), "updated": h.get("updated", ""), "author": h.get("author", ""),
                     "query": w["query"][:3000], "live": h["query"][:3000], "diff": [] if same else _diff(w["query"], h["query"])})
    for title, h in sorted(have.items()):
        if title in want:
            continue
        if kind == "elastic" and sigma_only and not any("sigma" in str(t).lower() for t in h.get("tags", [])):
            continue
        if kind == "sentinel" and sigma_only:
            continue
        rows.append({"title": title, "state": "extra", "enabled": h.get("enabled"), "updated": h.get("updated", ""), "author": h.get("author", ""), "live": h["query"][:3000]})
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    disabled = sum(1 for r in rows if r["state"] in ("same", "changed") and r.get("enabled") is False)
    order = {"changed": 0, "missing": 1, "extra": 2, "same": 3}
    rows.sort(key=lambda r: (order[r["state"]], r["title"].lower()))
    return {"kind": kind, "name": KINDS[kind]["name"], "rows": rows, "counts": counts, "disabled": disabled, "live_total": len(have), "workspace_total": len(want),
            "in_sync": not counts.get("changed") and not counts.get("missing") and not counts.get("extra")}
