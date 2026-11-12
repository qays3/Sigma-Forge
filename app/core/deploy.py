import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

from app.core.converter import ConversionRequestError, convert
from app.core.export import SENTINEL_TACTICS, SEVERITY_SENTINEL, SEVERITY_SPLUNK, _guid, _meta

KINDS = {
    "splunk": {"name": "Splunk", "targets": ["splunk", "splunk_cim"], "format": "default"},
    "elastic": {"name": "Elastic Security (Kibana)", "targets": ["elastic_lucene", "elastic_eql", "elastic_esql"], "format": "siem_rule_ndjson"},
    "sentinel": {"name": "Microsoft Sentinel", "targets": ["sentinel_asim", "azure_monitor"], "format": "default"},
    "wazuh": {"name": "Wazuh manager", "targets": ["wazuh"], "format": "default"},
}
TIMEOUT = 25


class DeployError(ValueError):
    pass


def _ctx(verify: bool):
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], verify: bool) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx(verify)) as res:
            return res.status, res.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4000).decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise DeployError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}")
    except TimeoutError:
        raise DeployError(f"{urllib.parse.urlsplit(url).netloc} did not answer in {TIMEOUT} seconds")


def _base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise DeployError("The URL must start with http:// or https://")
    return url


def _auth(settings: Dict[str, Any], scheme: str = "Bearer") -> Dict[str, str]:
    token = (settings.get("token") or "").strip()
    user = (settings.get("username") or "").strip()
    if token:
        return {"Authorization": f"{scheme} {token}"}
    if user:
        raw = f"{user}:{settings.get('password') or ''}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    raise DeployError("Add a token or a username and password")


def _mask(headers: Dict[str, str]) -> Dict[str, str]:
    return {k: ("***" if k.lower() == "authorization" else v) for k, v in headers.items()}


def _convert(items, kind: str, target: str, options, mapping) -> Dict:
    spec = KINDS[kind]
    if target not in spec["targets"]:
        target = spec["targets"][0]
    return convert(items, target, spec["format"], options, mapping)


def deploy(items, kind: str, target: str, settings: Dict[str, Any], options, mapping, dry_run: bool) -> Dict:
    if kind not in KINDS:
        raise DeployError(f"Unknown destination: {kind}")
    verify = bool(settings.get("verify_tls", True))
    items = list(items)
    result = _convert(items, kind, target, options, mapping)
    meta = _meta(items)
    rows = [r for r in result["results"] if not r["error"] and r["queries"]]
    failed = [{"title": r["title"], "status": "skipped", "message": r["error"]} for r in result["results"] if r["error"]]
    if not rows:
        raise DeployError("No rule converted, so there is nothing to deploy")
    plan = globals()[f"_plan_{kind}"](rows, meta, settings, result)
    out = []
    if dry_run:
        for step in plan:
            preview = step["body"][:1500].decode("utf-8", "replace") if step["body"] else ""
            out.append({"title": step["title"], "status": "planned", "method": step["method"], "url": step["url"], "headers": _mask(step["headers"]), "body": preview})
        return {"kind": kind, "dry_run": True, "results": out + failed, "target": result["target"]}
    for step in plan:
        if step.get("prepare"):
            step["prepare"](step, verify)
        code, text = _send(step["method"], step["url"], step["headers"], step["body"], verify)
        ok = 200 <= code < 300
        if not ok and step.get("retry_update"):
            alt = step["retry_update"]
            code, text = _send(alt["method"], alt["url"], step["headers"], alt["body"], verify)
            ok = 200 <= code < 300
        out.append({"title": step["title"], "status": "ok" if ok else "failed", "code": code, "message": "" if ok else _short(text)})
    return {"kind": kind, "dry_run": False, "results": out + failed, "target": result["target"]}


def _short(text: str) -> str:
    text = text.strip()
    try:
        data = json.loads(text)
        for key in ("message", "detail", "error", "messages"):
            if key in data:
                val = data[key]
                if isinstance(val, dict):
                    val = val.get("message") or json.dumps(val)
                if isinstance(val, list):
                    val = "; ".join(str(v.get("text", v)) if isinstance(v, dict) else str(v) for v in val)
                return str(val)[:400]
    except ValueError:
        pass
    return text[:400]


def _plan_splunk(rows, meta, settings, result):
    base = _base(settings.get("url"))
    app = urllib.parse.quote(settings.get("app") or "search")
    owner = urllib.parse.quote(settings.get("owner") or "nobody")
    headers = {**_auth(settings, "Bearer"), "Content-Type": "application/x-www-form-urlencoded"}
    prefix = settings.get("prefix", "Sigma - ")
    enable = bool(settings.get("enable"))
    plan = []
    for row in rows:
        info = meta.get(row["key"], {})
        name = f"{prefix}{row['title']}"
        search = row["queries"][0] if len(row["queries"]) == 1 else row["queries"][0] + "".join(f"\n| append [ search {q} ]" for q in row["queries"][1:])
        fields = {
            "search": search,
            "description": info.get("description", "")[:1000],
            "cron_schedule": settings.get("cron") or "*/15 * * * *",
            "dispatch.earliest_time": settings.get("earliest") or "-15m@m",
            "dispatch.latest_time": "now",
            "is_scheduled": "1",
            "disabled": "0" if enable else "1",
            "alert.track": "1",
            "alert.severity": str(SEVERITY_SPLUNK.get(info.get("level", "medium"), 4)),
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
        }
        create = urllib.parse.urlencode({"name": name, **fields}).encode()
        update = urllib.parse.urlencode(fields).encode()
        coll = f"{base}/servicesNS/{owner}/{app}/saved/searches"
        plan.append({
            "title": row["title"], "method": "POST", "url": coll + "?output_mode=json", "headers": headers, "body": create,
            "retry_update": {"method": "POST", "url": f"{coll}/{urllib.parse.quote(name, safe='')}?output_mode=json", "body": update},
        })
    return plan


def _plan_elastic(rows, meta, settings, result):
    base = _base(settings.get("url"))
    space = (settings.get("space") or "").strip()
    path = f"/s/{urllib.parse.quote(space)}" if space and space != "default" else ""
    headers = {**_auth(settings, "ApiKey"), "kbn-xsrf": "true"}
    enable = bool(settings.get("enable"))
    lines = []
    for row in rows:
        for q in row["queries"]:
            try:
                rule = json.loads(q)
            except ValueError:
                continue
            if isinstance(rule, dict):
                rule["enabled"] = enable
                lines.append(json.dumps(rule))
    if not lines:
        raise DeployError("The conversion did not give Kibana rules")
    boundary = "----sigmaforge" + uuid.uuid4().hex
    payload = ("\n".join(lines) + "\n").encode()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rules.ndjson\"\r\nContent-Type: application/ndjson\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    headers = {**headers, "Content-Type": f"multipart/form-data; boundary={boundary}"}
    return [{"title": f"{len(lines)} rules in one import", "method": "POST", "url": f"{base}{path}/api/detection_engine/rules/_import?overwrite=true", "headers": headers, "body": body}]


def _plan_sentinel(rows, meta, settings, result):
    sub = (settings.get("subscription") or "").strip()
    rg = (settings.get("resource_group") or "").strip()
    ws = (settings.get("workspace") or "").strip()
    if not (sub and rg and ws):
        raise DeployError("Add the subscription id, resource group and workspace name")
    token = (settings.get("token") or "").strip()
    if not token:
        raise DeployError("Add an Azure access token (az account get-access-token --resource https://management.azure.com)")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    enable = bool(settings.get("enable"))
    plan = []
    for row in rows:
        info = meta.get(row["key"], {})
        guid = _guid(info.get("id", ""), row["title"])
        query = row["queries"][0] if len(row["queries"]) == 1 else "\n| union ".join(f"({q})" for q in row["queries"])
        body = {
            "kind": "Scheduled",
            "properties": {
                "displayName": row["title"],
                "description": info.get("description", "")[:4900],
                "severity": SEVERITY_SENTINEL.get(info.get("level", "medium"), "Medium"),
                "enabled": enable,
                "query": query,
                "queryFrequency": settings.get("frequency") or "PT1H",
                "queryPeriod": settings.get("period") or "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False,
                "tactics": sorted({SENTINEL_TACTICS[t] for t in info.get("tactics", []) if t in SENTINEL_TACTICS}),
                "techniques": sorted({t.split(".")[0] for t in info.get("techniques", [])}),
            },
        }
        url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}"
               f"/providers/Microsoft.SecurityInsights/alertRules/{guid}?api-version=2023-02-01")
        plan.append({"title": row["title"], "method": "PUT", "url": url, "headers": headers, "body": json.dumps(body).encode()})
    return plan


def _plan_wazuh(rows, meta, settings, result):
    base = _base(settings.get("url"))
    filename = (settings.get("filename") or "sigma_forge_rules.xml").strip()
    if not filename.endswith(".xml") or "/" in filename or "\\" in filename:
        raise DeployError("The rules file name must end with .xml and have no folders")
    xml = result.get("bundle") or ""
    if not xml:
        raise DeployError("The conversion did not give a Wazuh rules file")
    user = (settings.get("username") or "").strip()
    token = (settings.get("token") or "").strip()
    if not token and not user:
        raise DeployError("Add the Wazuh API user and password, or a token")

    def prepare(step, verify):
        if token:
            step["headers"]["Authorization"] = f"Bearer {token}"
            return
        raw = base64.b64encode(f"{user}:{settings.get('password') or ''}".encode()).decode()
        code, text = _send("POST", f"{base}/security/user/authenticate", {"Authorization": f"Basic {raw}"}, None, verify)
        if code >= 300:
            raise DeployError(f"Wazuh login failed ({code}): {_short(text)}")
        try:
            jwt = json.loads(text)["data"]["token"]
        except (ValueError, KeyError, TypeError):
            raise DeployError("Wazuh login did not return a token")
        step["headers"]["Authorization"] = f"Bearer {jwt}"

    headers = {"Content-Type": "application/octet-stream", "Authorization": "Bearer <token from login>"}
    plan = [{"title": f"{len(rows)} rules in {filename}", "method": "PUT", "url": f"{base}/rules/files/{urllib.parse.quote(filename)}?overwrite=true",
             "headers": headers, "body": xml.encode(), "prepare": prepare}]
    if settings.get("restart"):
        plan.append({"title": "Restart the Wazuh manager", "method": "PUT", "url": f"{base}/manager/restart", "headers": headers, "body": None,
                     "prepare": lambda step, verify: step["headers"].update(plan[0]["headers"])})
    return plan
