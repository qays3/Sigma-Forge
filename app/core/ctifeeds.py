import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from app.core.ruletools import ioc_rules

MISP_TYPES = ["ip-dst", "ip-src", "ip-dst|port", "domain", "hostname", "url", "md5", "sha1", "sha256", "filename", "filename|sha256", "filename|md5"]
OTX_TYPES = {"IPv4", "IPv6", "domain", "hostname", "URL", "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "CIDR"}
MAX_IOCS = 20000


class FeedError(ValueError):
    pass


def _http(method: str, url: str, headers: Dict[str, str], body: bytes = None, verify: bool = True) -> Any:
    ctx = None
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as res:
            return json.loads(res.read(50 * 1048576).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{urllib.parse.urlsplit(url).netloc} said {exc.code}: {exc.read(300).decode('utf-8', 'replace')}")
    except urllib.error.URLError as exc:
        raise FeedError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}")
    except ValueError:
        raise FeedError("The feed did not answer with JSON")


def misp(url: str, key: str, days: int, tags: List[str], verify: bool = True) -> Tuple[List[str], List[str]]:
    base = (url or "").strip().rstrip("/")
    if not base.startswith(("http://", "https://")) or not key:
        raise FeedError("Add the MISP URL and an API key")
    body: Dict[str, Any] = {"returnFormat": "json", "type": MISP_TYPES, "to_ids": 1, "last": f"{days}d", "limit": MAX_IOCS, "deleted": False}
    if tags:
        body["tags"] = tags
    data = _http("POST", f"{base}/attributes/restSearch", {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}, json.dumps(body).encode(), verify)
    attrs = (data.get("response") or {}).get("Attribute", []) if isinstance(data, dict) else []
    values, sources = [], []
    for a in attrs:
        v = str(a.get("value", ""))
        t = a.get("type", "")
        if "|" in t and "|" in v:
            left, right = v.split("|", 1)
            values.extend([left, right] if t.startswith("filename") else [left])
        else:
            values.append(v)
        info = (a.get("Event") or {}).get("info")
        if info and info not in sources:
            sources.append(info)
    return values, sources


def otx(key: str, days: int) -> Tuple[List[str], List[str]]:
    if not key:
        raise FeedError("Add an OTX API key")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    values, sources = [], []
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&modified_since={since}"
    pages = 0
    while url and pages < 20 and len(values) < MAX_IOCS:
        data = _http("GET", url, {"X-OTX-API-KEY": key, "Accept": "application/json"})
        for pulse in data.get("results", []):
            if pulse.get("name") and pulse["name"] not in sources:
                sources.append(pulse["name"])
            for ind in pulse.get("indicators", []):
                if ind.get("type") in OTX_TYPES and ind.get("is_active", 1):
                    values.append(str(ind.get("indicator", "")))
        url = data.get("next")
        pages += 1
    return values, sources


def _expire(content: str, until: str, feed: str) -> str:
    lines = content.splitlines()
    out = []
    for line in lines:
        if line.startswith("description:"):
            line = line.rstrip() + f" Expires {until}."
        out.append(line)
    text = "\n".join(out)
    text = re.sub(r"^(date: .*)$", r"\1\nmodified: " + f"'{date.today().isoformat()}'", text, count=1, flags=re.M) if "modified:" not in text else text
    return text.rstrip("\n") + f"\nsf_expires: '{until}'\nsf_feed: {feed}\n"


def pull(source: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    days = max(1, min(int(settings.get("days") or 7), 90))
    keep = max(1, min(int(settings.get("expire_days") or 30), 365))
    if source == "misp":
        tags = [t.strip() for t in str(settings.get("tags") or "").split(",") if t.strip()][:20]
        values, sources = misp(settings.get("url", ""), settings.get("key", ""), days, tags, bool(settings.get("verify_tls", True)))
        feed = "misp"
    elif source == "otx":
        values, sources = otx(settings.get("key", ""), days)
        feed = "otx"
    else:
        raise FeedError("Pick MISP or OTX")
    values = list(dict.fromkeys(v.strip() for v in values if v and v.strip()))[:MAX_IOCS]
    if not values:
        raise FeedError(f"No indicators in the last {days} days")
    name = f"{feed}_{date.today().strftime('%Y%m%d')}"
    res = ioc_rules("\n".join(values), name)
    until = (date.today() + timedelta(days=keep)).isoformat()
    sigma = [{"name": f"cti/{feed}/{r['name']}", "content": _expire(r["content"], until, feed)} for r in res["sigma"]]
    yara = None
    if res.get("yara") and res["yara"].get("content"):
        yara = {"name": f"{name}.yar", "content": res["yara"]["content"].replace('author = "Sigma Forge"', f'author = "Sigma Forge"\n        expires = "{until}"')}
    return {"source": feed, "indicators": len(values), "counts": res["counts"], "sources": sources[:50], "sigma": sigma, "yara": yara, "expires": until, "skipped": len(res.get("skipped") or [])}


def expired(items, today: str = "") -> List[str]:
    today = today or date.today().isoformat()
    out = []
    for it in items:
        m = re.search(r"^sf_expires:\s*'?(\d{4}-\d{2}-\d{2})'?", it.content, flags=re.M)
        if m and m.group(1) < today:
            out.append(it.name)
    return out
