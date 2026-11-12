import base64
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

TARGETS = {
    "splunk_hec": "Splunk HTTP Event Collector",
    "elastic": "Elasticsearch bulk API",
    "syslog": "Syslog (Wazuh, QRadar, any collector)",
}
BATCH = 500
MAX_EVENTS = 50000


class SendError(ValueError):
    pass


def _ctx(verify: bool) -> Optional[ssl.SSLContext]:
    if verify:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post(url: str, body: bytes, headers: Dict[str, str], verify: bool):
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ctx(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise SendError(f"Could not reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}")


def _check_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise SendError("URL must start with http:// or https://")
    return url


def _epoch(ev: Dict[str, Any]) -> Optional[float]:
    for key in ("@timestamp", "timestamp", "UtcTime", "TimeCreated", "time", "eventTime", "_time"):
        v = ev.get(key)
        if isinstance(v, dict):
            v = v.get("#attributes", {}).get("SystemTime") or v.get("SystemTime")
        if not v:
            continue
        if isinstance(v, (int, float)):
            return v / 1000.0 if v > 1e11 else float(v)
        s = str(v).strip().replace("Z", "+00:00").replace(" ", "T", 1)
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        try:
            d = datetime.fromisoformat(s)
        except ValueError:
            try:
                d = datetime.fromisoformat(s[:19])
            except ValueError:
                continue
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.timestamp()
    return None


def _host(ev: Dict[str, Any]) -> str:
    for key in ("Computer", "host", "hostname", "ComputerName"):
        v = ev.get(key)
        if isinstance(v, dict):
            v = v.get("name")
        if v:
            return str(v)[:200]
    sys = ev.get("Event", {}).get("System", {}) if isinstance(ev.get("Event"), dict) else ev.get("System", {})
    if isinstance(sys, dict) and sys.get("Computer"):
        return str(sys["Computer"])[:200]
    return ""


def _splunk_payloads(events, index, sourcetype, source, when):
    out = []
    for i, ev in enumerate(events):
        item: Dict[str, Any] = {"event": ev, "sourcetype": sourcetype or "_json", "source": source or "sigma-forge"}
        if index:
            item["index"] = index
        t = when(i, ev)
        if t:
            item["time"] = round(t, 3)
        h = _host(ev)
        if h:
            item["host"] = h
        out.append(json.dumps(item, ensure_ascii=False, default=str))
    return out


def _syslog_line(ev: Dict[str, Any], app: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    host = (_host(ev) or socket.gethostname() or "-").replace(" ", "_")[:255]
    return f"<134>1 {ts} {host} {app or 'sigma-forge'} - - - " + json.dumps(ev, ensure_ascii=False, default=str, separators=(",", ":"))


def send(target: str, events: List[Dict[str, Any]], url: str = "", token: str = "", index: str = "", sourcetype: str = "",
         host: str = "", port: int = 514, protocol: str = "udp", verify_tls: bool = True, dry_run: bool = False, app_name: str = "sigma-forge", times: Optional[List[Optional[str]]] = None) -> Dict[str, Any]:
    if target not in TARGETS:
        raise SendError("Pick Splunk HEC, Elasticsearch or syslog")
    if not events:
        raise SendError("No events to send")
    events = events[:MAX_EVENTS]
    known = list(times or [])

    def when(i, ev):
        if i < len(known) and known[i]:
            try:
                return datetime.strptime(known[i][:23], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
            except ValueError:
                pass
        return _epoch(ev)

    started = time.monotonic()
    sent = 0
    failed = 0
    errors: List[str] = []
    preview: List[str] = []
    if target == "splunk_hec":
        url = _check_url(url)
        if "/services/collector" not in url:
            url += "/services/collector/event"
        if not dry_run and not token:
            raise SendError("Add the HEC token")
        lines = _splunk_payloads(events, index.strip(), sourcetype.strip(), "sigma-forge", when)
        preview = lines[:3]
        if not dry_run:
            for i in range(0, len(lines), BATCH):
                chunk = lines[i:i + BATCH]
                code, body = _post(url, "\n".join(chunk).encode(), {"Authorization": f"Splunk {token.strip()}", "Content-Type": "application/json"}, verify_tls)
                if code == 200:
                    sent += len(chunk)
                else:
                    failed += len(chunk)
                    errors.append(f"HTTP {code}: {body[:200].decode('utf-8', 'replace')}")
                    if code in (401, 403, 404):
                        break
    elif target == "elastic":
        url = _check_url(url)
        idx = (index or "sigma-forge-events").strip().lower()
        if not idx or any(c in idx for c in ' "*\\<|,>/?#'):
            raise SendError("Bad index name")
        bulk = f"{url}/{urllib.parse.quote(idx)}/_bulk" if not url.endswith("/_bulk") else url
        headers = {"Content-Type": "application/x-ndjson"}
        tok = token.strip()
        if tok:
            if tok.lower().startswith(("apikey ", "bearer ", "basic ")):
                headers["Authorization"] = tok
            elif ":" in tok:
                headers["Authorization"] = "Basic " + base64.b64encode(tok.encode()).decode()
            else:
                headers["Authorization"] = "ApiKey " + tok
        docs = []
        for i, ev in enumerate(events):
            d = dict(ev)
            t = when(i, ev)
            if t and "@timestamp" not in d:
                d["@timestamp"] = datetime.fromtimestamp(t, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            docs.append(json.dumps(d, ensure_ascii=False, default=str))
        preview = ['{"create":{}}\n' + d for d in docs[:3]]
        if not dry_run:
            for i in range(0, len(docs), BATCH):
                chunk = docs[i:i + BATCH]
                body = "".join('{"create":{}}\n' + d + "\n" for d in chunk).encode()
                code, raw = _post(bulk, body, headers, verify_tls)
                if code in (200, 201):
                    try:
                        res = json.loads(raw)
                    except ValueError:
                        res = {}
                    bad = [it for it in res.get("items", []) if (next(iter(it.values()), {}) or {}).get("error")]
                    failed += len(bad)
                    sent += len(chunk) - len(bad)
                    if bad:
                        err = next(iter(bad[0].values())).get("error")
                        errors.append(f"{len(bad)} documents rejected: {json.dumps(err)[:200]}")
                else:
                    failed += len(chunk)
                    errors.append(f"HTTP {code}: {raw[:200].decode('utf-8', 'replace')}")
                    if code in (401, 403, 404):
                        break
    else:
        host = (host or "").strip()
        if not host:
            raise SendError("Add the syslog host")
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise SendError("Port must be a number")
        if not 1 <= port <= 65535:
            raise SendError("Port must be 1 to 65535")
        proto = "tcp" if str(protocol).lower() == "tcp" else "udp"
        lines = [_syslog_line(ev, app_name) for ev in events]
        preview = lines[:3]
        if not dry_run:
            try:
                if proto == "udp":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        addr = (socket.gethostbyname(host), port)
                        for line in lines:
                            data = line.encode("utf-8")[:65000]
                            s.sendto(data, addr)
                            sent += 1
                else:
                    with socket.create_connection((host, port), timeout=10) as s:
                        for line in lines:
                            s.sendall(line.encode("utf-8") + b"\n")
                            sent += 1
            except OSError as exc:
                failed = len(lines) - sent
                errors.append(f"Syslog error: {exc}")
    return {
        "target": target,
        "target_name": TARGETS[target],
        "events": len(events),
        "sent": sent,
        "failed": failed,
        "dry_run": dry_run,
        "preview": [p[:2000] for p in preview],
        "errors": errors[:10],
        "seconds": round(time.monotonic() - started, 2),
    }
