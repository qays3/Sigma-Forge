import base64
import io
import json
import os
import re
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from app.config import MAX_LOG_BYTES, MAX_UNZIP_BYTES

PLATFORMS = {
    "splunk": {"name": "Splunk", "targets": ["splunk", "splunk_cim"], "live": True, "replay": True},
    "elastic": {"name": "Elasticsearch", "targets": ["elastic_lucene", "elastic_esql", "elastic_eql"], "live": True, "replay": True},
    "opensearch": {"name": "OpenSearch", "targets": ["opensearch_lucene"], "live": True, "replay": True},
    "wazuh": {"name": "Wazuh manager", "targets": ["wazuh"], "live": False, "replay": True},
    "sentinel": {"name": "Microsoft Sentinel", "targets": ["sentinel_asim", "azure_monitor"], "live": True, "replay": True},
}
SLOW_MS = 3000
TIMEOUT = 60
MAX_RULES = 500
MAX_EVENTS = 20000
JOBS: Dict[str, Dict[str, Any]] = {}
JOB_TTL = 3600
_lock = threading.Lock()


class FireError(ValueError):
    pass


def _ctx(verify: bool):
    if verify:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], verify: bool, timeout: int = TIMEOUT) -> Tuple[int, Any]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(verify)) as res:
            raw = res.read()
            code = res.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        code = exc.code
    except urllib.error.URLError as exc:
        raise FireError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}")
    except TimeoutError:
        raise FireError(f"{urllib.parse.urlsplit(url).netloc} did not answer in {timeout} seconds")
    text = raw.decode("utf-8", "replace")
    try:
        return code, json.loads(text) if text.strip() else {}
    except ValueError:
        return code, text


def _msg(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("messages", "error", "message", "detail"):
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return "; ".join(str(v.get("text", v)) if isinstance(v, dict) else str(v) for v in val)[:400]
                if isinstance(val, dict):
                    root = val.get("root_cause") or []
                    if root and isinstance(root, list):
                        return str(root[0].get("reason", root[0]))[:400]
                    return str(val.get("reason") or val.get("type") or val)[:400]
                return str(val)[:400]
    return str(data)[:400]


def _base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise FireError("URLs must start with http:// or https://")
    return url


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def flatten(obj: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        if all(not isinstance(v, (dict, list)) for v in obj):
            out.setdefault(prefix, [])
            if isinstance(out[prefix], list):
                out[prefix].extend(obj)
        else:
            for v in obj:
                flatten(v, prefix, out)
    elif prefix:
        out[prefix] = obj
    return out


def _windows_parts(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ev = raw.get("Event") if isinstance(raw.get("Event"), dict) else raw
    system = ev.get("System") if isinstance(ev.get("System"), dict) else {}
    data = ev.get("EventData") if isinstance(ev.get("EventData"), dict) else {}
    sysflat = {}
    for k, v in system.items():
        if isinstance(v, dict):
            attrs = v.get("#attributes") or {}
            if k == "Provider":
                sysflat["providerName"] = attrs.get("Name", "")
                if attrs.get("Guid"):
                    sysflat["providerGuid"] = attrs.get("Guid")
            elif k == "TimeCreated":
                sysflat["systemTime"] = attrs.get("SystemTime", "")
            elif "#text" in v:
                sysflat[k[0].lower() + k[1:]] = v["#text"]
            else:
                for ak, av in attrs.items():
                    sysflat[ak[0].lower() + ak[1:]] = av
        else:
            sysflat[k[0].lower() + k[1:]] = v
    dflat = {}
    items = data.get("Data") if isinstance(data.get("Data"), list) else None
    if items:
        for d in items:
            if isinstance(d, dict) and (d.get("#attributes") or {}).get("Name"):
                n = d["#attributes"]["Name"]
                dflat[n[0].lower() + n[1:]] = d.get("#text", "")
    else:
        for k, v in data.items():
            if not isinstance(v, (dict, list)):
                dflat[k[0].lower() + k[1:]] = v
    return sysflat, dflat


def _is_windows(raw: Dict[str, Any]) -> bool:
    ev = raw.get("Event") if isinstance(raw.get("Event"), dict) else raw
    return isinstance(ev, dict) and isinstance(ev.get("System"), dict)


def _channel(raw: Dict[str, Any]) -> str:
    sysflat, _ = _windows_parts(raw)
    return str(sysflat.get("channel") or "")


def load_records(files: List[Tuple[str, bytes]]) -> List[Dict[str, Any]]:
    from app.core.logtest import LogInputError, _expand_zip, _records_from_json_text, _strip_wrapper

    total = sum(len(d) for _, d in files)
    if total > MAX_LOG_BYTES:
        raise FireError(f"Log files are larger than {MAX_LOG_BYTES // 1048576} MB")
    budget = [MAX_UNZIP_BYTES]
    flat_files: List[Tuple[str, bytes]] = []
    for name, data in files:
        if name.lower().endswith(".zip") or data[:4] == b"PK\x03\x04":
            try:
                flat_files.extend(_expand_zip(name, data, budget))
            except LogInputError as exc:
                raise FireError(str(exc))
        else:
            flat_files.append((name, data))
    out: List[Dict[str, Any]] = []
    for name, data in flat_files:
        if name.lower().endswith(".evtx") or data[:8] == b"ElfFile\x00":
            try:
                from evtx import PyEvtxParser
            except ImportError:
                raise FireError("EVTX support needs the evtx package")
            handle, path = tempfile.mkstemp(suffix=".evtx")
            try:
                with os.fdopen(handle, "wb") as fh:
                    fh.write(data)
                xmls = [r.get("data", "") for r in PyEvtxParser(path).records()]
                jsons = []
                for r in PyEvtxParser(path).records_json():
                    try:
                        jsons.append(json.loads(r["data"]))
                    except (KeyError, ValueError):
                        jsons.append(None)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            for raw, xml in zip(jsons, xmls):
                if isinstance(raw, dict):
                    out.append({"raw": raw, "xml": xml, "source": name})
        else:
            try:
                text = data.decode("utf-8-sig")
                recs = _records_from_json_text(text)
            except (UnicodeDecodeError, LogInputError) as exc:
                if ":" in name:
                    continue
                raise FireError(f"{name}: {exc}")
            for rec in recs:
                rec = _strip_wrapper(rec)
                if isinstance(rec, dict):
                    rec = dict(rec)
                    rec.pop("logsource", None)
                    out.append({"raw": rec, "xml": None, "source": name})
        if len(out) > MAX_EVENTS:
            raise FireError(f"More than {MAX_EVENTS} events. Use a smaller sample for the fire check.")
    if not out:
        raise FireError("No events found in the files")
    return out


SPL_SKIP = {"index", "earliest", "latest", "search", "by", "as", "and", "or", "not", "in"}


def query_fields(language: str, query: str) -> List[str]:
    q = re.sub(r'"(?:[^"\\]|\\.)*"', '""', query) if language != "lucene" else query
    found: List[str] = []
    if language in ("spl", "spl2"):
        found = re.findall(r'(?<![\w."])([A-Za-z_][\w.{}\-]*)\s*(?:!=|<=|>=|=|<|>)', q)
        found += re.findall(r'(?<![\w."])([A-Za-z_][\w.{}\-]*)\s+IN\s*\(', q, flags=re.I)
    elif language == "lucene":
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', query)
        found = re.findall(r'(?:^|[\s(])([A-Za-z_@][\w.@\-]*):', stripped)
    elif language == "esql":
        body = re.sub(r"^\s*from\s+[^|]+", "", q, flags=re.I)
        found = re.findall(r'\(\s*([A-Za-z_@][\w.@]*)\s*,', body)
        found += re.findall(r'([A-Za-z_@][\w.@]*)\s*(?:==|!=|<=|>=|<|>|\s+(?:not\s+)?(?:like|rlike|in)\b)', body, flags=re.I)
    elif language == "eql":
        body = re.sub(r"^\s*\w+\s+where\s+", "", q)
        found = re.findall(r'([A-Za-z_@][\w.@]*)\s*(?:==|!=|<=|>=|<|>|:|\s+(?:like~?|in~?|regex~?)\b)', body)
    elif language == "xml":
        found = re.findall(r'<field name="([^"]+)"', query)
    elif language == "kql":
        body = re.sub(r"^\s*[A-Za-z_]\w*\s*\|", "", q)
        found = re.findall(r'([A-Za-z_][\w.]*)\s*(?:==|!=|=~|!~|<=|>=|<|>|\s+(?:!?endswith|!?startswith|!?contains|!?has|has_any|has_all|in~?|!in~?|matches regex|contains_cs|endswith_cs|startswith_cs|has_cs)\b)', body)
    out = []
    for f in found:
        if f.startswith("_") or f.lower() in SPL_SKIP or f.lower() in ("where", "from", "metadata", "_id", "_index", "_version", "any", "true", "false", "null", "tostring", "toint", "tolower"):
            continue
        if f not in out:
            out.append(f)
    return out


def literal_terms(language: str, query: str) -> List[Tuple[str, str]]:
    if language in ("spl", "spl2"):
        return [(f, v) for f, v in re.findall(r'(?<![\w."])([A-Za-z_][\w.{}\-]*)\s*=\s*"([^"*]*)"', query)] + \
               [(f, v) for f, v in re.findall(r'(?<![\w."])([A-Za-z_][\w.{}\-]*)\s*=\s*([^\s"()*]+)(?=[\s)]|$)', query)]
    if language == "esql":
        return re.findall(r'([A-Za-z_@][\w.@]*)\s*==\s*"([^"*]*)"', query)
    if language == "kql":
        return re.findall(r'([A-Za-z_][\w.]*)\s*(?:==|=~)\s*"([^"*]*)"', query)
    if language == "eql":
        return re.findall(r'([A-Za-z_@][\w.@]*)\s*(?:==|:)\s*"([^"*]*)"', query)
    return []


class Splunk:
    def __init__(self, s: Dict[str, Any]):
        self.api = _base(s.get("url"))
        self.verify = bool(s.get("verify_tls", True))
        self.index = (s.get("index") or "main").strip()
        if not re.match(r"^[\w\-*]+$", self.index):
            raise FireError("Bad index name")
        tok = (s.get("token") or "").strip()
        if not tok and not (s.get("username") or "").strip() and (s.get("password") or "").strip():
            tok = s["password"].strip()
        if tok:
            self.auth = f"Bearer {tok}"
        elif s.get("username"):
            self.auth = _basic(s["username"], s.get("password") or "")
        else:
            raise FireError("Add a Splunk token or user and password for the REST API (port 8089)")
        self.hec = (s.get("hec_url") or "").strip().rstrip("/")
        self.hec_token = (s.get("hec_token") or "").strip()
        self.sourcetype = (s.get("sourcetype") or "_json").strip()
        self.xml = bool(s.get("windows_xml", True))
        self.source_prefix = (s.get("source_prefix") or "XmlWinEventLog:").strip()

    def _search(self, spl: str, earliest: str = "0") -> Tuple[Optional[List[Dict[str, Any]]], str]:
        body = urllib.parse.urlencode({"search": spl, "exec_mode": "oneshot", "output_mode": "json", "earliest_time": earliest, "latest_time": "now", "count": 0}).encode()
        code, data = _http("POST", f"{self.api}/services/search/jobs", {"Authorization": self.auth, "Content-Type": "application/x-www-form-urlencoded"}, body, self.verify)
        if code >= 300:
            return None, f"Splunk said {code}: {_msg(data)}"
        if not isinstance(data, dict):
            return None, "Splunk did not answer with JSON"
        errs = [m.get("text", "") for m in data.get("messages", []) if m.get("type") in ("FATAL", "ERROR")]
        if errs:
            return None, "; ".join(errs)[:400]
        return data.get("results", []), ""

    def check(self) -> str:
        res, err = self._search(f"search index={self.index} | head 1 | stats count")
        return err

    def send(self, recs: List[Dict[str, Any]], run: str) -> int:
        if not self.hec or not self.hec_token:
            raise FireError("Add the HEC URL (port 8088) and HEC token to send events")
        url = _base(self.hec)
        if "/services/collector" not in url:
            url += "/services/collector/event"
        lines = []
        for r in recs:
            raw = r["raw"]
            item: Dict[str, Any] = {"index": self.index, "fields": {"sf_run": run}}
            ts = r.get("epoch")
            if ts:
                item["time"] = ts
            if r.get("xml") and self.xml:
                item["event"] = r["xml"]
                item["sourcetype"] = "XmlWinEventLog"
                item["source"] = self.source_prefix + (_channel(raw) or "Unknown")
            else:
                item["event"] = raw
                item["sourcetype"] = self.sourcetype
                item["source"] = (self.source_prefix + _channel(raw)) if _is_windows(raw) and _channel(raw) else "sigma-forge"
            host = (_windows_parts(raw)[0].get("computer") if _is_windows(raw) else raw.get("host")) or ""
            if host and isinstance(host, str):
                item["host"] = host
            lines.append(json.dumps(item, ensure_ascii=False, default=str))
        sent = 0
        for i in range(0, len(lines), 500):
            chunk = lines[i:i + 500]
            code, data = _http("POST", url, {"Authorization": f"Splunk {self.hec_token}", "Content-Type": "application/json"}, "\n".join(chunk).encode(), self.verify)
            if code >= 300:
                raise FireError(f"HEC said {code}: {_msg(data)}")
            sent += len(chunk)
        return sent

    def scope(self, run: Optional[str]) -> str:
        return f"index={self.index}" + (f" sf_run::{run}" if run else "")

    def wait(self, run: str, n: int, limit: int = 90) -> int:
        end = time.monotonic() + limit
        got = 0
        while time.monotonic() < end:
            res, err = self._search(f"search {self.scope(run)} | stats count")
            if err:
                raise FireError(err)
            got = int((res or [{}])[0].get("count", 0) or 0)
            if got >= n:
                return got
            time.sleep(3)
        return got

    def count(self, query: str, run: Optional[str], hours: float) -> Tuple[Optional[int], str]:
        q = query.strip()
        if q.startswith("|"):
            return None, "Queries that start with a pipe (tstats, data models) are not run by the fire check"
        q = re.sub(r"^\s*search\s+", "", q)
        res, err = self._search(f"search {self.scope(run)} {q} | stats count", "0" if run else f"-{int(hours * 60)}m")
        if err:
            return None, err
        return int((res or [{}])[0].get("count", 0) or 0), ""

    def inventory(self, run: Optional[str], hours: float) -> Dict[str, List[str]]:
        res, err = self._search(f"search {self.scope(run)} | head 2000 | fieldsummary maxvals=60 | table field values distinct_count", "0" if run else f"-{int(hours * 60)}m")
        if err:
            raise FireError(err)
        out: Dict[str, List[str]] = {}
        for row in res or []:
            vals = []
            try:
                vals = [str(v.get("value")) for v in json.loads(row.get("values") or "[]")]
            except (ValueError, AttributeError):
                vals = []
            out[str(row.get("field"))] = vals
        for meta in ("source", "sourcetype", "host", "index"):
            out.setdefault(meta, [])
        return out


class Elastic:
    def __init__(self, s: Dict[str, Any], opensearch: bool = False):
        self.url = _base(s.get("url"))
        self.verify = bool(s.get("verify_tls", True))
        self.opensearch = opensearch
        self.index = (s.get("index") or "sigma-forge-firecheck").strip()
        self.live_index = (s.get("live_index") or "logs-*,winlogbeat-*").strip()
        self.pipeline = (s.get("pipeline") or "").strip()
        for ix in [self.index] + self.live_index.split(","):
            if not re.match(r"^[a-z0-9_.\-*]+$", ix.strip()):
                raise FireError(f"Bad index name: {ix}")
        tok = (s.get("token") or "").strip()
        if tok:
            self.auth = tok if tok.lower().startswith(("apikey ", "bearer ", "basic ")) else f"ApiKey {tok}"
        elif s.get("username"):
            self.auth = _basic(s["username"], s.get("password") or "")
        else:
            self.auth = ""

    def _h(self, ctype: str = "application/json") -> Dict[str, str]:
        h = {"Content-Type": ctype}
        if self.auth:
            h["Authorization"] = self.auth
        return h

    def check(self) -> str:
        code, data = _http("GET", f"{self.url}/", self._h(), None, self.verify)
        return "" if code < 300 else f"Login failed ({code}): {_msg(data)}"

    def send(self, recs: List[Dict[str, Any]], run: str) -> int:
        sent = 0
        params = "?refresh=wait_for" + (f"&pipeline={urllib.parse.quote(self.pipeline)}" if self.pipeline else "")
        for i in range(0, len(recs), 500):
            chunk = recs[i:i + 500]
            body = ""
            for r in chunk:
                doc = dict(r["raw"])
                doc["sf_run"] = run
                if r.get("epoch") and "@timestamp" not in doc:
                    doc["@timestamp"] = datetime.fromtimestamp(r["epoch"], tz=timezone.utc).isoformat().replace("+00:00", "Z")
                body += '{"create":{}}\n' + json.dumps(doc, ensure_ascii=False, default=str) + "\n"
            code, data = _http("POST", f"{self.url}/{self.index}/_bulk{params}", self._h("application/x-ndjson"), body.encode(), self.verify)
            if code >= 300:
                raise FireError(f"Bulk said {code}: {_msg(data)}")
            bad = [it for it in (data.get("items") or []) if (next(iter(it.values()), {}) or {}).get("error")] if isinstance(data, dict) else []
            if bad and len(bad) == len(chunk):
                raise FireError("Every document was rejected: " + json.dumps(next(iter(bad[0].values())).get("error"))[:300])
            sent += len(chunk) - len(bad)
        return sent

    def wait(self, run: str, n: int, limit: int = 30) -> int:
        end = time.monotonic() + limit
        got = 0
        while time.monotonic() < end:
            code, data = _http("POST", f"{self.url}/{self.index}/_count", self._h(), json.dumps({"query": {"match_phrase": {"sf_run": run}}}).encode(), self.verify)
            if code < 300 and isinstance(data, dict):
                got = int(data.get("count", 0))
                if got >= n:
                    return got
            time.sleep(1)
        return got

    def _filter(self, run: Optional[str], hours: float) -> Dict[str, Any]:
        if run:
            return {"match_phrase": {"sf_run": run}}
        return {"range": {"@timestamp": {"gte": f"now-{int(hours * 60)}m"}}}

    def count(self, query: str, language: str, run: Optional[str], hours: float) -> Tuple[Optional[int], str]:
        index = self.index if run else self.live_index
        if language == "lucene":
            body = {"query": {"bool": {"filter": [{"query_string": {"query": query, "analyze_wildcard": True}}, self._filter(run, hours)]}}}
            code, data = _http("POST", f"{self.url}/{index}/_count", self._h(), json.dumps(body).encode(), self.verify)
            if code >= 300:
                return None, f"Search said {code}: {_msg(data)}"
            return int(data.get("count", 0)), ""
        if language == "eql":
            body = {"query": query, "filter": self._filter(run, hours), "size": 100}
            code, data = _http("POST", f"{self.url}/{index}/_eql/search", self._h(), json.dumps(body).encode(), self.verify)
            if code >= 300:
                return None, f"EQL said {code}: {_msg(data)}"
            hits = data.get("hits", {}) if isinstance(data, dict) else {}
            return len(hits.get("events") or hits.get("sequences") or []), ""
        if language == "esql":
            q = re.sub(r"^\s*from\s+\S+(\s+metadata[^|]*)?", f"from {index}", query.strip(), flags=re.I)
            q += f' | where sf_run.keyword == "{run}"' if run else f" | where @timestamp > now() - {int(hours * 60)} minutes"
            q += " | stats c = count(*)"
            code, data = _http("POST", f"{self.url}/_query", self._h(), json.dumps({"query": q}).encode(), self.verify)
            if code >= 300:
                return None, f"ES|QL said {code}: {_msg(data)}"
            vals = data.get("values") or [[0]]
            return int(vals[0][0] or 0), ""
        return None, f"{language} queries are not run by the fire check"

    def inventory(self, run: Optional[str], hours: float) -> Dict[str, List[str]]:
        index = self.index if run else self.live_index
        out: Dict[str, List[str]] = {}
        code, data = _http("GET", f"{self.url}/{index}/_field_caps?fields=*", self._h(), None, self.verify)
        if code < 300 and isinstance(data, dict):
            for f in (data.get("fields") or {}):
                if not f.startswith("_"):
                    out.setdefault(f, [])
        body = {"size": 500, "query": {"bool": {"filter": [self._filter(run, hours)]}}}
        code, data = _http("POST", f"{self.url}/{index}/_search", self._h(), json.dumps(body).encode(), self.verify)
        if code >= 300:
            raise FireError(f"Search said {code}: {_msg(data)}")
        for hit in (data.get("hits") or {}).get("hits", []):
            for k, v in flatten(hit.get("_source") or {}).items():
                vals = out.setdefault(k, [])
                for x in (v if isinstance(v, list) else [v]):
                    s = str(x)
                    if len(vals) < 60 and s not in vals:
                        vals.append(s)
        return out


class ElasticRules(Elastic):
    def __init__(self, s: Dict[str, Any]):
        super().__init__(s, False)
        self.kibana = _base(s.get("kibana_url"))
        space = (s.get("space") or "").strip()
        self.space = f"/s/{urllib.parse.quote(space)}" if space and space != "default" else ""

    def count(self, query: str, language: str, run: Optional[str], hours: float) -> Tuple[Optional[int], str]:
        kind = {"lucene": "query", "eql": "eql", "esql": "esql"}.get(language)
        if not kind:
            return None, f"{language} rules are not previewed"
        index = self.index if run else self.live_index
        body: Dict[str, Any] = {"type": kind, "language": {"query": "lucene", "eql": "eql", "esql": "esql"}[kind], "name": "Sigma Forge fire check",
                                "description": "Sigma Forge fire check preview", "risk_score": 21, "severity": "low", "interval": "5m",
                                "from": f"now-{max(int(hours * 60), 60 * 24 * 30) if run else int(hours * 60)}m", "invocationCount": 1,
                                "timeframeEnd": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        if kind == "esql":
            q = re.sub(r"^\s*from\s+\S+(\s+metadata[^|]*)?", f"from {index} metadata _id, _index, _version", query.strip(), flags=re.I)
            body["query"] = q + (f' | where sf_run.keyword == "{run}"' if run else "")
        else:
            body["query"] = query
            body["index"] = index.split(",")
            if run:
                body["filters"] = [{"meta": {"disabled": False, "negate": False}, "query": {"match_phrase": {"sf_run": run}}}]
        headers = {**self._h(), "kbn-xsrf": "true", "elastic-api-version": "2023-10-31"}
        code, data = _http("POST", f"{self.kibana}{self.space}/api/detection_engine/rules/preview", headers, json.dumps(body).encode(), self.verify, timeout=120)
        if code >= 300:
            return None, f"Kibana rule preview said {code}: {_msg(data)}"
        errs = [e for log in (data.get("logs") or []) for e in (log.get("errors") or [])] if isinstance(data, dict) else []
        if errs:
            return None, "Rule preview error: " + "; ".join(map(str, errs))[:400]
        pid = data.get("previewId")
        if not pid:
            return None, "Kibana did not return a preview id"
        cbody = {"query": {"term": {"kibana.alert.rule.uuid": pid}}}
        code, data = _http("POST", f"{self.url}/.preview.alerts-security.alerts-*/_count", self._h(), json.dumps(cbody).encode(), self.verify)
        if code >= 300:
            return None, f"Could not count preview alerts ({code}): {_msg(data)}"
        return int(data.get("count", 0)), ""


class Sentinel:
    def __init__(self, s: Dict[str, Any]):
        self.workspace = (s.get("workspace_id") or "").strip()
        if not re.match(r"^[0-9a-fA-F-]{36}$", self.workspace):
            raise FireError("Add the Log Analytics workspace id (a GUID)")
        self.verify = True
        self.tenant = (s.get("tenant_id") or "").strip()
        self.client = (s.get("client_id") or "").strip()
        self.secret = s.get("client_secret") or ""
        self.query_token = (s.get("query_token") or "").strip()
        self.ingest_token = (s.get("ingest_token") or "").strip()
        self.dce = (s.get("dce") or "").strip().rstrip("/")
        self.dcr = (s.get("dcr_id") or "").strip()
        self.stream = (s.get("stream") or "Custom-SigmaForge_CL").strip()
        self.table = (s.get("table") or "SigmaForge_CL").strip()
        self.live_table = (s.get("live_table") or "SecurityEvent").strip()
        for t in (self.table, self.live_table, self.stream):
            if not re.match(r"^[\w\-]+$", t):
                raise FireError(f"Bad table or stream name: {t}")
        if not self.query_token and not (self.tenant and self.client and self.secret):
            raise FireError("Add an app registration (tenant, client id, secret) or paste access tokens")

    def _token(self, scope: str) -> str:
        code, data = _http("POST", f"https://login.microsoftonline.com/{urllib.parse.quote(self.tenant)}/oauth2/v2.0/token",
                           {"Content-Type": "application/x-www-form-urlencoded"},
                           urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client, "client_secret": self.secret, "scope": scope}).encode(), True)
        if code >= 300 or not isinstance(data, dict) or "access_token" not in data:
            raise FireError(f"Azure sign in failed ({code}): {_msg(data)}")
        return data["access_token"]

    def _q(self, kql: str, timespan: str = "P30D") -> Tuple[Optional[Dict[str, Any]], str]:
        if not self.query_token:
            self.query_token = self._token("https://api.loganalytics.io/.default")
        code, data = _http("POST", f"https://api.loganalytics.io/v1/workspaces/{self.workspace}/query",
                           {"Authorization": f"Bearer {self.query_token}", "Content-Type": "application/json"}, json.dumps({"query": kql, "timespan": timespan}).encode(), True, timeout=120)
        if code >= 300:
            return None, f"Log Analytics said {code}: {_msg(data)}"
        tables = (data or {}).get("tables") or []
        if not tables:
            return None, "Log Analytics returned no table"
        t = tables[0]
        cols = [c["name"] for c in t.get("columns", [])]
        return {"columns": cols, "rows": t.get("rows", [])}, ""

    def check(self) -> str:
        res, err = self._q("print ok = 1", "PT1H")
        return err

    def send(self, recs: List[Dict[str, Any]], run: str) -> int:
        if not self.dce or not self.dcr:
            raise FireError("Add the data collection endpoint and the DCR immutable id to send events")
        if not self.ingest_token:
            self.ingest_token = self._token("https://monitor.azure.com/.default")
        url = f"{_base(self.dce)}/dataCollectionRules/{urllib.parse.quote(self.dcr)}/streams/{urllib.parse.quote(self.stream)}?api-version=2023-01-01"
        rows = []
        for r in recs:
            raw = r["raw"]
            if _is_windows(raw):
                sysflat, dflat = _windows_parts(raw)
                row = {k[0].upper() + k[1:]: v for k, v in dflat.items()}
                row.update({"EventID": sysflat.get("eventID"), "Computer": sysflat.get("computer"), "Channel": sysflat.get("channel"), "Provider": sysflat.get("providerName")})
            else:
                row = flatten(raw)
            row["sf_run"] = run
            row["TimeGenerated"] = datetime.fromtimestamp(r.get("epoch") or time.time(), tz=timezone.utc).isoformat().replace("+00:00", "Z")
            rows.append(row)
        sent = 0
        for i in range(0, len(rows), 300):
            chunk = rows[i:i + 300]
            code, data = _http("POST", url, {"Authorization": f"Bearer {self.ingest_token}", "Content-Type": "application/json"}, json.dumps(chunk, default=str).encode(), True)
            if code >= 300:
                raise FireError(f"Logs Ingestion API said {code}: {_msg(data)}")
            sent += len(chunk)
        return sent

    def wait(self, run: str, n: int, limit: int = 600) -> int:
        end = time.monotonic() + limit
        got = 0
        while time.monotonic() < end:
            res, err = self._q(f'{self.table} | where sf_run == "{run}" | count', "P1D")
            if err:
                raise FireError(err)
            got = int((res["rows"] or [[0]])[0][0] or 0)
            if got >= n:
                return got
            time.sleep(15)
        return got

    def _wrap(self, query: str, run: Optional[str], hours: float) -> str:
        q = query.strip()
        table = self.table if run else self.live_table
        m = re.match(r"^([A-Za-z_]\w*)\s*\|(.*)$", q, flags=re.S)
        if m:
            body = f"{table if run else m.group(1)} |{m.group(2)}"
        else:
            body = f"{table} | where {q}"
        body += f' | where sf_run == "{run}"' if run else f" | where TimeGenerated > ago({int(hours * 60)}m)"
        return body

    def count(self, query: str, run: Optional[str], hours: float) -> Tuple[Optional[int], str]:
        res, err = self._q(self._wrap(query, run, hours) + " | count", "P30D" if run else f"PT{max(1, int(hours))}H")
        if err:
            return None, err
        return int((res["rows"] or [[0]])[0][0] or 0), ""

    def inventory(self, run: Optional[str], hours: float) -> Dict[str, List[str]]:
        kql = f'{self.table} | where sf_run == "{run}" | take 500' if run else f"{self.live_table} | where TimeGenerated > ago({int(hours * 60)}m) | take 500"
        res, err = self._q(kql)
        if err:
            raise FireError(err)
        out: Dict[str, List[str]] = {c: [] for c in res["columns"]}
        for row in res["rows"]:
            for c, v in zip(res["columns"], row):
                if v in (None, ""):
                    continue
                vals = out[c]
                if len(vals) < 60 and str(v) not in vals:
                    vals.append(str(v))
        return out


class Wazuh:
    def __init__(self, s: Dict[str, Any]):
        self.url = _base(s.get("url"))
        self.verify = bool(s.get("verify_tls", True))
        self.user = (s.get("username") or "").strip()
        self.password = s.get("password") or ""
        self.token = (s.get("token") or "").strip()
        self.log_format = (s.get("log_format") or "eventchannel").strip()
        self.location = (s.get("location") or "EventChannel").strip()
        self.session = ""
        if not self.token and not self.user:
            raise FireError("Add the Wazuh API user and password (port 55000)")

    def login(self) -> str:
        if self.token:
            return self.token
        code, data = _http("POST", f"{self.url}/security/user/authenticate", {"Authorization": _basic(self.user, self.password)}, None, self.verify)
        if code >= 300:
            raise FireError(f"Wazuh login failed ({code}): {_msg(data)}")
        try:
            self.token = data["data"]["token"]
        except (KeyError, TypeError):
            raise FireError("Wazuh login did not return a token")
        return self.token

    def check(self) -> str:
        try:
            self.login()
        except FireError as exc:
            return str(exc)
        return ""

    def shape(self, raw: Dict[str, Any]) -> Tuple[str, str, str]:
        if _is_windows(raw):
            sysflat, dflat = _windows_parts(raw)
            if "eventID" in sysflat:
                sysflat["eventID"] = str(sysflat["eventID"])
            doc = {"win": {"system": {k: str(v) for k, v in sysflat.items()}, "eventdata": {k: str(v) for k, v in dflat.items()}}}
            return json.dumps(doc, ensure_ascii=False), self.log_format, self.location
        return json.dumps(raw, ensure_ascii=False, default=str), "json", "sigma-forge"

    def logtest(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        tok = self.login()
        event, fmt, loc = self.shape(raw)
        body = {"event": event, "log_format": fmt, "location": loc}
        if self.session:
            body["token"] = self.session
        code, data = _http("PUT", f"{self.url}/logtest", {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}, json.dumps(body).encode(), self.verify)
        if code >= 300:
            raise FireError(f"Wazuh logtest said {code}: {_msg(data)}")
        d = (data or {}).get("data") or {}
        self.session = d.get("token") or self.session
        return d.get("output") or {}


def _epoch(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts[:23], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def resolve(settings: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in (settings or {}).items():
        if isinstance(v, str) and v.startswith("env:"):
            name = v[4:].strip()
            if not re.match(r"^[A-Z_][A-Z0-9_]*$", name):
                raise FireError(f"Bad environment variable name for {k}")
            val = os.environ.get(name)
            if val is None:
                raise FireError(f"Environment variable {name} for {k} is not set")
            out[k] = val
        else:
            out[k] = v
    return out


def _client(platform: str, settings: Dict[str, Any]):
    settings = resolve(settings)
    if platform == "splunk":
        return Splunk(settings)
    if platform == "elastic" and (settings.get("kibana_url") or "").strip() and settings.get("use_rules"):
        return ElasticRules(settings)
    if platform in ("elastic", "opensearch"):
        return Elastic(settings, platform == "opensearch")
    if platform == "sentinel":
        return Sentinel(settings)
    if platform == "wazuh":
        return Wazuh(settings)
    raise FireError("Pick Splunk, Elasticsearch, OpenSearch, Sentinel or Wazuh")


def _rule_values(rule, events: List[Dict[str, Any]], rows: List[int]) -> Dict[str, List[str]]:
    from app.core.logtest import _rule_fields

    out: Dict[str, List[str]] = {}
    for f in _rule_fields(rule):
        vals = []
        for i in rows[:20]:
            v = (events[i].get("values") or {}).get(f.lower())
            if v not in (None, "") and str(v) not in vals:
                vals.append(str(v))
        if vals:
            out[f] = vals[:5]
    return out


def _find_value(inventory: Dict[str, List[str]], value: str) -> List[str]:
    v = value.strip().lower()
    if not v:
        return []
    exact = [f for f, vals in inventory.items() if any(str(x).strip().lower() == v for x in vals)]
    if exact:
        return exact[:4]
    tail = v.replace("/", "\\").split("\\")[-1]
    if len(tail) >= 4 and tail != v:
        return [f for f, vals in inventory.items() if any(str(x).strip().lower().endswith(tail) for x in vals)][:4]
    return []


PROBE = "sfprobe7"
ROUTING = {"source", "sourcetype", "eventcode", "eventid", "event.code", "winlog.channel", "channel", "event.dataset", "event.module",
           "event.provider", "winlog.provider_name", "log_name", "provider_name", "data_stream.dataset", "service"}


@lru_cache(maxsize=4096)
def probe(target: str, product: str, category: str, service: str, field: str) -> str:
    from app.core.converter import convert
    from app.schemas import ConvertOptions, RuleInput

    ls = "".join(f"\n    {k}: {v}" for k, v in (("product", product), ("category", category), ("service", service)) if v)
    if not re.match(r"^[A-Za-z0-9_.\-]+$", field):
        return ""
    text = f"title: probe\nlogsource:{ls}\ndetection:\n    selection:\n        {field}: {PROBE}\n    condition: selection\n"
    try:
        res = convert([RuleInput(name="probe.yml", content=text)], target, "default", ConvertOptions())
    except Exception:
        return ""
    row = (res.get("results") or [{}])[0]
    q = (row.get("queries") or [""])[0] if not row.get("error") else ""
    if target == "wazuh":
        q = res.get("bundle") or ""
    for rx in (r'([A-Za-z_@][\w.@{}\-]*)\s*(?:==|=|:)\s*"?\(?\*?' + PROBE, r'<field name="([^"]+)"[^>]*>[^<]*' + PROBE):
        m = re.search(rx, q, flags=re.I)
        if m:
            return m.group(1)
    return ""


def diagnose(language: str, query: str, inventory: Dict[str, List[str]], sigma_values: Dict[str, List[str]], target: str = "", logsource=None, field_map=None) -> Dict[str, Any]:
    fields = query_fields(language, query)
    lower = {k.lower(): k for k in inventory}

    def has(f):
        return f in inventory or (f.endswith(".caseless") and f[:-9] in inventory)

    missing, case = [], []
    for f in fields:
        if has(f):
            continue
        if f.lower() in lower:
            case.append({"field": f, "seen": lower[f.lower()]})
        else:
            missing.append(f)
    values = []
    for f, v in literal_terms(language, query):
        if f.lower() not in ROUTING:
            continue
        if f in inventory and inventory[f] and len(inventory[f]) < 60:
            if not any(str(x).lower() == v.lower() for x in inventory[f]) and not any(x["field"] == f for x in values):
                values.append({"field": f, "want": v, "seen": inventory[f][:5]})
    norm = lambda x: re.sub(r"[^a-z0-9]", "", x.lower())
    hints = []
    mapping: Dict[str, str] = {}
    aliases: Dict[str, str] = {}
    ls = logsource or {}
    for sf, vals in sigma_values.items():
        src = (field_map or {}).get(sf, sf)
        qf = probe(target, ls.get("product", ""), ls.get("category", ""), ls.get("service", ""), src) if target else src
        qf = qf or sf
        score: Dict[str, float] = {}
        for v in vals:
            for c in _find_value(inventory, v):
                score[c] = score.get(c, 0) + 1
        if not score:
            hints.append({"sigma_field": sf, "query_field": qf, "value": vals[0][:160], "fields": [], "ok": has(qf)})
            continue
        for c in score:
            tail = norm(c.split(".")[-1])
            if tail in (norm(sf), norm(qf.split(".")[-1])):
                score[c] += 10
            elif norm(sf) in norm(c) or (tail and tail in norm(sf)):
                score[c] += 4
        cands = sorted(score, key=lambda c: (-score[c], len(c)))[:4]
        ok = has(qf)
        hints.append({"sigma_field": sf, "query_field": qf, "value": vals[0][:160], "fields": cands, "ok": ok})
        if not ok and cands[0] != qf:
            mapping[sf] = cands[0]
            aliases[qf[:-9] if qf.endswith(".caseless") else qf] = cands[0]
    for f, v in literal_terms(language, query):
        if f in missing and f not in aliases:
            cands = [c for c in _find_value(inventory, v) if norm(f.split(".")[-1]) in norm(c) or norm(c.split(".")[-1]) in norm(f) or norm(c.split(".")[-1]) in ("eventid", "code", "eventcode")]
            if cands:
                aliases[f] = sorted(cands, key=len)[0]
    return {"fields": fields, "missing": missing, "case": case, "values": values, "hints": hints, "mapping": mapping, "aliases": aliases}


def _ls(pr) -> Dict[str, str]:
    if pr is None or pr.rule is None:
        return {}
    ls = pr.rule.logsource
    return {"product": ls.product or "", "category": ls.category or "", "service": ls.service or ""}


def _lang(target_id: str) -> str:
    from app.core.targets import TARGET_MAP

    t = TARGET_MAP.get(target_id)
    return getattr(t, "language", "") if t else ""


def _wazuh_ids(bundle: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rid, block in re.findall(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', bundle or "", flags=re.S):
        m = re.search(r"<description>Sigma: (.*?)</description>", block, flags=re.S)
        if m:
            title = m.group(1).strip()
            out.setdefault(title.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">"), []).append(rid)
    return out


def run(job: Dict[str, Any]) -> None:
    from app.core.converter import convert
    from app.core.logtest import run_test
    from app.core.parsing import parse_inputs
    from app.schemas import ConvertOptions

    p = job["params"]
    platform, target, mode = p["platform"], p["target"], p["mode"]
    items, settings, mapping, hours = p["rules"], p["settings"], p.get("mapping") or {}, float(p.get("hours") or 24)
    files = list(p.get("files") or [])

    def stage(text, done=0, total=0):
        job.update(stage=text, done=done, total=total)

    try:
        client = _client(platform, settings)
        stage("Signing in")
        err = client.check()
        if err:
            raise FireError(err)
        stage("Converting rules")
        opts = ConvertOptions(splunk_windows_source=settings.get("splunk_windows_source") or "") if platform == "splunk" else ConvertOptions()
        conv = convert(items, target, "default", opts, mapping)
        lang = _lang(target)
        rows = conv["results"][:MAX_RULES]
        parsed = {pr.key: pr for pr in parse_inputs(items)}
        expected: Dict[str, List[int]] = {}
        events: List[Dict[str, Any]] = []
        run_id = None
        sent = 0
        if mode == "replay" and p.get("attack"):
            from app.core.attack import split_attack_tags
            from app.core.attacklogs import generate

            tids = []
            for pr in parsed.values():
                if pr.rule is not None:
                    tids.extend(split_attack_tags(pr.rule.tags)[0])
            gen = generate(sorted(set(tids)) if p["attack"] == "rules" else p["attack"])
            if gen["events"]:
                files.append(("attack_logs.jsonl", gen["jsonl"].encode()))
                job["attack_techniques"] = gen["techniques"]
        if mode == "replay":
            if not files:
                raise FireError("No logs to replay. None of these rules use a technique that has built in attack logs.")
            stage("Reading the logs")
            recs = load_records(files)
            stage("Running the Sigma rules locally on the same logs")
            local = run_test(items, files, "auto", max_samples=0, options=ConvertOptions(), keep_rows=True)
            from app.core.logtest import LogDatabase, load_events

            events = load_events(files)
            LogDatabase(events)
            for i, r in enumerate(recs):
                r["epoch"] = _epoch(events[i].get("ts")) if i < len(events) else None
            for e in local["results"]:
                expected[e["key"]] = e.get("rows") or []
            run_id = "sf" + uuid.uuid4().hex[:12]
            job["run_id"] = run_id
            if platform == "splunk":
                job["stanza"] = "XmlWinEventLog" if client.xml and any(r.get("xml") for r in recs) else client.sourcetype
            if platform != "wazuh":
                stage(f"Sending {len(recs)} events", 0, len(recs))
                sent = client.send(recs, run_id)
                stage("Waiting for the events to be searchable")
                indexed = client.wait(run_id, sent)
                job["indexed"] = indexed
                if indexed == 0:
                    raise FireError("The events were sent but none can be found. Check the index name and that the token can write to it.")
        results = []
        if platform == "wazuh":
            if mode != "replay":
                raise FireError("Wazuh is checked with replay through logtest")
            ids = _wazuh_ids(conv.get("bundle") or "")
            fired_by_event: List[str] = []
            inventory: Dict[str, List[str]] = {}
            for n, r in enumerate(recs):
                if n % 20 == 0:
                    stage("Running events through Wazuh logtest", n, len(recs))
                out = client.logtest(r["raw"])
                fired_by_event.append(str((out.get("rule") or {}).get("id") or ""))
                for k, v in flatten(out.get("data") or {}).items():
                    vals = inventory.setdefault(k, [])
                    for x in (v if isinstance(v, list) else [v]):
                        if len(vals) < 60 and str(x) not in vals:
                            vals.append(str(x))
            sent = len(recs)
            for row in rows:
                rid = ids.get(row["title"], [])
                exp = expected.get(row["key"], [])
                got_events = [i for i, fid in enumerate(fired_by_event) if fid in rid]
                hidden = [i for i in exp if i not in got_events and fired_by_event[i] and fired_by_event[i] not in rid]
                entry = _entry(row, lang, len(exp), len(got_events), row["error"] or ("" if rid else "Rule not in the converted Wazuh file"))
                entry["wazuh_ids"] = rid
                if hidden and not got_events and len(hidden) == len(exp):
                    entry["verdict"] = "hidden"
                    entry["note"] = f"Wazuh matched {len(hidden)} of its events to another rule first. Logtest shows one rule per event, so this rule could not be seen."
                elif hidden and not got_events:
                    entry["note"] = f"{len(hidden)} events matched other rules first"
                if entry["verdict"] in ("silent", "partial"):
                    pr = parsed.get(row["key"])
                    entry["diagnosis"] = diagnose(lang, row["queries"][0] if row["queries"] else "", inventory, _rule_values(pr.rule if pr else None, events, exp), target, _ls(pr), mapping)
                results.append(entry)
        else:
            stage("Reading field names from the platform")
            inventory = client.inventory(run_id, hours)
            total = len(rows)
            for n, row in enumerate(rows):
                stage("Running the converted queries", n, total)
                exp = expected.get(row["key"], [])
                if row["error"] or not row["queries"]:
                    e = _entry(row, lang, len(exp), None, row["error"] or "Used only inside a correlation rule, so it has no query of its own")
                    if not row["error"]:
                        e["verdict"] = "skipped"
                    results.append(e)
                    continue
                got_total = 0
                errors = []
                started = time.monotonic()
                for q in row["queries"]:
                    if platform in ("splunk", "sentinel"):
                        got, e = client.count(q, run_id, hours)
                    else:
                        got, e = client.count(q, lang, run_id, hours)
                    if e:
                        errors.append(e)
                    else:
                        got_total += got or 0
                entry = _entry(row, lang, len(exp) if mode == "replay" else None, None if errors and not got_total else got_total, errors[0] if errors and not got_total else "")
                entry["ms"] = int((time.monotonic() - started) * 1000)
                if entry["verdict"] in ("silent", "partial", "no_data"):
                    pr = parsed.get(row["key"])
                    entry["diagnosis"] = diagnose(lang, row["queries"][0], inventory, _rule_values(pr.rule if pr else None, events, exp) if mode == "replay" else {}, target, _ls(pr), mapping)
                results.append(entry)
        order = {"silent": 0, "error": 1, "partial": 2, "hidden": 3, "no_data": 4, "extra": 5, "fires": 6, "hits": 7, "untested": 8, "skipped": 9}
        results.sort(key=lambda r: (order.get(r["verdict"], 9), r["title"].lower()))
        counts: Dict[str, int] = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        should = sum(1 for r in results if (r.get("expected") or 0) > 0)
        good = sum(1 for r in results if r["verdict"] == "fires")
        merged: Dict[str, str] = {}
        aliases: Dict[str, str] = {}
        for r in results:
            for k, v in ((r.get("diagnosis") or {}).get("mapping") or {}).items():
                merged.setdefault(k, v)
            for k, v in ((r.get("diagnosis") or {}).get("aliases") or {}).items():
                aliases.setdefault(k, v)
        times = sorted(r["ms"] for r in results if r.get("ms") is not None)
        slow_at = max(SLOW_MS, times[int(len(times) * 0.9)] if len(times) >= 10 else SLOW_MS)
        for r in results:
            if r.get("ms") is not None and r["ms"] >= slow_at:
                r["slow"] = True
        source_fix = ""
        if platform == "splunk":
            for r in results:
                for v in ((r.get("diagnosis") or {}).get("values") or []):
                    if v["field"] == "source" and v["want"].startswith("WinEventLog:"):
                        seen = [str(x) for x in v["seen"]]
                        source_fix = "xml" if any(x.startswith("XmlWinEventLog:") for x in seen) else "none"
                        break
                if source_fix:
                    break
        job.update(
            status="done",
            stage="Done",
            result={
                "platform": platform, "platform_name": PLATFORMS[platform]["name"], "target": target, "mode": mode, "run_id": run_id,
                "events": sent, "indexed": job.get("indexed"), "results": results, "counts": counts,
                "score": round(good * 100 / should) if should else None, "should_fire": should, "fired": good,
                "mapping": merged, "aliases": aliases, "alias_config": alias_config(platform, aliases, job.get("stanza") or settings.get("sourcetype") or "XmlWinEventLog"), "fields_seen": len(inventory), "source_fix": source_fix,
                "slow": sum(1 for r in results if r.get("slow")), "attack_techniques": job.get("attack_techniques", []), "median_ms": times[len(times) // 2] if times else None,
            },
        )
    except FireError as exc:
        job.update(status="error", error=str(exc))
    except Exception as exc:
        job.update(status="error", error=f"Fire check failed: {exc}")


def _entry(row: Dict[str, Any], lang: str, expected: Optional[int], got: Optional[int], error: str) -> Dict[str, Any]:
    if error and got is None:
        verdict = "error"
    elif expected is None:
        verdict = "hits" if got else "no_data"
    elif expected and got and got >= expected:
        verdict = "fires"
    elif expected and got:
        verdict = "partial"
    elif expected:
        verdict = "silent"
    elif got:
        verdict = "extra"
    else:
        verdict = "untested"
    return {"key": row["key"], "title": row["title"], "level": row["level"], "language": lang, "query": (row["queries"] or [""])[0][:4000],
            "expected": expected, "got": got, "error": error, "verdict": verdict}


def alias_config(platform: str, aliases: Dict[str, str], stanza: str = "XmlWinEventLog") -> str:
    if not aliases:
        return ""
    if platform == "splunk":
        lines = [f"[{stanza}]"]
        for i, (want, have) in enumerate(sorted(aliases.items())):
            if want in ("source", "sourcetype", "index", "host"):
                continue
            lines.append(f"FIELDALIAS-sigma{i} = \"{have}\" AS \"{want}\"")
        return "\n".join(lines) if len(lines) > 1 else ""
    if platform in ("elastic", "opensearch"):
        props = {want: {"type": "alias", "path": have} for want, have in sorted(aliases.items()) if not want.endswith(".caseless")}
        return json.dumps({"properties": props}, indent=2) if props else ""
    return ""


def start(params: Dict[str, Any]) -> str:
    if params.get("platform") not in PLATFORMS:
        raise FireError("Pick Splunk, Elasticsearch, OpenSearch, Sentinel or Wazuh")
    spec = PLATFORMS[params["platform"]]
    if params.get("target") not in spec["targets"]:
        params["target"] = spec["targets"][0]
    if params.get("mode") not in ("replay", "live"):
        raise FireError("Pick replay or live")
    if params["mode"] == "live" and not spec["live"]:
        raise FireError(f"{spec['name']} is checked with replay")
    if params["mode"] == "replay" and not params.get("files") and not params.get("attack"):
        raise FireError("Add log files to replay")
    if not params.get("rules"):
        raise FireError("Add at least one rule")
    _client(params["platform"], params.get("settings") or {})
    now = time.time()
    with _lock:
        for k in [k for k, v in JOBS.items() if now - v["created"] > JOB_TTL]:
            JOBS.pop(k, None)
        if sum(1 for v in JOBS.values() if v["status"] == "running") >= 2:
            raise FireError("Two fire checks are already running. Wait for one to finish.")
        jid = uuid.uuid4().hex
        JOBS[jid] = {"id": jid, "status": "running", "stage": "Starting", "done": 0, "total": 0, "created": now, "params": params, "error": "", "result": None}
    threading.Thread(target=run, args=(JOBS[jid],), daemon=True, name=f"firecheck-{jid[:6]}").start()
    return jid


def status(jid: str) -> Optional[Dict[str, Any]]:
    job = JOBS.get(jid)
    if not job:
        return None
    out = {k: job[k] for k in ("id", "status", "stage", "done", "total", "error", "result")}
    if job["status"] != "running":
        job["params"]["files"] = []
    return out
