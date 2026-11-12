import json
import re
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.core.firecheck import flatten, literal_terms, query_fields


def _xml_fields(xml: str):
    out = {}
    root = ET.fromstring(xml)
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "Data" and el.get("Name"):
            out[el.get("Name")] = el.text or ""
        elif tag == "EventID":
            out["EventCode"] = el.text or ""
            out["EventID"] = el.text or ""
        elif tag == "Channel":
            out["Channel"] = el.text or ""
        elif tag == "Computer":
            out["Computer"] = el.text or ""
    return out


def _match(doc, lang, query):
    for f in query_fields(lang, query):
        base = f[:-9] if f.endswith(".caseless") else f
        if f not in doc and base not in doc:
            return False
    for f, v in literal_terms(lang, query):
        if f in doc and str(doc[f]).lower() != v.lower():
            return False
    return True


class Fake:
    def __init__(self):
        self.splunk = []
        self.elastic = []
        self.wazuh_rule = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()

    def _handler(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode() if n else ""

            def do_GET(self):
                p = urllib.parse.urlsplit(self.path)
                if p.path == "/":
                    return self._send(200, {"version": {"number": "8.15.0"}})
                if p.path.endswith("/_field_caps"):
                    keys = {}
                    for d in fake.elastic:
                        for k in d:
                            keys[k] = {"keyword": {"type": "keyword"}}
                    return self._send(200, {"fields": keys})
                self._send(404, {"error": "no"})

            def do_PUT(self):
                p = urllib.parse.urlsplit(self.path)
                if p.path == "/logtest":
                    body = json.loads(self._body())
                    ev = json.loads(body["event"])
                    flat = flatten(ev)
                    rid = ""
                    for r, (lang, q) in fake.wazuh_rule.items():
                        if _match(flat, "xml", q):
                            rid = r
                            break
                    out = {"data": ev, "rule": {"id": rid, "level": 5} if rid else {}}
                    return self._send(200, {"data": {"token": "s1", "output": out}, "error": 0})
                self._send(404, {})

            def do_POST(self):
                p = urllib.parse.urlsplit(self.path)
                raw = self._body()
                if p.path == "/security/user/authenticate":
                    return self._send(200, {"data": {"token": "jwt"}})
                if p.path.startswith("/services/collector"):
                    for line in raw.splitlines():
                        item = json.loads(line)
                        doc = _xml_fields(item["event"]) if isinstance(item["event"], str) else flatten(item["event"])
                        doc.update({"source": item.get("source"), "sourcetype": item.get("sourcetype"), "host": item.get("host", ""), "sf_run": item["fields"]["sf_run"]})
                        fake.splunk.append(doc)
                    return self._send(200, {"text": "Success", "code": 0})
                if p.path == "/services/search/jobs":
                    form = urllib.parse.parse_qs(raw)
                    spl = form["search"][0]
                    run = re.search(r"sf_run::(\w+)", spl)
                    docs = [d for d in fake.splunk if not run or d["sf_run"] == run.group(1)]
                    if "fieldsummary" in spl:
                        fields = {}
                        for d in docs:
                            for k, v in d.items():
                                fields.setdefault(k, [])
                                if v not in fields[k]:
                                    fields[k].append(v)
                        return self._send(200, {"results": [{"field": k, "values": json.dumps([{"value": x, "count": 1} for x in v])} for k, v in fields.items()]})
                    inner = re.sub(r"^search index=\S+( sf_run::\w+)?\s*", "", spl).rsplit("| stats count", 1)[0].strip()
                    if "syntaxerror(" in inner:
                        return self._send(400, {"messages": [{"type": "FATAL", "text": "Error in 'search' command"}]})
                    n = sum(1 for d in docs if not inner or _match(d, "spl", inner))
                    return self._send(200, {"results": [{"count": str(n)}]})
                if p.path.endswith("/_bulk"):
                    lines = [l for l in raw.splitlines() if l.strip()]
                    for i in range(1, len(lines), 2):
                        fake.elastic.append(flatten(json.loads(lines[i])))
                    return self._send(200, {"errors": False, "items": [{"create": {"status": 201}}] * (len(lines) // 2)})
                if p.path.endswith("/_count"):
                    body = json.loads(raw)
                    flt = body["query"]
                    run = json.dumps(flt).split('"sf_run": "')[1].split('"')[0] if "sf_run" in json.dumps(flt) else None
                    docs = [d for d in fake.elastic if not run or d.get("sf_run") == run]
                    qs = None
                    if "bool" in flt:
                        for f in flt["bool"]["filter"]:
                            if "query_string" in f:
                                qs = f["query_string"]["query"]
                    n = sum(1 for d in docs if qs is None or _match(d, "lucene", qs))
                    return self._send(200, {"count": n})
                if p.path.endswith("/_search"):
                    return self._send(200, {"hits": {"hits": [{"_source": d} for d in fake.elastic[:500]]}})
                self._send(404, {"error": "unknown " + p.path})

        return H
