import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent


def rules(folder="sample/rules/windows", limit=None):
    files = sorted((ROOT / folder).rglob("*.yml"))
    if limit:
        files = files[:limit]
    return [{"name": f.name, "content": f.read_text(encoding="utf-8")} for f in files]


def yara_rules():
    return [{"name": p.name, "content": p.read_text(encoding="utf-8")} for p in sorted((ROOT / "sample/yara/rules").glob("*.yar"))]


def test_generated_events_fire_every_rule():
    items = rules("sample/rules")
    gen = client.post("/api/generate-events", json={"rules": items}).json()
    assert gen["count"] > 0
    files = [("files", ("generated.jsonl", gen["jsonl"].encode(), "application/json"))]
    res = client.post("/api/test", data={"rules": json.dumps(items), "mode": "strict"}, files=files).json()
    ok = [r for r in res["results"] if r["status"] == "ok"]
    silent = [r["key"] for r in ok if not r["hits"]]
    assert not silent


def test_noise_check_on_baseline():
    items = rules("sample/rules/attack")
    logs = client.get("/api/samples/logs?set=baseline").json()["logs"]
    files = [("files", (l["name"], l["content"].encode(), "application/json")) for l in logs]
    res = client.post("/api/test", data={"rules": json.dumps(items), "mode": "auto"}, files=files).json()
    noisy = [r for r in res["results"] if r.get("noise") and r["noise"]["level"] != "quiet"]
    assert noisy
    assert any(r["noise"]["suggestions"] for r in noisy)


def test_rule_from_event_and_filter():
    event = {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all", "ParentImage": "C:\\agent\\inv_agent.exe"}
    res = client.post("/api/rulegen", json={"event": event, "logsource": {"product": "windows", "category": "process_creation"}, "fields": ["Image", "CommandLine"]}).json()
    assert "Image|endswith" in res["yaml"]
    out = client.post("/api/rules/add-filter", json={"content": res["yaml"], "filters": [{"field": "ParentImage|endswith", "value": "\\inv_agent.exe"}]}).json()
    assert "filter_sf_noise" in out["content"]
    assert "not filter_sf_noise" in out["content"]


@pytest.mark.parametrize(
    "query,lang,expect",
    [
        ('index=win EventCode=1 Image="*\\\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-e *") | stats count', "splunk", "CommandLine|contains"),
        ('DeviceProcessEvents | where FileName in~ ("rundll32.exe") and ProcessCommandLine contains "http"', "kql", "Image|endswith"),
        ('process.name:("mshta.exe" OR "wscript.exe") AND NOT user.name:SYSTEM', "lucene", "filter_1"),
        ('process where process.name : "vssadmin.exe" and process.args : ("delete", "shadows")', "eql", "CommandLine|contains"),
        ('FROM logs-* | WHERE process.executable LIKE "*\\\\schtasks.exe"', "esql", "Image|endswith"),
    ],
)
def test_query_to_rule(query, lang, expect):
    res = client.post("/api/querygen", json={"query": query}).json()
    assert res["language"] == lang
    assert expect in res["yaml"]
    assert res["logsource"].get("category") == "process_creation"
    assert not res["error"]


def test_query_to_rule_converts_back():
    res = client.post("/api/querygen", json={"query": 'EventCode=4625 Account_Name!="*$"'}).json()
    conv = client.post("/api/convert", json={"rules": [{"name": "q.yml", "content": res["yaml"]}], "target": "splunk"}).json()
    assert conv["results"][0]["queries"]


def test_groups_atomic_and_coverage():
    groups = client.get("/api/groups").json()["groups"]
    assert len(groups) > 100
    atomic = client.get("/api/atomic/T1059").json()
    assert atomic["subs"]
    cov = client.post("/api/coverage", json={"rules": rules(), "group": "G0016", "collected": ["windows / process_creation"]}).json()
    assert cov["group"]["name"] == "APT29"
    assert "blind_count" in cov["readiness"]


def test_report_and_quality():
    res = client.post("/api/report", json={"rules": rules(limit=5), "title": "T", "group": "G0016"})
    assert res.status_code == 200 and "<html" in res.text.lower()
    data = client.post("/api/analyze", json={"rules": rules(limit=5)}).json()
    assert all("quality" in r for r in data["rules"])
    assert 0 <= data["summary"]["quality"] <= 100


def test_deploy_against_mock_server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def _reply(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            calls.append((self.command, self.path))
            body = json.dumps({"data": {"token": "jwt"}}).encode() if "authenticate" in self.path else b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = _reply

        def log_message(self, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        dry = client.post("/api/deploy", json={"rules": rules(limit=2), "kind": "splunk", "settings": {"url": url, "token": "t"}}).json()
        assert all(r["status"] == "planned" for r in dry["results"] if r["status"] != "skipped")
        assert not calls
        live = client.post("/api/deploy", json={"rules": rules(limit=2), "kind": "wazuh", "dry_run": False, "settings": {"url": url, "username": "u", "password": "p"}}).json()
        assert any(r["status"] == "ok" for r in live["results"])
        assert any("authenticate" in path for _, path in calls)
    finally:
        server.shutdown()


def test_yara_check_and_scan():
    check = client.post("/api/yara/check", json={"rules": yara_rules()}).json()
    assert check["errors"] == 0 and check["rules"] >= 6
    files = [("files", (p.name, p.read_bytes(), "application/octet-stream")) for p in sorted((ROOT / "sample/yara/files").iterdir())]
    res = client.post("/api/yara/scan", data={"rules": json.dumps(yara_rules())}, files=files).json()
    assert res["summary"]["matched_files"] == 6


def test_hunt_yara_folder():
    res = client.post("/api/hunt/yara", json={"rules": yara_rules(), "paths": [str(ROOT / "sample/yara/files")]}).json()
    assert res["summary"]["scanned"] == 7
    assert res["summary"]["matched_files"] == 6


def test_hunt_live_logs_parsed():
    import app.core.hunt as hunt

    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        "<EventID>1</EventID><TimeCreated SystemTime=\"2026-11-12T05:00:00Z\"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        "<Computer>PC1</Computer></System><EventData><Data Name=\"Image\">C:\\Windows\\System32\\whoami.exe</Data>"
        "<Data Name=\"CommandLine\">whoami /all</Data></EventData></Event>"
    )
    with mock.patch.object(hunt, "is_windows", return_value=True), mock.patch.object(hunt, "_run", return_value=(0, xml, "")):
        res = client.post("/api/hunt/events", json={"rules": rules(), "channels": ["Microsoft-Windows-Sysmon/Operational"]}).json()
    assert res["channels"][0]["events"] == 1
    assert any(r["hits"] for r in res["results"])


def test_hunt_events_needs_windows():
    with mock.patch("app.core.hunt.is_windows", return_value=False):
        res = client.post("/api/hunt/events", json={"rules": rules(limit=1), "channels": ["Security"]})
    assert res.status_code == 400


def test_git_fetch_with_mock_archive():
    import io
    import zipfile

    import app.core.gitsync as gitsync

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("repo-main/rules/a.yml", "title: A\nlogsource:\n  product: windows\ndetection:\n  sel:\n    a: 1\n  condition: sel\n")
        z.writestr("repo-main/README.md", "x")
    with mock.patch.object(gitsync, "_get", return_value=buf.getvalue()):
        res = client.post("/api/git/fetch", json={"repo": "owner/repo"}).json()
    assert res["rules"][0]["name"] == "github/owner/repo/rules/a.yml"
