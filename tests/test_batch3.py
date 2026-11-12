import io
import json
import pathlib
import socket
import zipfile
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import RuleInput

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent
WHOAMI = next((ROOT / "sample/rules/windows").glob("proc_creation_whoami*.yml"))


def rules(folder="sample/rules"):
    return [{"name": f.name, "content": f.read_text(encoding="utf-8")} for f in sorted((ROOT / folder).rglob("*.yml")) if "broken" not in str(f)]


def test_sysmon_config():
    res = client.post("/api/sysmon/config", json={"rules": rules()}).json()
    assert res["xml"].startswith("<Sysmon")
    events = {t["event"] for t in res["types"]}
    assert {"ProcessCreate", "NetworkConnect", "FileCreate"} <= events
    assert any(a["subcategory"] == "Process Creation" for a in res["audit"])
    assert "auditpol /set" in res["script"]


def test_field_suggest():
    ev = [{"process": {"executable": "C:\\Windows\\cmd.exe", "command_line": "cmd /c whoami"}, "user": {"name": "CORP\\bob"}}]
    body = {"rules": json.dumps([{"name": WHOAMI.name, "content": WHOAMI.read_text()}])}
    res = client.post("/api/mappings/suggest", data=body, files=[("files", ("e.json", json.dumps(ev).encode(), "application/json"))]).json()
    assert res["mapping"]["Image"] == "process.executable"
    assert res["mapping"]["CommandLine"] == "process.command_line"


def test_siem_import():
    conf = b"[Encoded]\nalert.severity = 5\nsearch = index=w EventCode=1 Image=\"*\\\\powershell.exe\" \\\n  CommandLine=\"* -enc *\"\n\n[Off]\ndisabled = 1\nsearch = index=x a=b\n"
    sent = json.dumps({"resources": [{"properties": {"displayName": "Whoami", "severity": "Low", "query": "SecurityEvent | where CommandLine contains \"whoami\"", "techniques": ["T1033"]}}]}).encode()
    el = b'{"name":"Certutil","language":"kuery","severity":"high","query":"process.name:certutil.exe and process.args:urlcache"}\n{"exported_count":1}\n'
    files = [("files", ("savedsearches.conf", conf, "text/plain")), ("files", ("s.json", sent, "application/json")), ("files", ("r.ndjson", el, "application/json"))]
    res = client.post("/api/import/siem", files=files).json()
    assert res["converted"] == 3 and res["skipped"] == 1
    kinds = {r["kind"] for r in res["rules"]}
    assert kinds == {"splunk", "sentinel", "elastic"}
    whoami = next(r for r in res["rules"] if r["kind"] == "sentinel")
    assert "attack.t1033" in whoami["content"]


def test_github_push_mocked():
    from app.core import githubpush

    calls = []

    def fake(method, url, token, body=None):
        calls.append((method, url))
        if url.endswith("/repos/acme/det"):
            return 200, {"default_branch": "main"}
        if "/git/ref/heads/main" in url:
            return 200, {"object": {"sha": "abc"}}
        if url.endswith("/git/refs"):
            return 201, {}
        if "/contents/" in url and method == "GET":
            return 404, {}
        if "/contents/" in url and method == "PUT":
            return 201, {}
        if url.endswith("/pulls"):
            return 201, {"html_url": "https://github.com/acme/det/pull/7", "number": 7}
        return 500, {}

    with mock.patch.object(githubpush, "_req", fake):
        res = client.post("/api/github/push", json={"token": "t", "repo": "acme/det", "rules": [{"name": "a.yml", "content": "x"}], "branch": "sf/test"}).json()
    assert res["pr_number"] == 7 and res["files"][0]["path"] == "rules/a.yml"
    assert ("PUT", "https://api.github.com/repos/acme/det/contents/rules/a.yml") in calls
    from app.api import routes

    with mock.patch.object(routes, "DEMO", True):
        assert client.post("/api/github/push", json={"token": "t", "repo": "acme/det", "rules": [{"name": "a.yml", "content": "x"}]}).status_code == 403


def test_sigmahq_check_and_fix():
    res = client.post("/api/rules/sigmahq", json={"rules": [{"name": WHOAMI.name, "content": WHOAMI.read_text()}]}).json()
    row = res["rules"][0]
    assert row["suggested_name"].startswith("proc_creation_win_")
    assert any(c["id"] == "filename_prefix" for c in row["checks"])
    fixed = client.post("/api/rules/sigmahq/fix", json={"name": WHOAMI.name, "content": WHOAMI.read_text()}).json()
    assert "\n    " in fixed["content"]
    assert not any(c["id"] == "indent" for c in fixed["check"]["checks"])


def test_unit_tests():
    tests = {WHOAMI.name: {"match": [{"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /priv"}],
                           "nomatch": [{"Image": "C:\\x\\whoami.exe", "CommandLine": "whoami"}, {"Image": "C:\\x\\whoami.exe", "CommandLine": "whoami /all"}]}}
    res = client.post("/api/rules/unit", json={"rules": [{"name": WHOAMI.name, "content": WHOAMI.read_text()}], "tests": tests}).json()
    assert res["passed"] == 2 and res["failed"] == 1
    bad = [c for c in res["rules"][0]["cases"] if not c["ok"]]
    assert bad[0]["kind"] == "nomatch" and bad[0]["index"] == 1


def test_wizard_and_correlation():
    tax = client.get("/api/wizard/taxonomy").json()
    assert any(s["category"] == "process_creation" for s in tax["logsources"])
    spec = {"title": "Certutil Download", "logsource": {"product": "windows", "category": "process_creation"}, "techniques": ["T1105"],
            "selections": [{"name": "img", "items": [{"field": "Image", "op": "endswith", "values": ["\\certutil.exe"]}]},
                           {"name": "cli", "items": [{"field": "CommandLine", "op": "contains", "values": ["urlcache", "http"], "all": True}]}],
            "filters": [{"name": "main_admin", "items": [{"field": "User", "op": "contains", "values": ["admin"]}]}]}
    res = client.post("/api/wizard/build", json={"spec": spec}).json()
    assert not res["errors"]
    assert "all of selection_* and not 1 of filter_*" in res["yaml"]
    assert res["name"].startswith("proc_creation_win_")
    corr = client.post("/api/correlation/build", json={"spec": {"type": "event_count", "group_by": ["Computer"], "timespan": "5m", "count": 3},
                                                       "rules": [{"name": "a.yml", "content": res["yaml"]}]}).json()
    assert not corr["errors"] and "event_count" in corr["yaml"] and corr["updated"]
    assert client.post("/api/correlation/build", json={"spec": {"type": "temporal", "timespan": "5m"}, "rules": [{"name": "a.yml", "content": res["yaml"]}]}).status_code == 400


def test_threat_report():
    text = "They used Spearphishing Attachment (T1566.001), dumped LSASS Memory and talked to 45.77.12.9 and hxxp://evil[.]example[.]com/x"
    res = client.post("/api/threat/report", json={"text": text, "rules": rules("sample/rules/windows")}).json()
    ids = {t["id"]: t for t in res["techniques"]}
    assert "T1566.001" in ids and "T1003.001" in ids
    assert ids["T1003.001"]["state"] == "covered"
    assert res["iocs"]["ipv4"] == ["45.77.12.9"]


def test_siem_send_dry_run_and_syslog():
    data = (ROOT / "sample/logs/attack_chain_sysmon.jsonl").read_bytes()
    res = client.post("/api/siem/send", data={"target": "splunk_hec", "url": "https://s:8088", "dry_run": "true"},
                      files=[("files", ("c.jsonl", data, "application/json"))]).json()
    first = json.loads(res["preview"][0])
    assert res["events"] == 17 and first["host"] == "FIN-WS07" and first["time"] > 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2)
    port = sock.getsockname()[1]
    from app.core.siemsend import send

    out = send("syslog", [{"Computer": "H1", "a": 1}], host="127.0.0.1", port=port)
    assert out["sent"] == 1
    msg = sock.recv(4096).decode()
    sock.close()
    assert msg.startswith("<134>1 ") and '"a":1' in msg


def test_zip_upload():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT / "sample/logs/attack_chain_sysmon.jsonl", "triage/sysmon.jsonl")
        z.writestr("triage/readme.txt", "not json")
    res = client.post("/api/test", data={"rules": json.dumps(rules("sample/rules/windows"))}, files=[("files", ("triage.zip", buf.getvalue(), "application/zip"))]).json()
    assert res["summary"]["events"] == 17


def test_log_health():
    from app.core.scheduler import check_health

    cfg = {"quiet_runs": 2, "health": {}}
    assert check_health(cfg, [{"channel": "Security", "events": 5}], "t1") == []
    assert check_health(cfg, [{"channel": "Security", "events": 0}], "t2") == []
    quiet = check_health(cfg, [{"channel": "Security", "events": 0}], "t3")
    assert quiet[0]["state"] == "quiet" and quiet[0]["since"] == "t2"
    assert check_health(cfg, [{"channel": "Security", "events": 0}], "t4") == []
    back = check_health(cfg, [{"channel": "Security", "events": 2}], "t5")
    assert back[0]["state"] == "back"


def test_case_report():
    case = {"title": "Chain", "status": "open", "severity": "high", "hits": [{"ts": "2026-01-01", "host": "WS1", "rule": "R", "level": "high"}], "notes": [{"time": "t", "text": "checked"}]}
    out = client.post("/api/cases/report", json={"case": case})
    assert out.status_code == 200 and "WS1" in out.text and "checked" in out.text


def test_cli_unit(tmp_path):
    from app.cli import main

    rule = tmp_path / WHOAMI.name
    rule.write_text(WHOAMI.read_text())
    (tmp_path / (WHOAMI.stem + ".tests.json")).write_text(json.dumps({"match": [{"Image": "C:\\w\\whoami.exe", "CommandLine": "whoami /priv"}]}))
    assert main(["unit", str(tmp_path)]) == 0
    (tmp_path / (WHOAMI.stem + ".tests.json")).write_text(json.dumps({"match": [{"Image": "C:\\w\\notepad.exe"}]}))
    assert main(["unit", str(tmp_path)]) == 1
