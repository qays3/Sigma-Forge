import json
import pathlib
from unittest import mock

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent


def rules(folder="sample/rules", limit=None):
    files = sorted((ROOT / folder).rglob("*.yml"))
    if limit:
        files = files[:limit]
    return [{"name": f.name, "content": f.read_text(encoding="utf-8")} for f in files]


def chain_files():
    data = (ROOT / "sample/logs/attack_chain_sysmon.jsonl").read_bytes()
    return [("files", ("attack_chain_sysmon.jsonl", data, "application/json"))]


def test_timeline_and_process_tree():
    res = client.post("/api/test", data={"rules": json.dumps(rules())}, files=chain_files()).json()
    tl = res["timeline"]
    assert tl["items"] and tl["hosts"][0]["host"] == "FIN-WS07"
    assert [t["short"] for t in tl["tactics"]][-1] == "impact"
    trees = [s["lineage"] for r in res["results"] for s in r["samples"] if s.get("lineage")]
    deep = max(trees, key=lambda t: len(t["ancestors"]))
    assert [a["image"].split("\\")[-1] for a in deep["ancestors"]][:2] == ["explorer.exe", "WINWORD.EXE"]


def test_hunt_report():
    res = client.post("/api/test", data={"rules": json.dumps(rules())}, files=chain_files()).json()
    out = client.post("/api/hunt/report", json={"result": res, "title": "Chain"})
    assert out.status_code == 200
    assert "Attack path" in out.text and "FIN-WS07" in out.text


def test_purple_score():
    res = client.post("/api/purple", data={"rules": json.dumps(rules()), "techniques": json.dumps(["T1105", "T1490", "T1003.001"])}, files=chain_files()).json()
    states = {t["id"]: t["state"] for t in res["techniques"]}
    assert states["T1105"] == "detected" and states["T1490"] == "detected" and states["T1003.001"] == "missed"
    assert res["summary"]["score"] == 67


def test_ioc_rules_parse_and_yara():
    from app.core.yara_engine import check

    res = client.post("/api/rules/ioc", json={"text": "203.0.113.10 evil[.]com hxxps://evil[.]com/a 44d88612fea8a8f36de82e1278abb02f run.exe", "name": "Test"}).json()
    assert res["counts"]["ipv4"] == 1 and res["counts"]["domain"] == 1 and res["counts"]["md5"] == 1
    names = [r["name"] for r in res["sigma"]]
    assert "test_dns.yml" in names and "test_hashes.yml" in names
    assert check([(res["yara"]["name"], res["yara"]["content"])])["errors"] == 0
    a = client.post("/api/analyze", json={"rules": res["sigma"]}).json()
    assert all(not r["error"] for r in a["rules"])


def test_explain_and_autofix():
    ex = client.post("/api/rules/explain", json={"rules": rules("sample/rules/windows", 5)}).json()["rules"]
    assert all(r["lines"][0].startswith("Looks at") for r in ex)
    bad = "title: test\nstatus: Test\nlogsource:\n  product: Windows\ndetection:\n  sel:\n    Image|endwith: x.exe\n  condition: sel\n"
    fix = client.post("/api/rules/autofix", json={"content": bad}).json()
    assert "Image|endswith" in fix["content"] and fix["changed"]
    a = client.post("/api/analyze", json={"rules": [{"name": "f.yml", "content": fix["content"]}]}).json()
    assert not a["rules"][0]["error"]


def test_allowlist_applies_to_convert():
    body = {"rules": rules("sample/rules/windows", 3), "target": "splunk", "allowlist": [{"field": "User", "value": "CORP\\svc_backup"}]}
    res = client.post("/api/convert", json=body).json()
    assert any("svc_backup" in q for r in res["results"] for q in r["queries"])


def test_query_cost():
    res = client.post("/api/convert", json={"rules": rules("sample/rules/windows", 6), "target": "splunk"}).json()
    assert any(r.get("cost") and r["cost"]["items"] for r in res["results"])


def test_linux_audit_parse():
    from app.core.hunt import _merge_execve, parse_audit_line

    ev = parse_audit_line('type=EXECVE msg=audit(1731400000.123:456): argc=3 a0="bash" a1="-c" a2=6964202D61')
    assert _merge_execve([ev])[0]["CommandLine"] == "bash -c id -a"


def test_schedule_flow(tmp_path):
    import app.core.scheduler as sch

    with mock.patch.object(sch, "FILE", tmp_path / "s.json"):
        out = client.post("/api/hunt/schedule", json={"enabled": False, "every_minutes": 15, "channels": ["journal"], "rules": rules(limit=2), "kind": "slack", "url": "https://hooks.example/x"}).json()
        assert out["rule_count"] == 2 and out["webhook"]["url_set"]
        events = (ROOT / "sample/logs/attack_chain_sysmon.jsonl").read_bytes()
        with mock.patch("app.core.hunt.collect", return_value=([("live:x", events)], [{"channel": "x", "events": 17, "error": ""}])), \
                mock.patch.object(sch, "send", return_value="") as sent:
            sch.update(False, 15, ["journal"], rules(), "medium", "slack", None)
            first = client.post("/api/hunt/schedule/run").json()["run"]
            again = client.post("/api/hunt/schedule/run").json()["run"]
        assert first["new"] > 0 and again["new"] == 0 and sent.call_count == 1


def test_demo_mode_blocks_machine_tools():
    import app.api.routes as routes

    with mock.patch.object(routes, "DEMO", True):
        assert client.get("/api/hunt/status").status_code == 403
        assert client.post("/api/git/fetch", json={"repo": "a/b"}).status_code == 403
        res = client.post("/api/deploy", json={"rules": rules(limit=1), "kind": "splunk", "dry_run": False, "settings": {"url": "https://x:8089", "token": "t"}}).json()
        assert all(r["status"] in ("planned", "skipped") for r in res["results"])


def test_library_updates_without_library():
    with mock.patch("app.core.library.load_index", return_value=None):
        res = client.post("/api/library/updates", json={"rules": rules(limit=2)}).json()
    assert res["available"] is False
