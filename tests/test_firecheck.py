import json
import pathlib
import sys
import time

from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fakesiem import Fake

from app.core.firecheck import diagnose, literal_terms, probe, query_fields
from app.main import app

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = [{"name": p.name, "content": p.read_text()} for p in sorted((ROOT / "sample/rules/windows").glob("*.yml"))]


def run(platform, settings, mapping=None):
    r = client.post("/api/firecheck/start", data={"rules": json.dumps(RULES), "platform": platform, "mode": "replay", "settings": json.dumps(settings),
                                                    "sample": "1", "field_mapping": json.dumps(mapping or {})})
    assert r.status_code == 200, r.text
    jid = r.json()["id"]
    for _ in range(200):
        s = client.get(f"/api/firecheck/{jid}").json()
        if s["status"] != "running":
            return s
        time.sleep(0.1)
    raise AssertionError("fire check did not finish")


def test_query_fields_per_language():
    assert query_fields("spl", 'source="WinEventLog:x" EventCode=1 Image="*\\\\a.exe"') == ["source", "EventCode", "Image"]
    assert "process.command_line" in query_fields("lucene", "process.command_line:(*a* OR *b*) AND user.name:x")
    assert query_fields("xml", '<field name="win.eventdata.image">x</field>') == ["win.eventdata.image"]
    assert ("source", "WinEventLog:x") in literal_terms("spl", 'source="WinEventLog:x" EventCode=1')


def test_probe_finds_pipeline_names():
    assert probe("elastic_lucene", "windows", "process_creation", "", "CommandLine") == "process.command_line"
    assert probe("wazuh", "windows", "process_creation", "", "Image") == "win.eventdata.image"


def test_diagnose_points_to_real_field():
    d = diagnose("spl", 'EventCode=1 Image="*\\\\certutil.exe"', {"EventData.Image": ["C:\\Windows\\certutil.exe"], "System.EventID": ["1"]},
                 {"Image": ["C:\\Windows\\certutil.exe"]}, "splunk", {"product": "windows", "category": "process_creation"})
    assert d["missing"] == ["EventCode", "Image"]
    assert d["mapping"] == {"Image": "EventData.Image"}
    assert d["aliases"]["EventCode"] == "System.EventID"


def test_splunk_silent_then_fixed():
    f = Fake()
    try:
        cfg = {"url": f.url, "username": "admin", "password": "x", "hec_url": f.url, "hec_token": "t", "index": "main"}
        s = run("splunk", cfg)
        res = s["result"]
        assert s["status"] == "done" and res["fired"] == 0 and res["should_fire"] > 0
        assert res["source_fix"] == "xml"
        assert res["mapping"]["Image"] == "EventData.Image"
        assert 'AS "EventCode"' in res["alias_config"]
        cfg["splunk_windows_source"] = "xml"
        s2 = run("splunk", cfg, res["mapping"])
        assert all(not (r.get("diagnosis") or {}).get("values") for r in s2["result"]["results"])
    finally:
        f.close()


def test_elastic_fires_after_mapping():
    f = Fake()
    try:
        cfg = {"url": f.url, "username": "elastic", "password": "x"}
        res = run("elastic", cfg)["result"]
        assert res["fired"] == 0 and res["mapping"]
        res2 = run("elastic", cfg, res["mapping"])["result"]
        assert res2["fired"] == res2["should_fire"] > 0 and res2["score"] == 100
    finally:
        f.close()


def test_converter_splunk_source_option():
    body = {"rules": RULES[:3], "target": "splunk", "options": {"splunk_windows_source": "xml"}}
    out = client.post("/api/convert", json=body).json()
    q = " ".join(x for r in out["results"] for x in r["queries"])
    assert "WinEventLog:" not in q.replace("XmlWinEventLog:", "")


def test_firecheck_blocked_in_demo():
    from unittest import mock

    from app.api import routes

    with mock.patch.object(routes, "DEMO", True):
        r = client.post("/api/firecheck/start", data={"rules": json.dumps(RULES[:1]), "platform": "splunk", "settings": "{}", "sample": "1"})
        assert r.status_code == 403
