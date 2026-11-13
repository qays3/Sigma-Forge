import json
import pathlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core import attacklogs, ciworkflow, ctifeeds, drift, fcschedule, firecheck, response
from app.core.logtest import run_test
from app.main import app

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = [SimpleNamespace(name=p.name, content=p.read_text()) for p in sorted((ROOT / "sample/rules/windows").glob("*.yml"))]
ALL = [SimpleNamespace(name=str(p.relative_to(ROOT)), content=p.read_text()) for p in sorted((ROOT / "sample/rules").rglob("*.yml")) if "broken" not in p.parts]


def test_attack_logs_fire_sample_rules():
    cat = attacklogs.catalog()
    assert len(cat) >= 50 and all(t["events"] for t in cat)
    res = attacklogs.generate()
    assert res["events"] > 100 and not res["missing"]
    out = run_test(ALL, [("attack.jsonl", res["jsonl"].encode())])
    fired = [r for r in out["results"] if r.get("hits")]
    assert len(fired) >= 35
    one = attacklogs.generate(["T1003.001", "T9999"])
    assert one["techniques"] == ["T1003.001"] and one["missing"] == ["T9999"]
    r = client.post("/api/attacklogs", json={"techniques": ["T1059.001"]})
    assert r.status_code == 200 and r.json()["events"] > 0
    assert client.post("/api/attacklogs", json={"techniques": ["T9999"]}).status_code == 400


def test_response_steps_round_trip():
    rule = next(r for r in RULES if r.name == "lsass_access_suspicious.yml")
    steps = response.suggest(rule.content)
    assert len(steps) >= 2
    content = response.set_steps(rule.content, ["Isolate the host", "Reset the account"])
    assert "response:" in content and "- Isolate the host" in content
    again = response.set_steps(content, ["Only one"])
    assert again.count("response:") == 1 and "Isolate" not in again
    res = run_test([SimpleNamespace(name=rule.name, content=content)], [("a.jsonl", attacklogs.generate(["T1003.001"])["jsonl"].encode())])
    hit = [r for r in res["results"] if r.get("hits")]
    assert hit and hit[0]["response"] == ["Isolate the host", "Reset the account"]
    r = client.post("/api/rules/response", json={"content": rule.content, "steps": None})
    assert r.status_code == 200 and r.json()["steps"]


def test_ci_workflow():
    out = ciworkflow.generate({"rules": "detections", "branch": "main", "firecheck": {"platform": "splunk"}, "deploy": {"kind": "sentinel"}})
    names = [f["name"] for f in out["files"]]
    assert ".github/workflows/sigma-forge.yml" in names and ".sigma-forge-firecheck-splunk.json" in names
    wf = out["workflow"]
    assert "app.cli firecheck" in wf and "app.cli deploy" in wf and "secrets.SPLUNK_TOKEN" in wf
    assert '"detections/**"' in wf and "refs/heads/main" in wf
    settings = json.loads(next(f["content"] for f in out["files"] if f["name"].endswith("splunk.json")))
    assert all(str(v).startswith("env:") for k, v in settings.items() if k != "splunk_windows_source")
    with pytest.raises(ValueError):
        ciworkflow.generate({"rules": "../etc"})
    assert client.post("/api/ci/workflow", json={"spec": {"rules": "rules"}}).status_code == 200


def test_cti_pull_and_expiry(monkeypatch):
    monkeypatch.setattr(ctifeeds, "otx", lambda key, days: (["185.220.101.4", "evil-domain.example", "44d88612fea8a8f36de82e1278abb02f"], ["pulse one"]))
    res = ctifeeds.pull("otx", {"key": "k", "days": 3, "expire_days": 10})
    assert res["indicators"] == 3 and res["sigma"] and all(r["name"].startswith("cti/otx/") for r in res["sigma"])
    assert all("sf_expires:" in r["content"] and "sf_feed: otx" in r["content"] for r in res["sigma"])
    items = [SimpleNamespace(name=r["name"], content=r["content"]) for r in res["sigma"]]
    assert ctifeeds.expired(items) == []
    assert len(ctifeeds.expired(items, today="2999-01-01")) == len(items)
    with pytest.raises(ctifeeds.FeedError):
        ctifeeds.pull("misp", {"url": "", "key": ""})
    parsed = run_test(items[:1], [("x.jsonl", b'{"DestinationIp": "185.220.101.4"}\n')])
    assert not [r for r in parsed["results"] if r.get("status") == "error"]


def test_drift_states(monkeypatch):
    rules = RULES[:3]
    conv = drift._convert(rules, "splunk", "splunk", None, {})
    titles = [r["title"] for r in conv["results"] if r["queries"]]
    live = {titles[0]: {"query": conv["results"][0]["queries"][0], "enabled": True},
            titles[1]: {"query": "index=main changed", "enabled": False},
            "Old rule": {"query": "index=main old", "enabled": True}}
    monkeypatch.setattr(drift, "_splunk", lambda s, v: live)
    res = drift.check(rules, "splunk", "splunk", {"url": "https://x"}, None, {})
    st = {r["title"]: r["state"] for r in res["rows"]}
    assert st[titles[0]] == "same" and st[titles[1]] == "changed" and st[titles[2]] == "missing" and st["Old rule"] == "extra"
    assert res["disabled"] == 1 and not res["in_sync"]
    assert next(r for r in res["rows"] if r["state"] == "changed")["diff"]


def test_schedule_alerts_when_rule_stops(monkeypatch, tmp_path):
    monkeypatch.setattr(fcschedule, "DIR", tmp_path)
    monkeypatch.setattr(fcschedule, "FILE", tmp_path / "schedule.json")
    sent = []
    import app.core.scheduler as sched

    monkeypatch.setattr(sched, "send", lambda cfg, title, lines, hits: sent.append((title, lines)) or "")
    verdicts = iter(["fires", "silent"])

    def fake_run(job):
        v = next(verdicts)
        job.update(status="done", result={"results": [{"key": "a.yml", "title": "Rule A", "verdict": v}], "score": 100 if v == "fires" else 0,
                                          "fired": 1 if v == "fires" else 0, "should_fire": 1, "counts": {v: 1}, "platform_name": "Splunk", "slow": 0})

    monkeypatch.setattr(firecheck, "run", fake_run)
    params = {"rules": [SimpleNamespace(name="a.yml", content=RULES[0].content)], "platform": "splunk", "target": "splunk", "mode": "replay", "hours": 24,
              "settings": {"url": "https://x", "password": "secret", "token": "env:SPLUNK_TOKEN"}, "mapping": {}, "files": [("x.jsonl", b"{}\n")], "attack": [], "sample": False}
    pub = fcschedule.update(True, 24, params, "slack", "https://hooks.example/x")
    assert pub["enabled"] and pub["stored_secrets"] == ["password"] and pub["env_secrets"] == ["token"]
    assert (tmp_path / "schedule.json").stat().st_mode & 0o077 == 0
    first = fcschedule.run_once()
    assert first["status"] == "ok" and not sent
    second = fcschedule.run_once()
    assert second["broke"] == ["Rule A"] and sent and "Rule A stopped firing" in sent[0][1]
    assert len(fcschedule.public()["history"]) == 2


class FakeHttp:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, method, url, headers, body=None, verify=True, timeout=60):
        self.calls.append((method, url, json.loads(body) if body and body[:1] in (b"{", b"[") else body))
        for key, ans in self.answers:
            if key in url:
                return ans(url, body) if callable(ans) else ans
        return 404, {"error": "not found"}


def test_sentinel_client(monkeypatch):
    def query(url, body):
        q = json.loads(body)["query"]
        n = 3 if "count" in q else 0
        return 200, {"tables": [{"columns": [{"name": "Count"}], "rows": [[n]]}]}

    fake = FakeHttp([("login.microsoftonline.com", (200, {"access_token": "tok"})), ("api.loganalytics.io", query), ("ingest.monitor.azure.com", (204, {}))])
    monkeypatch.setattr(firecheck, "_http", fake)
    with pytest.raises(firecheck.FireError):
        firecheck.Sentinel({"workspace_id": "nope"})
    s = firecheck.Sentinel({"workspace_id": "0" * 8 + "-0000-0000-0000-" + "0" * 12, "tenant_id": "t", "client_id": "c", "client_secret": "x",
                            "dce": "https://dce.westeurope-1.ingest.monitor.azure.com", "dcr_id": "dcr-1"})
    assert s.check() == ""
    recs = [{"raw": {"EventID": 1, "Image": "C:\\a.exe"}, "epoch": 1700000000}]
    assert s.send(recs, "run1") == 1
    sent = [c for c in fake.calls if "ingest" in c[1]][0][2]
    assert sent[0]["sf_run"] == "run1" and sent[0]["TimeGenerated"].startswith("2023-")
    assert "SigmaForge_CL" in s._wrap("SecurityEvent | where EventID == 4688", "run1", 24)
    assert s._wrap("SecurityEvent | where EventID == 4688", None, 2).startswith("SecurityEvent |")
    assert s.count("SecurityEvent | where EventID == 1", "run1", 24) == (3, "")


def test_elastic_rule_preview(monkeypatch):
    fake = FakeHttp([("/api/detection_engine/rules/preview", (200, {"previewId": "p1", "logs": []})), ("/_count", (200, {"count": 2}))])
    monkeypatch.setattr(firecheck, "_http", fake)
    c = firecheck._client("elastic", {"url": "https://es:9200", "kibana_url": "https://kb:5601", "use_rules": True, "space": "soc", "token": "k"})
    assert isinstance(c, firecheck.ElasticRules)
    assert c.count('process.name:"x.exe"', "lucene", "run1", 24) == (2, "")
    pv = [x for x in fake.calls if "rules/preview" in x[1]][0]
    assert "/s/soc/" in pv[1] and pv[2]["filters"][0]["query"]["match_phrase"]["sf_run"] == "run1"
    cnt = [x for x in fake.calls if "_count" in x[1]][0]
    assert cnt[2]["query"]["term"]["kibana.alert.rule.uuid"] == "p1"
    assert c.count("from logs-*", "esql", "run1", 24)[1] == ""
    assert "where sf_run" in [x for x in fake.calls if "rules/preview" in x[1]][-1][2]["query"]
