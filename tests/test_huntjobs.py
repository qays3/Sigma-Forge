import pathlib
import time

from fastapi.testclient import TestClient

from app.core import huntjobs
from app.main import app

client = TestClient(app)
ROOT = pathlib.Path(__file__).resolve().parent.parent
YARA = [{"name": p.name, "content": p.read_text()} for p in sorted((ROOT / "sample/yara/rules").glob("*.yar*"))]


def wait(kind, limit=60):
    for _ in range(limit * 4):
        j = client.get("/api/hunt/jobs").json()[kind]
        if j["status"] != "running":
            return j
        time.sleep(0.25)
    raise AssertionError("job did not finish")


def test_tabs_run_apart_and_keep_results(tmp_path, monkeypatch):
    monkeypatch.setattr(huntjobs, "DIR", tmp_path)
    huntjobs._jobs.clear()
    r = client.post("/api/hunt/jobs/yara", json={"rules": YARA, "paths": [str(ROOT / "sample/yara/files")]})
    assert r.status_code == 200 and r.json()["status"] == "running"
    assert client.post("/api/hunt/jobs/yara", json={"rules": YARA, "paths": [str(ROOT / "sample")]}).status_code == 409
    p = client.post("/api/hunt/jobs/procs", json={"rules": YARA, "pids": []})
    assert p.status_code == 200
    jobs = client.get("/api/hunt/jobs").json()
    assert jobs["live"] is None and jobs["evtx"] is None
    c = client.post("/api/hunt/jobs/procs/cancel").json()
    assert c["status"] == "cancelled"
    done = wait("yara")
    assert done["status"] == "done" and done["has_result"]
    full = client.get("/api/hunt/jobs/yara").json()
    assert full["result"]["summary"]["matched_files"] >= 1
    huntjobs._jobs.clear()
    again = client.get("/api/hunt/jobs").json()
    assert again["yara"]["status"] == "done" and again["procs"]["status"] == "cancelled"
    assert client.delete("/api/hunt/jobs/yara").status_code == 200
    assert client.get("/api/hunt/jobs").json()["yara"] is None


def test_evtx_job(tmp_path, monkeypatch):
    monkeypatch.setattr(huntjobs, "DIR", tmp_path)
    huntjobs._jobs.clear()
    rules = [{"name": p.name, "content": p.read_text()} for p in sorted((ROOT / "sample/rules/windows").glob("*.yml"))]
    log = (ROOT / "sample/logs/attack_chain_sysmon.jsonl").read_bytes()
    import json

    r = client.post("/api/hunt/jobs/evtx", data={"rules": json.dumps(rules)}, files=[("files", ("chain.jsonl", log, "application/json"))])
    assert r.status_code == 200
    j = wait("evtx")
    assert j["status"] == "done"
    res = client.get("/api/hunt/jobs/evtx").json()["result"]
    assert any(x.get("hits") for x in res["results"])
