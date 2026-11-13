import pathlib

import pytest
from fastapi.testclient import TestClient

from app.core import team
from app.main import app

ROOT = pathlib.Path(__file__).resolve().parent.parent
H = {"X-Sigma-Forge": "1"}
RULE = (ROOT / "sample/rules/windows").glob("proc_creation_whoami*.yml").__next__()


@pytest.fixture
def tc(tmp_path, monkeypatch):
    monkeypatch.setattr(team, "DIR", tmp_path)
    monkeypatch.setattr(team, "AUTH", True)
    monkeypatch.setattr(team, "REQUIRE_REVIEW", True)
    monkeypatch.setattr(team, "ITER", 1000)
    team.limiter.hits.clear()
    return TestClient(app)


def login(c, user, pw):
    r = c.post("/api/auth/login", json={"username": user, "password": pw}, headers=H)
    assert r.status_code == 200, r.text
    return r


def test_setup_login_roles_and_csrf(tc):
    assert tc.get("/api/auth/me").json()["setup_needed"] is True
    assert tc.get("/api/library/status").status_code == 401
    assert tc.post("/api/auth/setup", json={"username": "boss", "password": "short"}, headers=H).status_code == 400
    r = tc.post("/api/auth/setup", json={"username": "boss", "password": "Str0ngPassw0rd"}, headers=H)
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"
    assert tc.post("/api/auth/setup", json={"username": "x2", "password": "Str0ngPassw0rd"}, headers=H).status_code == 403
    assert tc.get("/api/auth/me").json()["user"]["username"] == "boss"
    assert tc.post("/api/team/users", json={"username": "vic", "password": "Str0ngPassw0rd", "role": "viewer"}).status_code == 403
    assert tc.post("/api/team/users", json={"username": "vic", "password": "Str0ngPassw0rd", "role": "viewer"}, headers=H).status_code == 200
    tc.post("/api/team/users", json={"username": "eve", "password": "Str0ngPassw0rd", "role": "editor"}, headers=H)
    tc.post("/api/team/users", json={"username": "rob", "password": "Str0ngPassw0rd", "role": "reviewer"}, headers=H)
    tc.post("/api/auth/logout", headers=H)
    assert tc.post("/api/auth/login", json={"username": "vic", "password": "nope"}, headers=H).status_code == 401
    login(tc, "vic", "Str0ngPassw0rd")
    assert tc.post("/api/team/rules", json={"files": [{"name": "a.yml", "content": "x"}]}, headers=H).status_code == 403
    assert tc.post("/api/analyze", json={"rules": [{"name": RULE.name, "content": RULE.read_text()}]}, headers=H).status_code == 200
    assert tc.get("/api/team/users").status_code == 403
    r = tc.post("/api/convert", json={"rules": [], "target": "splunk"}, headers={"X-Sigma-Forge": "1", "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_shared_workspace_reviews_and_deploy_gate(tc):
    tc.post("/api/auth/setup", json={"username": "boss", "password": "Str0ngPassw0rd"}, headers=H)
    tc.post("/api/team/users", json={"username": "eve", "password": "Str0ngPassw0rd", "role": "editor"}, headers=H)
    tc.post("/api/team/users", json={"username": "rob", "password": "Str0ngPassw0rd", "role": "reviewer"}, headers=H)
    login(tc, "eve", "Str0ngPassw0rd")
    content = RULE.read_text()
    assert tc.post("/api/team/rules", json={"files": [{"name": RULE.name, "content": content}]}, headers=H).json()["added"] == 1
    data = tc.get("/api/team/rules").json()
    assert data["rules"][0]["by"] == "eve"
    body = {"rules": [{"name": RULE.name, "content": content}], "kind": "splunk", "settings": {"url": "https://127.0.0.1:1", "token": "t"}, "dry_run": False}
    r = tc.post("/api/deploy", json=body, headers=H)
    assert r.status_code == 400 and "not approved" in r.json()["detail"]
    tc.post("/api/team/reviews", json={"name": RULE.name, "content": content, "note": "new"}, headers=H)
    assert tc.post("/api/team/reviews/decide", json={"name": RULE.name, "decision": "approved"}, headers=H).status_code == 403
    login(tc, "rob", "Str0ngPassw0rd")
    assert tc.post("/api/team/reviews/decide", json={"name": RULE.name, "decision": "approved", "note": "ok"}, headers=H).status_code == 200
    assert tc.get("/api/team/rules").json()["reviews"][RULE.name]["status"] == "approved"
    r = tc.post("/api/deploy", json=body, headers=H)
    assert "not approved" not in r.text
    tc.put("/api/team/rules", json={"old_id": data["rules"][0]["id"], "name": RULE.name, "content": content + "\n"}, headers=H)
    assert tc.get("/api/team/rules").json()["reviews"][RULE.name]["status"] == "outdated"
    login(tc, "boss", "Str0ngPassw0rd")
    actions = [e["action"] for e in tc.get("/api/team/audit").json()["entries"]]
    assert "review approved" in actions and "rule saved" in actions and "login" in actions


def test_cases_shared(tc):
    tc.post("/api/auth/setup", json={"username": "boss", "password": "Str0ngPassw0rd"}, headers=H)
    tc.put("/api/team/cases", json={"case": {"id": "c123", "title": "T", "hits": []}}, headers=H)
    assert tc.get("/api/team/cases").json()["cases"][0]["updated_by"] == "boss"
    tc.delete("/api/team/cases/c123", headers=H)
    assert tc.get("/api/team/cases").json()["cases"] == []


def test_rate_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(team, "RATE_LIMIT", 3)
    team.limiter.hits.clear()
    c = TestClient(app)
    codes = [c.get("/api/config").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[-1] == 429
    team.limiter.hits.clear()
