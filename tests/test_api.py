from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def sample_rules():
    return client.get("/api/samples").json()["rules"]


def test_health():
    data = client.get("/api/health").json()
    assert data["app"] == "Sigma Forge"
    assert data["attack_loaded"] is True


def test_targets_listed():
    ids = {t["id"] for t in client.get("/api/targets").json()["targets"]}
    assert {"splunk", "elastic_lucene", "defender_xdr", "crowdstrike_falcon", "secops", "sentinelone", "cortex_xdr", "qradar", "loki", "wazuh"} <= ids
    assert len(ids) >= 30


def good_rules():
    return [r for r in sample_rules() if not r["name"].startswith("broken/")]


def test_analyze_samples():
    data = client.post("/api/analyze", json={"rules": good_rules()}).json()
    assert data["summary"]["rules"] >= 40
    assert data["summary"]["errors"] == 0
    assert data["summary"]["correlations"] == 2


def test_broken_samples_are_reported():
    rows = {r["key"]: r for r in client.post("/api/analyze", json={"rules": sample_rules()}).json()["rules"]}
    assert rows["broken/error_yaml_syntax.yml#0"]["error"].startswith("YAML error")
    assert rows["broken/error_undefined_detection.yml#0"]["error"]
    assert rows["broken/error_unknown_modifier.yml#0"]["error"]
    assert any("revoked" in i["message"] for i in rows["broken/issue_revoked_and_unknown_tags.yml#0"]["issues"])
    assert rows["broken/issue_validator_findings.yml#0"]["issues"]


def test_correlation_conversion():
    rules = [r for r in sample_rules() if r["name"].startswith("correlation/")]
    res = client.post("/api/convert", json={"rules": rules, "target": "splunk"}).json()
    corr = [r for r in res["results"] if r["kind"] == "correlation"]
    assert len(corr) == 2 and all(r["queries"] for r in corr)
    wazuh = client.post("/api/convert", json={"rules": rules, "target": "wazuh"}).json()
    rows = {r["title"]: r for r in wazuh["results"]}
    assert 'frequency="10"' in rows["Brute Force From One Source Address"]["queries"][0]
    assert rows["Password Spray Many Users From One Source"]["error"]


def test_convert_each_target():
    rules = sample_rules()
    for target in client.get("/api/targets").json()["targets"]:
        fmt = "data_model" if target["id"] == "splunk_cim" else "default"
        res = client.post("/api/convert", json={"rules": rules, "target": target["id"], "format": fmt})
        assert res.status_code == 200, target["id"]
        assert res.json()["summary"]["converted"] > 0, target["id"]


def test_convert_bad_target_and_format():
    rules = sample_rules()[:1]
    assert client.post("/api/convert", json={"rules": rules, "target": "nope"}).status_code == 400
    assert client.post("/api/convert", json={"rules": rules, "target": "splunk", "format": "nope"}).status_code == 400


def test_yaml_error_is_reported():
    res = client.post("/api/convert", json={"rules": [{"name": "bad.yml", "content": "title: [oops"}], "target": "splunk"}).json()
    assert res["results"][0]["error"].startswith("YAML error")


def test_coverage_and_navigator():
    rules = sample_rules()
    cov = client.post("/api/coverage", json={"rules": rules}).json()
    assert cov["rules_tagged"] > 30
    assert cov["revoked"].get("T1562.001") == "T1685"
    assert "T1059" in cov["rollup"]
    layer = client.post("/api/coverage/navigator", json={"rules": rules, "colors": ["#000000", "#ffffff"]}).json()
    assert layer["domain"] == "enterprise-attack"
    assert layer["gradient"]["colors"] == ["#000000", "#ffffff"]


def test_spa_fallback():
    assert client.get("/coverage").status_code == 200
    assert client.get("/api/missing").status_code == 404
