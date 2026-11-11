import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ROOT = Path(__file__).resolve().parent.parent


def rules(group=None):
    out = []
    for r in client.get("/api/samples").json()["rules"]:
        top = r["name"].split("/")[0]
        if top == "broken":
            continue
        if group == "attack" and top != "attack":
            continue
        if group == "features" and top == "attack":
            continue
        out.append({"name": r["name"], "content": r["content"]})
    return out


def test_attack_pack_covers_every_technique():
    data = client.post("/api/coverage", json={"rules": rules("attack")}).json()
    assert data["parents_covered"] == data["parents_total"]
    assert all(t["covered"] == t["total"] for t in data["tactics"])


def test_logtest_on_sample_logs():
    files = [("files", (p.name, p.read_bytes(), "application/json")) for p in sorted((ROOT / "sample" / "logs").glob("*"))]
    res = client.post("/api/test", data={"rules": json.dumps(rules("features")), "mode": "auto"}, files=files)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["summary"]["events"] > 50
    assert data["summary"]["errors"] == 0
    assert data["summary"]["silent_rules"] == 0
    brute = next(r for r in data["results"] if r["title"] == "Brute Force From One Source Address")
    assert brute["hits"] > 0 and brute["alerts"]


def test_logtest_rejects_bad_json():
    res = client.post("/api/test", data={"rules": json.dumps(rules("features")[:1])}, files=[("files", ("x.json", b"not json", "application/json"))])
    assert res.status_code == 400


def test_field_mapping_renames_fields():
    rule = next(r for r in rules("features") if r["name"].endswith("proc_creation_whoami_recon.yml"))
    res = client.post("/api/convert", json={"rules": [rule], "target": "splunk", "field_mapping": {"CommandLine": "process_cmd"}}).json()
    query = res["results"][0]["queries"][0]
    assert "process_cmd" in query and "CommandLine" not in query
    assert res["mapped_fields"] == {"CommandLine": 1}


def test_compare_targets():
    rule = rules("features")[0]
    data = client.post("/api/compare", json={"rules": [rule], "targets": ["splunk", "elastic_esql", "wazuh"]}).json()
    assert [t["target"]["id"] for t in data["targets"]] == ["splunk", "elastic_esql", "wazuh"]
    assert all(t["summary"]["failed"] == 0 for t in data["targets"])


def test_export_packages_are_valid_zips():
    packages = client.get("/api/export/packages").json()["packages"]
    body = rules("features")
    for target, pkgs in [("splunk", "splunk_app"), ("elastic_esql", "kibana_rules"), ("sentinel_asim", "sentinel_arm"), ("wazuh", "wazuh_rules"), ("sqlite", "zircolite")]:
        assert pkgs in {p["id"] for p in packages[target]}
        res = client.post("/api/export", json={"rules": body, "target": target, "package": pkgs, "name": "t"})
        assert res.status_code == 200, res.text
        archive = zipfile.ZipFile(io.BytesIO(res.content))
        names = archive.namelist()
        assert "t/manifest.json" in names and "t/README.md" in names
        for name in names:
            if name.endswith(".json"):
                json.loads(archive.read(name))
            if name.endswith(".ndjson"):
                for line in archive.read(name).decode().splitlines():
                    json.loads(line)


def test_elastic_siem_rules_work_offline():
    picked = [r for r in rules("features") if r["name"].startswith("windows/")][:6]
    res = client.post("/api/convert", json={"rules": picked, "target": "elastic_lucene", "format": "siem_rule_ndjson"}).json()
    assert res["summary"]["failed"] == 0


def test_fields_listing():
    data = client.post("/api/fields", json={"rules": rules("features")}).json()
    names = {f["name"] for f in data["fields"]}
    assert {"CommandLine", "Image"} <= names


def test_library_status_without_sync():
    data = client.get("/api/library/status").json()
    assert "available" in data
