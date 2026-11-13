import io
import zipfile

import pytest

from app.core import yaralib

PACK = '''/*
 * YARA-Forge YARA Rule Package
 * Name: core
 * Creation Date: 2026-11-08
 */
import "pe"

/*
 * Repository Name: Repo One
 */
private rule ONE_Helper
{
	condition:
		uint16(0) == 0x5A4D
}

rule ONE_Main : FILE MEMORY
{
	meta:
		description = "Finds a \\"thing\\" in files"
		author = "Someone"
		date = "2024-01-02"
		score = 80
		quality = 90
		tags = "FILE, RAT"
		reference = "https://example.org/a // not a comment"
	strings:
		$a = "abc{" ascii
		$re = /https?:\\/\\/x\\.y/
	condition:
		ONE_Helper and pe.number_of_sections > 1 and any of them
}

/*
 * Repository Name: Repo Two
 */
rule TWO_Plain
{
	meta:
		description = "Plain"
	strings:
		$b = { 4D 5A }
	condition:
		$b
}
'''


def _zip(text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("packages/core/yara-rules-core.yar", text)
    return buf.getvalue()


def test_install_search_and_read(tmp_path, monkeypatch):
    monkeypatch.setattr(yaralib, "DIR", tmp_path)
    yaralib._cache.update(mtime=None, index=None, content=None)
    st = yaralib.install_zip(_zip(PACK))
    assert st["available"] and st["rules"] == 3 and st["package"] == "core" and st["release"] == "2026-11-08"
    assert {r["name"] for r in st["repos"]} == {"Repo One", "Repo Two"}
    res = yaralib.search("thing")
    assert res["total"] == 1 and res["rules"][0]["name"] == "ONE_Main"
    main = res["rules"][0]
    assert main["repo"] == "Repo One" and main["score"] == 80 and "RAT" in main["tags"] and main["deps"] == ["ONE_Helper"]
    assert yaralib.search(repo="Repo Two")["total"] == 1
    assert yaralib.search(min_score=70)["total"] == 1
    got = yaralib.read_rules(["ONE_Main"])[0]
    assert got["rules"] == ["ONE_Helper", "ONE_Main"] and got["content"].startswith('import "pe"')
    yara = pytest.importorskip("yara")
    yara.compile(source=got["content"])
    yara.compile(source=yaralib.read_rules(["TWO_Plain"])[0]["content"])


def test_bad_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(yaralib, "DIR", tmp_path)
    with pytest.raises(yaralib.YaraLibError):
        yaralib.install_zip(b"not a zip")
    with pytest.raises(yaralib.YaraLibError):
        yaralib.install_zip(_zip("nothing here"))
    with pytest.raises(yaralib.YaraLibError):
        yaralib.start_sync("huge")
