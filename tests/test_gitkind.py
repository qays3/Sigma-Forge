import io
import zipfile

from app.core import gitsync


def test_fetch_picks_rules_by_kind(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("repo-main/yara/a.yar", "rule A { condition: true }")
        z.writestr("repo-main/yara/notes.yar", "just text")
        z.writestr("repo-main/rules/c.yml", "title: x\ndetection:\n  s:\n    a: 1\n  condition: s\n")
    data = buf.getvalue()
    monkeypatch.setattr(gitsync, "_get", lambda url, limit: data)
    y = gitsync.fetch("o/repo", "main", "", "yara")
    assert [r["name"] for r in y["rules"]] == ["github/o/repo/yara/a.yar"]
    s = gitsync.fetch("o/repo", "main", "", "sigma")
    assert [r["name"] for r in s["rules"]] == ["github/o/repo/rules/c.yml"]
