import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_every_page_has_a_guide():
    routes = set(re.findall(r'route\("(/[a-z]*)"', (ROOT / "web/assets/js/app.js").read_text()))
    guides = (ROOT / "web/assets/js/guides-data.js").read_text()
    covered = set(re.findall(r'route: "(/[a-z]*)"', guides))
    missing = routes - covered - {"/guides"}
    assert not missing, f"Pages without a guide: {missing}"


def test_guide_links_resolve():
    guides = (ROOT / "web/assets/js/guides-data.js").read_text()
    ids = set(re.findall(r'id: "([a-z0-9-]+)"', guides))
    for block in re.findall(r"related: \[([^\]]*)\]", guides):
        for rid in re.findall(r'"([a-z0-9-]+)"', block):
            assert rid in ids, rid


def test_every_page_has_a_guide_button():
    routes = set(re.findall(r'route\("/[a-z]*", "([a-z]+)"', (ROOT / "web/assets/js/app.js").read_text())) - {"notfound", "guides"}
    router = (ROOT / "web/assets/js/router.js").read_text()
    table = re.search(r"GUIDE_FOR = \{(.*?)\};", router, re.S).group(1)
    pairs = dict(re.findall(r'([a-z]+): "([a-z0-9-]+)"', table))
    ids = set(re.findall(r'id: "([a-z0-9-]+)"', (ROOT / "web/assets/js/guides-data.js").read_text()))
    assert routes <= set(pairs), routes - set(pairs)
    assert set(pairs.values()) <= ids
