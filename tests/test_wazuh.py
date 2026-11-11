import re
import xml.etree.ElementTree as ET

import pytest
from sigma.rule import SigmaRule

from app.core.wazuh import WazuhBackend, WazuhConversionError, WazuhOptions


def convert(yaml_text, **opts):
    backend = WazuhBackend(WazuhOptions(**opts))
    return backend.convert_rule(SigmaRule.from_yaml(yaml_text))


def fields(xml_text):
    root = ET.fromstring(xml_text)
    out = []
    for rule in root.findall("rule"):
        items = {}
        for f in rule.findall("field"):
            items[f.get("name")] = (f.text, f.get("negate") == "yes")
        out.append(items)
    return out


def matches(pattern, negate, value):
    hit = re.search(pattern, value) is not None
    return not hit if negate else hit


RULE = """
title: Test
id: 11111111-2222-3333-4444-555555555555
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {product: windows, category: process_creation}
detection:
  sel_img:
    Image|endswith: ['\\\\powershell.exe', '\\\\pwsh.exe']
  sel_cli:
    CommandLine|contains: [' -enc ', ' -ec ']
  filter:
    ParentImage|startswith: 'C:\\\\Program Files\\\\'
  condition: all of sel_* and not filter
"""


def test_single_rule_and_parent():
    res = convert(RULE, double_backslash=False)
    assert len(res.rule_ids) == 1
    root = ET.fromstring(res.xml)
    rule = root.find("rule")
    assert rule.get("level") == "12"
    assert rule.find("if_group").text == "sysmon"
    assert rule.find("mitre/id").text == "T1059.001"


def test_field_semantics_single_backslash():
    f = fields(convert(RULE, double_backslash=False).xml)[0]
    img, neg = f["win.eventdata.image"]
    assert matches(img, neg, r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe")
    assert not matches(img, neg, r"C:\Windows\System32\cmd.exe")
    cli, neg = f["win.eventdata.commandLine"]
    assert matches(cli, neg, "powershell -ENC AAAA")
    assert not matches(cli, neg, "powershell -File x.ps1")
    parent, neg = f["win.eventdata.parentImage"]
    assert neg
    assert matches(parent, neg, r"C:\Windows\explorer.exe")
    assert not matches(parent, neg, r"C:\Program Files\Agent\agent.exe")
    eid, neg = f["win.system.eventID"]
    assert matches(eid, neg, "1") and not matches(eid, neg, "11")


def test_double_backslash():
    f = fields(convert(RULE, double_backslash=True).xml)[0]
    img, neg = f["win.eventdata.image"]
    assert matches(img, neg, r"C:\\Windows\\powershell.exe")
    assert not matches(img, neg, r"C:\Windows\powershell.exe")


def test_or_across_fields_splits():
    yaml_text = """
title: Split
level: medium
logsource: {product: windows, category: process_creation}
detection:
  a:
    - Image|endswith: '\\\\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'
  b:
    CommandLine|contains|all: ['urlcache', 'http']
  condition: a and b
"""
    res = convert(yaml_text, double_backslash=False)
    assert len(res.rule_ids) == 2
    for f in fields(res.xml):
        cli, neg = f["win.eventdata.commandLine"]
        assert matches(cli, neg, "certutil -urlcache -f http://x/a.exe")
        assert not matches(cli, neg, "certutil -urlcache -f a.exe")


def test_compare_modifier_fails():
    yaml_text = """
title: Cmp
logsource: {product: windows, category: process_creation}
detection:
  sel:
    ProcessId|gt: 4
  condition: sel
"""
    with pytest.raises(WazuhConversionError):
        convert(yaml_text)


def test_keyword_and_security_channel():
    yaml_text = """
title: Kw
logsource: {product: windows, service: security}
detection:
  sel:
    EventID: 4625
  keywords:
    - 'mimikatz'
  condition: sel and keywords
"""
    root = ET.fromstring(convert(yaml_text).xml)
    rule = root.find("rule")
    assert rule.find("if_group").text == "windows"
    assert rule.find("regex") is not None
    names = [f.get("name") for f in rule.findall("field")]
    assert "win.system.channel" in names and "win.system.eventID" in names


def test_explosion_limit():
    values = "\n".join(f"    - F{i}: v" for i in range(8))
    yaml_text = f"""
title: Big
logsource: {{product: windows, category: process_creation}}
detection:
  a:
{values}
  b:
{values.replace('F', 'G')}
  condition: a and b
"""
    with pytest.raises(WazuhConversionError):
        convert(yaml_text, max_split=32)
