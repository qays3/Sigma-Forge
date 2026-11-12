import html
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.config import APP_NAME, APP_VERSION
from app.core.analyzer import analyze
from app.core.attack import load_attack
from app.core.coverage import coverage, gaps
from app.core.parsing import ParsedRule
from app.core.threat import group_coverage, readiness

CSS = """
:root{--ink:#1B1530;--mut:#5F5A73;--line:#E4E0EE;--soft:#F6F3FC;--v:#7B2FE0;--v2:#B06CFF;--ok:#1F9D6B;--warn:#B7841A;--bad:#D23B5E}
*{box-sizing:border-box}body{margin:0;font-family:"Archivo","Segoe UI",Arial,sans-serif;color:var(--ink);background:#fff;font-size:14px;line-height:1.5}
.wrap{max-width:1040px;margin:0 auto;padding:40px 44px 60px}
header{background:linear-gradient(120deg,#120A24,#2A1257 60%,#4B1E96);color:#fff;padding:38px 44px;border-radius:0 0 18px 18px}
header .eb{font-family:"IBM Plex Mono",Consolas,monospace;font-size:12px;letter-spacing:.2em;color:#CDB2FF;text-transform:uppercase}
header h1{margin:8px 0 6px;font-size:34px;font-family:"Chakra Petch","Segoe UI",sans-serif}
header p{margin:0;color:#D9CCF5}
h2{font-family:"Chakra Petch","Segoe UI",sans-serif;font-size:22px;margin:36px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--line)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:26px}
.kpi{border:1px solid var(--line);border-radius:12px;padding:14px 16px;background:var(--soft)}
.kpi b{display:block;font-size:28px;font-family:"Chakra Petch","Segoe UI",sans-serif;color:var(--v)}
.kpi span{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.08em}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--line);padding:8px 6px}
td{border-bottom:1px solid var(--line);padding:7px 6px;vertical-align:top}
.bar{height:8px;background:var(--line);border-radius:99px;overflow:hidden;min-width:120px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--v),var(--v2));border-radius:99px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600;border:1px solid var(--line);background:#fff}
.ok{color:var(--ok);border-color:#BFE6D5}.warn{color:var(--warn);border-color:#EED9A8}.bad{color:var(--bad);border-color:#F2C2CF}
.mono{font-family:"IBM Plex Mono",Consolas,monospace;font-size:12px}
.note{color:var(--mut);font-size:12.5px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:24px}
footer{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media print{header{border-radius:0}.wrap{padding:24px 0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _pct(a, b) -> int:
    return round(a * 100 / b) if b else 0


def _bar(p: int) -> str:
    return f'<div class="bar"><i style="width:{max(0, min(100, p))}%"></i></div>'


def build_report(parsed: List[ParsedRule], title: str = "", group: Optional[str] = None, collected: Optional[List[str]] = None) -> str:
    attack = load_attack()
    cov = coverage(parsed)
    ana = analyze(parsed)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = title or "Detection coverage report"
    parts: List[str] = []
    tactics_full = sum(1 for t in cov["tactics"] if t["total"] and t["covered"] == t["total"])
    s = ana["summary"]
    parts.append('<div class="kpis">')
    for label, value in [
        ("Rules", s["valid"]),
        ("Techniques covered", f'{cov["parents_covered"]}/{cov["parents_total"]}'),
        ("Coverage", f'{_pct(cov["parents_covered"], cov["parents_total"])}%'),
        ("Average rule quality", f'{s.get("quality", 0)}/100'),
    ]:
        parts.append(f'<div class="kpi"><b>{_e(value)}</b><span>{_e(label)}</span></div>')
    parts.append("</div>")
    parts.append(f'<p class="note">{tactics_full} of {len(cov["tactics"])} tactics are fully covered. ATT&amp;CK Enterprise v{_e(cov["attack_version"])}.</p>')

    parts.append("<h2>Coverage by tactic</h2><table><thead><tr><th>Tactic</th><th>Covered</th><th style='width:40%'></th><th>Rules tagged</th></tr></thead><tbody>")
    for t in cov["tactics"]:
        p = _pct(t["covered"], t["total"])
        parts.append(f'<tr><td>{_e(t["name"])}</td><td>{t["covered"]} / {t["total"]} ({p}%)</td><td>{_bar(p)}</td><td>{cov["tactic_tags"].get(t["short"], 0)}</td></tr>')
    parts.append("</tbody></table>")

    if collected is not None:
        r = readiness(parsed, collected)["summary"]
        parts.append("<h2>Log source readiness</h2>")
        parts.append(f'<p>You collect <b>{r["collected"]}</b> of the <b>{r["sources_total"]}</b> log sources your rules use. '
                     f'<b>{r["rules_ready"]}</b> of <b>{r["rules_total"]}</b> rules can run. Real coverage is '
                     f'<b>{r["techniques_ready"]}</b> techniques, against <b>{r["techniques_on_paper"]}</b> on paper.</p>')
        if r["missing_sources"]:
            parts.append('<p class="note">Missing log sources: ' + ", ".join(f'<span class="mono">{_e(m)}</span>' for m in r["missing_sources"][:40]) + "</p>")
        if r["blind"]:
            parts.append('<p class="note">Techniques that are blind without those sources: ' + ", ".join(f'{_e(b["id"])} {_e(b["name"])}' for b in r["blind"][:30]) + "</p>")

    if group:
        g = group_coverage(cov, group)
        if g:
            parts.append(f'<h2>Threat group: {_e(g["name"])} ({_e(g["id"])})</h2>')
            parts.append(f'<p>{_e(g["description"])}</p>')
            parts.append(f'<p><b>{g["covered"]}</b> covered, <b>{g["partial"]}</b> partly covered and <b>{g["missing"]}</b> missing out of <b>{g["total"]}</b> techniques this group is known to use ({g["percent"]}%).</p>')
            parts.append("<table><thead><tr><th>Technique</th><th>Tactics</th><th>State</th></tr></thead><tbody>")
            for row in g["techniques"]:
                cls = {"covered": "ok", "partial": "warn", "missing": "bad"}[row["state"]]
                parts.append(f'<tr><td><span class="mono">{_e(row["id"])}</span> {_e(row["name"])}</td><td>{_e(", ".join(row["tactics"]))}</td><td><span class="pill {cls}">{row["state"]}</span></td></tr>')
            parts.append("</tbody></table>")

    parts.append('<h2>Log sources</h2><table><thead><tr><th>Log source</th><th>Rules</th><th>Techniques</th></tr></thead><tbody>')
    for src in cov["logsources"]:
        parts.append(f'<tr><td class="mono">{_e(src["label"])}</td><td>{src["rules"]}</td><td>{len(src["techniques"])}</td></tr>')
    parts.append("</tbody></table>")

    gp = gaps(parsed, limit=20)
    if gp.get("available"):
        parts.append(f'<h2>Biggest gaps</h2><p class="note">Techniques the SigmaHQ library covers and these rules do not ({gp["missing"]} in total). The top 20 by number of community rules:</p>')
        parts.append("<table><thead><tr><th>Technique</th><th>Tactics</th><th>SigmaHQ rules</th></tr></thead><tbody>")
        for t in gp["techniques"]:
            parts.append(f'<tr><td><span class="mono">{_e(t["id"])}</span> {_e(t["name"])}</td><td>{_e(", ".join(t["tactics"]))}</td><td>{t["library_rules"]}</td></tr>')
        parts.append("</tbody></table>")

    parts.append('<h2>Rules</h2><table><thead><tr><th>Rule</th><th>Level</th><th>Techniques</th><th>Quality</th></tr></thead><tbody>')
    for r in sorted((x for x in ana["rules"] if not x["error"]), key=lambda x: (x.get("title") or "").lower()):
        q = r.get("quality", {})
        cls = "ok" if q.get("grade") in ("A", "B") else "warn" if q.get("grade") == "C" else "bad"
        parts.append(f'<tr><td>{_e(r["title"])}<div class="note mono">{_e(r["key"])}</div></td><td>{_e(r.get("level"))}</td>'
                     f'<td class="mono">{_e(", ".join(r.get("techniques") or []))}</td><td><span class="pill {cls}">{_e(q.get("grade"))} {q.get("score", 0)}</span></td></tr>')
    parts.append("</tbody></table>")

    body = "\n".join(parts)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><header><div class="eb">{_e(APP_NAME)} report</div><h1>{_e(title)}</h1><p>Generated {stamp} from {s["valid"]} rules.</p></header>
<div class="wrap">{body}<footer>Made with {_e(APP_NAME)} {_e(APP_VERSION)}. Print this page or save it as PDF from your browser.</footer></div></body></html>"""


LEVEL_CLASS = {"critical": "bad", "high": "bad", "medium": "warn", "low": "ok", "informational": "ok"}

NEXT_STEPS = {
    "initial-access": "Find the first entry point: mail, web or remote service logs around the first hit.",
    "execution": "Collect the scripts and binaries that ran and check their hashes.",
    "persistence": "Remove the run keys, services or tasks that were added, after you save copies.",
    "privilege-escalation": "Check which accounts gained rights and reset them.",
    "credential-access": "Reset passwords for every account used on these hosts and look for reuse elsewhere.",
    "discovery": "Look for what the attacker learned next: lateral movement usually follows discovery.",
    "lateral-movement": "Scope every host the account touched and isolate the ones with hits.",
    "collection": "Find which files were gathered and where they were staged.",
    "command-and-control": "Block the remote IPs and domains at the edge and search for them on other hosts.",
    "exfiltration": "Estimate what data left and from which host. Start the data breach process if needed.",
    "impact": "Isolate the hosts now and check backups before you restore.",
    "stealth": "Assume logs may be missing. Collect memory and disk images before cleaning.",
    "defense-impairment": "Turn security tools back on and check which ones were changed.",
}


def build_hunt_report(result: Dict, title: str = "", scope: str = "") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = title or "Hunt report"
    s = result.get("summary", {})
    tl = result.get("timeline") or {"items": [], "hosts": [], "tactics": []}
    fired = [r for r in result.get("results", []) if r.get("hits")]
    fired.sort(key=lambda r: (-{"critical": 5, "high": 4, "medium": 3, "low": 2}.get(r.get("level") or "", 0), -r["hits"]))
    worst = max(({"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(r.get("level") or "", 0) for r in fired), default=0)
    verdict = {5: ("Critical", "bad"), 4: ("High", "bad"), 3: ("Medium", "warn"), 2: ("Low", "ok"), 1: ("Low", "ok")}.get(worst, ("Clean", "ok"))
    parts: List[str] = ['<div class="kpis">']
    for label, value in [("Events", s.get("events", 0)), ("Rules that fired", f'{s.get("matched_rules", 0)} / {s.get("tested", 0)}'),
                         ("Hosts with hits", len(tl.get("hosts", []))), ("Highest level", verdict[0])]:
        parts.append(f'<div class="kpi"><b>{_e(value)}</b><span>{_e(label)}</span></div>')
    parts.append("</div>")
    if scope:
        parts.append(f'<p class="note">Scope: {_e(scope)}</p>')
    if result.get("channels"):
        parts.append("<h2>Logs read</h2><table><thead><tr><th>Log</th><th>Events</th><th>Note</th></tr></thead><tbody>")
        for c in result["channels"]:
            parts.append(f'<tr><td class="mono">{_e(c.get("channel"))}</td><td>{c.get("events", 0)}</td><td>{_e(c.get("error") or "")}</td></tr>')
        parts.append("</tbody></table>")
    if not fired:
        parts.append('<h2>Result</h2><p>No rule fired on these events. That is a good sign, but check that the right logs were collected.</p>')
    else:
        parts.append("<h2>Hosts</h2><table><thead><tr><th>Host</th><th>Highest level</th><th>Hits</th><th>First seen</th><th>Last seen</th><th>Furthest stage</th></tr></thead><tbody>")
        for h in tl.get("hosts", []):
            parts.append(f'<tr><td class="mono">{_e(h["host"])}</td><td><span class="pill {LEVEL_CLASS.get(h["top"], "")}">{_e(h["top"])}</span></td><td>{h["hits"]}</td>'
                         f'<td class="mono">{_e(h["first"])}</td><td class="mono">{_e(h["last"])}</td><td>{_e(h["stage"])}</td></tr>')
        parts.append("</tbody></table>")
        if tl.get("tactics"):
            parts.append('<h2>Attack path</h2><p>' + " &rarr; ".join(f'<span class="pill">{_e(t["name"])}</span>' for t in tl["tactics"]) + "</p>")
            steps = [NEXT_STEPS[t["short"]] for t in tl["tactics"] if t["short"] in NEXT_STEPS]
            if steps:
                parts.append("<h2>Next steps</h2><ol>" + "".join(f"<li>{_e(x)}</li>" for x in reversed(steps)) + "</ol>")
        parts.append("<h2>Rules that fired</h2><table><thead><tr><th>Rule</th><th>Level</th><th>Hits</th><th>Techniques</th><th>Noise</th></tr></thead><tbody>")
        for r in fired:
            noise = (r.get("noise") or {}).get("level", "")
            parts.append(f'<tr><td>{_e(r["title"])}<div class="note mono">{_e(r["key"])}</div></td><td><span class="pill {LEVEL_CLASS.get(r.get("level") or "", "")}">{_e(r.get("level"))}</span></td>'
                         f'<td>{r["hits"]}</td><td class="mono">{_e(", ".join(r.get("techniques") or []))}</td><td>{_e(noise)}</td></tr>')
        parts.append("</tbody></table>")
        items = tl.get("items", [])
        parts.append(f'<h2>Timeline</h2><p class="note">{len(items)} hits in time order{", cut at the limit" if tl.get("truncated") else ""}.</p>')
        parts.append("<table><thead><tr><th>Time</th><th>Host</th><th>Rule</th><th>Tactic</th><th>Detail</th></tr></thead><tbody>")
        for it in items[:400]:
            parts.append(f'<tr><td class="mono">{_e(it["ts"])}</td><td class="mono">{_e(it["host"])}</td><td>{_e(it["rule"])}</td>'
                         f'<td>{_e(", ".join(it["tactics"]))}</td><td class="mono">{_e(it["summary"])}</td></tr>')
        parts.append("</tbody></table>")
    body = "\n".join(parts)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><header><div class="eb">{_e(APP_NAME)} hunt report</div><h1>{_e(title)}</h1><p>Generated {stamp}. Verdict: {_e(verdict[0])}.</p></header>
<div class="wrap">{body}<footer>Made with {_e(APP_NAME)} {_e(APP_VERSION)}. Print this page or save it as PDF from your browser.</footer></div></body></html>"""
