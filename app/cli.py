import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from app.config import APP_NAME, APP_VERSION
from app.schemas import ConvertOptions, RuleInput

EXT = (".yml", ".yaml")


def _collect(paths: List[str]) -> List[RuleInput]:
    items = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files = sorted(f for f in p.rglob("*") if f.suffix.lower() in EXT and f.is_file())
            base = p
        elif p.is_file():
            files = [p]
            base = p.parent
        else:
            print(f"Not found: {raw}", file=sys.stderr)
            sys.exit(2)
        for f in files:
            try:
                name = f.relative_to(base).as_posix()
            except ValueError:
                name = f.name
            items.append(RuleInput(name=name, content=f.read_text(encoding="utf-8", errors="replace")))
    if not items:
        print("No .yml rule files found", file=sys.stderr)
        sys.exit(2)
    return items


def _mapping(path: str):
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data.get("map", data) if isinstance(data, dict) else {}


def _summary(path: str, lines: List[str]) -> None:
    target = path or os.getenv("GITHUB_STEP_SUMMARY")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def cmd_validate(args) -> int:
    from app.core.analyzer import analyze
    from app.core.parsing import parse_inputs

    items = _collect(args.paths)
    res = analyze(parse_inputs(items))
    fail = 0
    rows = []
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    limit = order.get(args.fail_on, 99)
    for r in res["rules"]:
        q = r.get("quality", {})
        worst = max([order.get(i["severity"], 0) for i in r["issues"]] or [0])
        bad = bool(r["error"]) or worst >= limit or (args.min_quality and q.get("score", 0) < args.min_quality)
        fail += 1 if bad else 0
        mark = "FAIL" if bad else "ok"
        if bad or args.verbose:
            print(f"[{mark}] {r['key']}  quality {q.get('grade', '-')} {q.get('score', 0)}")
            if r["error"]:
                print(f"       error: {r['error']}")
            for i in r["issues"]:
                print(f"       {i['severity']}: {i['message']}")
        rows.append(f"| {'fail' if bad else 'pass'} | `{r['key']}` | {q.get('grade', '-')} {q.get('score', 0)} | {len(r['issues'])} |")
    s = res["summary"]
    print(f"\n{s['valid']} valid, {s['errors']} errors, {s['with_issues']} with findings, average quality {s.get('quality', 0)}. {fail} failed the gate.")
    _summary(args.summary, [f"## {APP_NAME} validate", "", f"{s['valid']} valid rules, {s['errors']} errors, average quality {s.get('quality', 0)}, **{fail} failed**.", "",
                            "| | Rule | Quality | Findings |", "|---|---|---|---|"] + rows[:300])
    return 1 if fail else 0


def cmd_convert(args) -> int:
    from app.core.converter import convert

    items = _collect(args.paths)
    res = convert(items, args.target, args.format, ConvertOptions(), _mapping(args.mapping))
    failed = [r for r in res["results"] if r["error"]]
    if args.output:
        out = Path(args.output)
        if out.suffix:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(res["bundle"] or "\n\n".join(q for r in res["results"] for q in r["queries"]), encoding="utf-8")
        else:
            out.mkdir(parents=True, exist_ok=True)
            for r in res["results"]:
                if r["queries"]:
                    stem = r["key"].replace("/", "__").replace("#", "_")
                    (out / f"{stem}.txt").write_text("\n\n".join(r["queries"]) + "\n", encoding="utf-8")
    else:
        for r in res["results"]:
            if r["queries"]:
                print(f"# {r['title']} ({r['key']})")
                print("\n\n".join(r["queries"]))
                print()
    for r in failed:
        print(f"failed: {r['key']}: {r['error']}", file=sys.stderr)
    s = res["summary"]
    print(f"{res['target']['name']}: {s['converted']} converted, {s['skipped']} skipped, {s['failed']} failed", file=sys.stderr)
    _summary(args.summary, [f"## {APP_NAME} convert to {res['target']['name']}", "", f"{s['converted']} converted, {s['skipped']} skipped, **{s['failed']} failed**."]
             + [f"* `{r['key']}`: {r['error']}" for r in failed[:100]])
    return 1 if failed and args.strict else 0


def cmd_test(args) -> int:
    from app.core.logtest import run_test

    items = _collect(args.paths)
    blobs = []
    if args.generate:
        from app.core.eventgen import generate, to_jsonl

        blobs.append(("generated.jsonl", to_jsonl(generate(items)["events"]).encode()))
    for f in args.logs or []:
        blobs.append((Path(f).name, Path(f).read_bytes()))
    if not blobs:
        print("Add --logs files or --generate", file=sys.stderr)
        return 2
    res = run_test(items, blobs, args.mode)
    s = res["summary"]
    silent = [r for r in res["results"] if r["status"] == "ok" and not r["hits"]]
    for r in res["results"]:
        if r["hits"] or args.verbose:
            print(f"{r['hits']:>6}  {r['title']}  ({r['key']})")
    print(f"\n{s['events']} events, {s['matched_rules']} of {s['tested']} rules fired, {s['errors']} errors.")
    _summary(args.summary, [f"## {APP_NAME} test", "", f"{s['events']} events, {s['matched_rules']} of {s['tested']} rules fired, {len(silent)} silent, {s['errors']} errors."]
             + [f"* silent: `{r['key']}`" for r in silent[:100]])
    if args.expect_all and silent:
        return 1
    return 1 if s["errors"] else 0


def cmd_coverage(args) -> int:
    from app.core.coverage import coverage, navigator_layer
    from app.core.parsing import parse_inputs

    items = _collect(args.paths)
    parsed = parse_inputs(items)
    cov = coverage(parsed)
    pct = round(cov["parents_covered"] * 100 / cov["parents_total"]) if cov["parents_total"] else 0
    print(f"{cov['parents_covered']} of {cov['parents_total']} techniques covered ({pct}%)")
    for t in cov["tactics"]:
        print(f"  {t['name']:<24} {t['covered']:>3} / {t['total']}")
    if args.navigator:
        from app.schemas import NavigatorRequest

        colors = NavigatorRequest(rules=[]).colors
        Path(args.navigator).write_text(json.dumps(navigator_layer(parsed, args.name or f"{APP_NAME} coverage", colors), indent=2), encoding="utf-8")
        print(f"Navigator layer saved to {args.navigator}")
    if args.report:
        from app.core.report import build_report

        Path(args.report).write_text(build_report(parsed, args.name or "", args.group), encoding="utf-8")
        print(f"Report saved to {args.report}")
    _summary(args.summary, [f"## {APP_NAME} coverage", "", f"**{pct}%** of ATT&CK techniques covered ({cov['parents_covered']} of {cov['parents_total']}).", "",
                            "| Tactic | Covered |", "|---|---|"] + [f"| {t['name']} | {t['covered']} / {t['total']} |" for t in cov["tactics"]])
    return 1 if args.min_coverage and pct < args.min_coverage else 0


def cmd_export(args) -> int:
    from app.core.export import build_export

    items = _collect(args.paths)
    filename, data, summary = build_export(items, args.target, args.format, ConvertOptions(), _mapping(args.mapping), args.package, args.name)
    out = Path(args.output or filename)
    out.write_bytes(data)
    print(f"Saved {out} ({summary['converted']} converted, {summary['failed']} failed)")
    return 0


def cmd_unit(args) -> int:
    from app.core.unittests import run_units

    items = []
    tests = {}
    for raw in args.paths:
        p = Path(raw)
        files = sorted(f for f in p.rglob("*") if f.suffix.lower() in EXT and f.is_file()) if p.is_dir() else [p]
        for f in files:
            side = f.with_name(f.stem + ".tests.json")
            if not side.is_file():
                continue
            items.append(RuleInput(name=f.as_posix(), content=f.read_text(encoding="utf-8", errors="replace")))
            tests[f.as_posix()] = json.loads(side.read_text(encoding="utf-8"))
    if not items:
        print("No rules with a .tests.json file next to them", file=sys.stderr)
        return 2
    res = run_units(items, tests, args.mode)
    for r in res["rules"]:
        mark = "PASS" if not r["failed"] and r["status"] == "ok" else "FAIL"
        print(f"{mark}  {r['passed']}/{r['passed'] + r['failed']}  {r['name']}" + (f"  {r['message']}" if r["message"] else ""))
        for c in r["cases"]:
            if not c["ok"] or args.verbose:
                want = "should match" if c["kind"] == "match" else "should not match"
                print(f"        {'ok ' if c['ok'] else 'BAD'} {want} #{c['index'] + 1}: {c['label']}")
    print(f"\n{res['passed']} cases passed, {res['failed']} failed, in {len(res['rules'])} rules.")
    _summary(args.summary, [f"## {APP_NAME} rule unit tests", "", f"{res['passed']} passed, {res['failed']} failed."]
             + [f"* failed: `{r['name']}`" for r in res["rules"] if r["failed"] or r["status"] != "ok"])
    return 1 if res["failed"] or res["rules_failed"] else 0


def cmd_sysmon(args) -> int:
    from app.core.sysmon import build

    res = build(_collect(args.paths))
    if res["xml"]:
        if args.output:
            Path(args.output).write_text(res["xml"], encoding="utf-8")
            print(f"Saved {args.output}")
        else:
            print(res["xml"])
    for t in res["types"]:
        print(f"# {t['event']}: {t['rules']} rules, {t['conditions']} conditions" + (" (logs all events)" if t["all"] else ""), file=sys.stderr)
    if res["script"]:
        print("\n# Audit policy and logging commands, run as admin:", file=sys.stderr)
        print(res["script"], file=sys.stderr)
    return 0


def cmd_sigmahq(args) -> int:
    from app.core.sigmahq import check_inputs

    res = check_inputs(_collect(args.paths))
    bad = 0
    for r in res["rules"]:
        if r["errors"]:
            bad += 1
        if r["errors"] or r["warnings"] or args.verbose:
            print(f"{r['score']:>3}  {r['name']}" + (f"  -> rename to {r['suggested_name']}" if r["suggested_name"] else ""))
            for c in r["checks"]:
                if c["level"] != "info" or args.verbose:
                    print(f"       {c['level']:<5} {c['text']}")
    print(f"\n{res['ready']} of {res['total']} rules are ready for SigmaHQ, {bad} have errors.")
    return 1 if bad else 0


def cmd_import(args) -> int:
    from app.core.siemimport import import_rules

    files = [(Path(f).name, Path(f).read_text(encoding="utf-8-sig")) for f in args.files]
    res = import_rules(files, args.kind, args.include_disabled)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    for r in res["rules"]:
        (out / r["name"]).write_text(r["content"], encoding="utf-8")
        print(f"ok    {r['name']}  ({r['kind']})")
    for f in res["failed"]:
        print(f"fail  {f['name']}: {f['error']}", file=sys.stderr)
    for e in res["errors"]:
        print(f"error {e['name']}: {e['error']}", file=sys.stderr)
    print(f"\n{res['converted']} of {res['found']} converted into {out}, {res['skipped']} disabled skipped.")
    return 1 if res["failed"] or res["errors"] else 0


def _logs(paths):
    out = []
    for raw in paths or []:
        p = Path(raw)
        files = sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".evtx", ".json", ".jsonl", ".ndjson", ".zip")) if p.is_dir() else [p]
        out.extend((f.name, f.read_bytes()) for f in files)
    return out


def cmd_firecheck(args) -> int:
    from app.core.firecheck import PLATFORMS, run

    if args.platform not in PLATFORMS:
        print(f"Unknown platform. Use one of: {', '.join(PLATFORMS)}", file=sys.stderr)
        return 2
    settings = json.loads(Path(args.settings).read_text(encoding="utf-8")) if args.settings else {}
    mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8")) if args.mapping else {}
    files = _logs(args.logs)
    if args.sample:
        sample = Path(__file__).resolve().parent.parent / "sample" / "logs" / "attack_chain_sysmon.jsonl"
        files.append((sample.name, sample.read_bytes()))
    params = {"rules": _collect(args.paths), "platform": args.platform, "target": args.target or PLATFORMS[args.platform]["targets"][0],
              "mode": args.mode, "hours": args.hours, "settings": settings, "mapping": mapping, "files": files, "attack": "rules" if args.attack else []}
    job = {"status": "running", "params": params, "stage": "", "done": 0, "total": 0, "error": "", "result": None}
    run(job)
    if job["status"] != "done":
        print(f"Fire check failed: {job['error']}", file=sys.stderr)
        return 2
    res = job["result"]
    for r in res["results"]:
        if r["verdict"] in ("untested", "skipped") and not args.verbose:
            continue
        miss = ", ".join((r.get("diagnosis") or {}).get("missing", [])[:4])
        print(f"{r['verdict'].upper():<9} {str(r.get('expected', '')):>4} {str(r.get('got', '')):>5}  {r['title']}" + (f"  missing: {miss}" if miss else "") + (f"  {r['error'][:100]}" if r["error"] else ""))
    score = res["score"]
    print(f"\nFire score {score if score is not None else 'none'}% on {res['platform_name']}: {res['fired']} of {res['should_fire']} rules fire. {res['counts'].get('silent', 0)} silent, {res['counts'].get('error', 0)} errors.")
    if res.get("alias_config"):
        print("\nField aliases that would fix the platform:\n" + res["alias_config"])
    if res.get("mapping"):
        print("\nMapping that would fix the rules:\n" + json.dumps(res["mapping"], indent=2))
    _summary(args.summary, [f"## {APP_NAME} fire check on {res['platform_name']}", "", f"Fire score **{score}%**: {res['fired']} of {res['should_fire']} rules fire."]
             + [f"* {r['verdict']}: {r['title']}" for r in res["results"] if r["verdict"] in ("silent", "partial", "error")][:100])
    if score is not None and score < args.min_score:
        return 1
    return 0


def cmd_deploy(args) -> int:
    from app.core.deploy import DeployError, deploy
    from app.core.firecheck import FireError, resolve
    from app.schemas import ConvertOptions

    try:
        settings = resolve(json.loads(Path(args.settings).read_text(encoding="utf-8")) if args.settings else {})
    except FireError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8")) if args.mapping else {}
    opts = ConvertOptions(splunk_windows_source=settings.pop("splunk_windows_source", "") or "")
    try:
        res = deploy(_collect(args.paths), args.kind, args.target, settings, opts, mapping, args.dry_run)
    except DeployError as exc:
        print(f"Deploy failed: {exc}", file=sys.stderr)
        return 2
    bad = 0
    for st in res.get("results", []):
        if st.get("status") == "failed":
            bad += 1
        print(f"{st.get('status', ''):<8} {st.get('title', '')}" + (f"  {st.get('message', '')}" if st.get("message") else ""))
    print(f"\n{len(res.get('results', []))} steps, {bad} failed{' (dry run)' if res.get('dry_run') else ''}.")
    return 1 if bad else 0


def cmd_from_query(args) -> int:
    from app.core.querygen import convert_query

    text = Path(args.query).read_text(encoding="utf-8") if args.query and Path(args.query).is_file() else (args.query or sys.stdin.read())
    res = convert_query(text, args.language, args.title, args.level)
    for w in res["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    if res["error"]:
        print(f"error: {res['error']}", file=sys.stderr)
    if args.output:
        Path(args.output).write_text(res["yaml"], encoding="utf-8")
        print(f"Saved {args.output} ({res['language_name']})")
    else:
        print(res["yaml"], end="")
    return 1 if res["error"] else 0


def cmd_hunt(args) -> int:
    from app.core.hunt import channel_list, collect, os_kind
    from app.core.logtest import run_test

    if os_kind() not in ("windows", "linux", "macos"):
        print("Live log scans need Windows, Linux or macOS. Use 'test --logs file.evtx' instead.", file=sys.stderr)
        return 2
    items = _collect(args.paths)
    names = {c["name"].lower(): c["id"] for c in channel_list()}
    default = ["sysmon", "security", "powershell", "system"] if os_kind() == "windows" else [c["id"] for c in channel_list()]
    channels = [names.get(c.lower(), c) for c in (args.channels or default)]
    blobs, stats = collect(channels, args.hours, args.max_events)
    for st in stats:
        print(f"{st['channel']}: {st['error'] or str(st['events']) + ' events'}")
    if not blobs:
        return 2
    res = run_test(items, blobs, "auto")
    hits = [r for r in res["results"] if r["hits"]]
    for r in sorted(hits, key=lambda x: -x["hits"]):
        print(f"{r['hits']:>6}  {r['level'] or '':<8} {r['title']}  ({r['key']})")
    s = res["summary"]
    print(f"\n{s['events']} events, {s['matched_rules']} rules fired, {s['errors']} errors.")
    _summary(args.summary, [f"## {APP_NAME} hunt", "", f"{s['events']} events, {s['matched_rules']} rules fired."] + [f"* {r['hits']} hits: {r['title']}" for r in hits[:100]])
    return 1 if hits and args.fail_on_hit else 0


def cmd_yara(args) -> int:
    from app.core.yara_engine import check, scan_paths

    rules = []
    for raw in args.rules:
        p = Path(raw)
        files = sorted(f for f in p.rglob("*") if f.suffix.lower() in (".yar", ".yara")) if p.is_dir() else [p]
        rules += [(f.name, f.read_text(encoding="utf-8", errors="replace")) for f in files]
    if not rules:
        print("No .yar rule files found", file=sys.stderr)
        return 2
    checked = check(rules)
    for f in checked["files"]:
        if not f["ok"]:
            print(f"rule error in {f['name']}: {f['error']}", file=sys.stderr)
    if checked["errors"]:
        return 2
    if not args.scan:
        print(f"{checked['rules']} YARA rules in {len(rules)} files, all valid.")
        return 0
    res = scan_paths(rules, args.scan, not args.no_recursive, args.max_files, args.max_size * 1024 * 1024)
    for f in res["files"]:
        print(f"{f['name']}: {', '.join(m['rule'] for m in f['matches'])}")
    s = res["summary"]
    print(f"\n{s['scanned']} files scanned, {s['matched_files']} matched, {s['errors']} errors in {s['seconds']}s.")
    _summary(args.summary, [f"## {APP_NAME} YARA scan", "", f"{s['scanned']} files scanned, {s['matched_files']} matched."] + [f"* `{f['name']}`: {', '.join(m['rule'] for m in f['matches'])}" for f in res["files"][:100]])
    return 1 if res["files"] and args.fail_on_hit else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sigma-forge", description=f"{APP_NAME} {APP_VERSION} command line")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("paths", nargs="+", help="Rule files or folders")
        p.add_argument("--summary", default="", help="Append a Markdown summary to this file (defaults to GITHUB_STEP_SUMMARY when set)")
        p.add_argument("-v", "--verbose", action="store_true")

    p = sub.add_parser("validate", help="Check rules and score their quality")
    common(p)
    p.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical", "never"], help="Fail on findings of this severity or worse")
    p.add_argument("--min-quality", type=int, default=0, help="Fail rules with a quality score below this")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("convert", help="Convert rules to a target query language")
    common(p)
    p.add_argument("-t", "--target", required=True, help="Target id, for example splunk, elastic_esql, sentinel_asim, wazuh")
    p.add_argument("-f", "--format", default="default")
    p.add_argument("-o", "--output", default="", help="A file for the bundle, or a folder for one file per rule")
    p.add_argument("--mapping", default="", help="JSON file with a field mapping")
    p.add_argument("--strict", action="store_true", help="Exit with an error when any rule fails")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("test", help="Run rules on log files")
    common(p)
    p.add_argument("--logs", nargs="*", help="EVTX, JSON or JSON lines files")
    p.add_argument("--generate", action="store_true", help="Also generate matching test events for every rule")
    p.add_argument("--mode", default="auto", choices=["auto", "strict", "off"])
    p.add_argument("--expect-all", action="store_true", help="Fail when any rule stays silent")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("coverage", help="ATT&CK coverage, Navigator layer and report")
    common(p)
    p.add_argument("--navigator", default="", help="Save an ATT&CK Navigator layer here")
    p.add_argument("--report", default="", help="Save an HTML coverage report here")
    p.add_argument("--group", default="", help="Add a threat group section to the report, for example G0016 or APT29")
    p.add_argument("--name", default="")
    p.add_argument("--min-coverage", type=int, default=0, help="Fail when coverage is below this percent")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("export", help="Build a ready to deploy package zip")
    common(p)
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-f", "--format", default="default")
    p.add_argument("--package", default="auto")
    p.add_argument("--name", default="sigma-forge")
    p.add_argument("--mapping", default="")
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("from-query", help="Turn a Splunk, KQL, Elastic or EQL query into a Sigma rule")
    p.add_argument("query", nargs="?", default="", help="The query text, a file with the query, or empty to read stdin")
    p.add_argument("-l", "--language", default="auto", choices=["auto", "splunk", "kql", "lucene", "eql", "esql"])
    p.add_argument("--title", default="")
    p.add_argument("--level", default="medium")
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_from_query)

    p = sub.add_parser("hunt", help="Run rules on this Windows machine's live event logs")
    common(p)
    p.add_argument("--channels", nargs="*", help="Log names: sysmon security powershell system defender, or full channel names")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--max-events", type=int, default=20000)
    p.add_argument("--fail-on-hit", action="store_true", help="Exit 1 when any rule fires")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("yara", help="Check YARA rules and scan files or folders")
    p.add_argument("rules", nargs="+", help="YARA rule files or folders")
    p.add_argument("--scan", nargs="*", help="Files or folders to scan")
    p.add_argument("--no-recursive", action="store_true")
    p.add_argument("--max-files", type=int, default=20000)
    p.add_argument("--max-size", type=int, default=32, help="Skip files over this many MB")
    p.add_argument("--fail-on-hit", action="store_true", help="Exit 1 when any file matches")
    p.add_argument("--summary", default="")
    p.set_defaults(func=cmd_yara)

    p = sub.add_parser("firecheck", help="Replay logs into a platform, run the converted queries there and score them")
    common(p)
    p.add_argument("--platform", required=True, help="splunk, elastic, opensearch, wazuh or sentinel")
    p.add_argument("--target", default="")
    p.add_argument("--settings", default="", help="JSON file with the connection settings. Values like env:SPLUNK_TOKEN read environment variables.")
    p.add_argument("--mapping", default="", help="JSON file with a field mapping")
    p.add_argument("--logs", nargs="*", help="Log files or folders to replay")
    p.add_argument("--attack", action="store_true", help="Also replay built in attack logs for the techniques of your rules")
    p.add_argument("--sample", action="store_true", help="Also replay the sample attack chain")
    p.add_argument("--mode", default="replay", choices=["replay", "live"])
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--min-score", type=int, default=100, help="Fail when the fire score is below this")
    p.set_defaults(func=cmd_firecheck)

    p = sub.add_parser("deploy", help="Deploy rules to Splunk, Elastic, Sentinel or Wazuh")
    common(p)
    p.add_argument("--kind", required=True, choices=["splunk", "elastic", "sentinel", "wazuh"])
    p.add_argument("--target", default="")
    p.add_argument("--settings", default="", help="JSON file with the connection settings. Values like env:SPLUNK_TOKEN read environment variables.")
    p.add_argument("--mapping", default="")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("unit", help="Run rule unit tests from <rule>.tests.json files")
    p.add_argument("paths", nargs="+", help="Rule files or folders")
    p.add_argument("--mode", default="off", choices=["auto", "strict", "off"])
    p.add_argument("--summary", default="")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_unit)

    p = sub.add_parser("sysmon", help="Build a Sysmon config and audit policy from your rules")
    p.add_argument("paths", nargs="+", help="Rule files or folders")
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_sysmon)

    p = sub.add_parser("sigmahq", help="Check rules against SigmaHQ contribution rules")
    p.add_argument("paths", nargs="+", help="Rule files or folders")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_sigmahq)

    p = sub.add_parser("import", help="Turn Splunk, Sentinel or Elastic rule exports into Sigma rules")
    p.add_argument("files", nargs="+", help="savedsearches.conf, Sentinel JSON or YAML, Elastic ndjson")
    p.add_argument("--kind", default="auto", choices=["auto", "splunk", "sentinel", "elastic"])
    p.add_argument("--include-disabled", action="store_true")
    p.add_argument("-o", "--output", default="imported")
    p.set_defaults(func=cmd_import)

    args = parser.parse_args(argv)
    if getattr(args, "fail_on", None) == "never":
        args.fail_on = "none"
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
