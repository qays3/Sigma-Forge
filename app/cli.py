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
