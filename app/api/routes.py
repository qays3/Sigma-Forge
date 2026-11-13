import json

import os

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response

from app.config import APP_NAME, APP_VERSION, DEMO, SAMPLES_DIR
from app.core.analyzer import analyze
from app.core.attack import attack_available, load_attack
from app.core.converter import ConversionRequestError, convert
from app.core import library
from app.core.coverage import coverage, gaps, navigator_layer
from app.core.export import all_packages, build_export
from app.core.fieldmap import MappingError, clean_mapping
from app.core.logtest import LogInputError, run_test
from app.core.parsing import InputLimitError, parse_inputs
from app.core.targets import available_targets
from app.schemas import (
    AddFilterRequest,
    CompareRequest,
    ConvertOptions,
    ConvertRequest,
    CoverageRequest,
    DeployRequest,
    ExportRequest,
    GitFetchRequest,
    AutofixRequest,
    HuntEventsRequest,
    HuntReportRequest,
    IocRequest,
    ProcessScanRequest,
    ScheduleRequest,
    HuntYaraRequest,
    QueryGenRequest,
    LibraryAddRequest,
    NavigatorRequest,
    ReportRequest,
    RuleGenRequest,
    RuleInput,
    YaraLibRequest,
    RulesRequest,
)

router = APIRouter(prefix="/api")


def _allow(items, allowlist):
    if not allowlist:
        return items
    from app.core.ruletools import apply_allowlist

    return apply_allowlist(items, allowlist)


def _no_demo(what: str):
    if DEMO:
        raise HTTPException(status_code=403, detail=f"{what} is turned off on the public demo. Run Sigma Forge on your own computer to use it.")


def _parse(rules):
    try:
        return parse_inputs(rules)
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))


@router.get("/health")
def health():
    import sigma

    attack = load_attack()
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "pysigma": getattr(sigma, "__version__", None) or _pysigma_version(),
        "attack_version": attack.get("version", ""),
        "attack_loaded": attack_available(),
    }


def _pysigma_version():
    try:
        from importlib.metadata import version

        return version("pysigma")
    except Exception:
        return "unknown"


@router.get("/targets")
def targets():
    return {"targets": available_targets()}


@router.get("/attack")
def attack_matrix():
    data = load_attack()
    if not data.get("techniques"):
        raise HTTPException(status_code=503, detail="ATT&CK data is missing. Run: python tools/fetch_attack.py")
    return data


@router.get("/samples")
def samples():
    files = []
    if SAMPLES_DIR.exists():
        for path in sorted(SAMPLES_DIR.rglob("*.y*ml")):
            name = path.relative_to(SAMPLES_DIR).as_posix()
            files.append({"name": name, "group": name.split("/")[0] if "/" in name else "", "content": path.read_text(encoding="utf-8")})
    return {"rules": files}


@router.get("/samples/logs")
def sample_logs(set: str = Query("default", max_length=20)):
    folder = SAMPLES_DIR.parent / "logs"
    if set == "baseline":
        folder = folder / "baseline"
    files = []
    if folder.exists():
        for path in sorted(folder.glob("*")):
            if path.suffix.lower() in (".json", ".jsonl", ".ndjson") and path.stat().st_size < 2_000_000:
                files.append({"name": path.name, "content": path.read_text(encoding="utf-8")})
    return {"logs": files}


@router.post("/analyze")
def analyze_rules(req: RulesRequest):
    return analyze(_parse(req.rules))


@router.post("/convert")
def convert_rules(req: ConvertRequest):
    try:
        return convert(_allow(req.rules, req.allowlist), req.target, req.format, req.options, req.field_mapping)
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except ConversionRequestError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/coverage")
def coverage_rules(req: CoverageRequest):
    from app.core.threat import atomic_counts, group_coverage, readiness

    parsed = _parse(req.rules)
    if req.collected is not None:
        r = readiness(parsed, req.collected)
        cov = r["ready"]
        full = coverage(parsed)
        cov["readiness"] = r["summary"]
        cov["all_logsources"] = full["logsources"]
    else:
        cov = coverage(parsed)
        cov["all_logsources"] = cov["logsources"]
    if req.group:
        cov["group"] = group_coverage(cov, req.group)
    cov["atomic"] = atomic_counts()
    return cov


@router.post("/coverage/navigator")
def navigator(req: NavigatorRequest):
    return navigator_layer(_parse(req.rules), req.name, req.colors)


@router.post("/coverage/gaps")
def coverage_gaps(req: RulesRequest):
    return gaps(_parse(req.rules))


@router.post("/compare")
def compare(req: CompareRequest):
    out = []
    rules = _allow(req.rules, req.allowlist)
    for target in dict.fromkeys(req.targets):
        try:
            out.append(convert(rules, target, "default", req.options, req.field_mapping))
        except InputLimitError as exc:
            raise HTTPException(status_code=413, detail=str(exc))
        except ConversionRequestError as exc:
            out.append({"target": {"id": target, "name": target, "language": ""}, "error": str(exc), "results": [], "notes": []})
    return {"targets": out}


@router.get("/export/packages")
def export_packages():
    return {"packages": all_packages()}


@router.post("/export")
def export(req: ExportRequest):
    try:
        filename, data, summary = build_export(_allow(req.rules, req.allowlist), req.target, req.format, req.options, req.field_mapping, req.package, req.name)
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except ConversionRequestError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-Summary": json.dumps(summary),
        "Access-Control-Expose-Headers": "Content-Disposition, X-Export-Summary",
    }
    return Response(content=data, media_type="application/zip", headers=headers)


@router.post("/test")
async def test_logs(
    rules: str = Form(...),
    mode: str = Form("auto"),
    field_mapping: str = Form("{}"),
    allowlist: str = Form("[]"),
    files: list[UploadFile] = File(...),
):
    try:
        raw = json.loads(rules)
        items = _allow([RuleInput(**r) for r in raw], json.loads(allowlist or "[]"))
        mapping = clean_mapping(json.loads(field_mapping or "{}"))
    except (ValueError, TypeError, MappingError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    if not items:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    blobs = []
    for upload in files[:20]:
        blobs.append((upload.filename or "events.json", await upload.read()))
    try:
        if mapping:
            from app.core.fieldmap import map_inputs

            items, _ = map_inputs(items, mapping)
        return run_test(items, blobs, mode, options=ConvertOptions())
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except LogInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/fields")
def rule_fields(req: RulesRequest):
    from sigma.rule import SigmaDetection, SigmaDetectionItem

    counts = {}

    def walk(node):
        if isinstance(node, SigmaDetection):
            for item in node.detection_items:
                walk(item)
        elif isinstance(node, SigmaDetectionItem) and node.field:
            counts[node.field] = counts.get(node.field, 0) + 1

    for parsed in _parse(req.rules):
        if parsed.rule is None:
            continue
        for detection in parsed.rule.detection.detections.values():
            walk(detection)
        for field in parsed.rule.fields or []:
            counts.setdefault(field, 0)
    return {"fields": [{"name": k, "uses": v} for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0].lower()))]}


@router.get("/library/status")
def library_status():
    return library.status()


@router.post("/library/sync")
def library_sync():
    _no_demo("Library sync")
    return library.start_sync()


@router.post("/library/upload")
async def library_upload(file: UploadFile = File(...)):
    _no_demo("Library upload")
    data = await file.read(library.MAX_ZIP_BYTES + 1)
    try:
        return library.install_zip(data, (file.filename or "").rsplit(".", 1)[0])
    except library.LibraryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/library/search")
def library_search(
    q: str = Query("", max_length=200),
    technique: str = Query("", max_length=20),
    level: str = Query("", max_length=20),
    product: str = Query("", max_length=60),
    category: str = Query("", max_length=60),
    service: str = Query("", max_length=60),
    status: str = Query("", max_length=20),
    group: str = Query("", max_length=60),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    try:
        return library.search(q, technique, level, product, category, service, status, group, limit, offset)
    except library.LibraryError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/library/rules")
def library_rules(req: LibraryAddRequest):
    try:
        return {"rules": library.read_rules(req.paths)}
    except library.LibraryError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/yaralib/status")
def yaralib_status():
    from app.core import yaralib

    return yaralib.status()


@router.post("/yaralib/sync")
def yaralib_sync(package: str = Query("core", max_length=20)):
    from app.core import yaralib

    _no_demo("Library sync")
    try:
        return yaralib.start_sync(package)
    except yaralib.YaraLibError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/yaralib/upload")
async def yaralib_upload(file: UploadFile = File(...)):
    from app.core import yaralib

    _no_demo("Library upload")
    data = await file.read(yaralib.MAX_ZIP_BYTES + 1)
    try:
        return yaralib.install_zip(data)
    except yaralib.YaraLibError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/yaralib/search")
def yaralib_search(
    q: str = Query("", max_length=200),
    repo: str = Query("", max_length=120),
    tag: str = Query("", max_length=80),
    min_score: int = Query(0, ge=0, le=100),
    sort: str = Query("", max_length=10),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    from app.core import yaralib

    try:
        return yaralib.search(q, repo, tag, min_score, sort, limit, offset)
    except yaralib.YaraLibError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/yaralib/rules")
def yaralib_rules(req: YaraLibRequest):
    from app.core import yaralib

    try:
        return {"rules": yaralib.read_rules(req.names)}
    except yaralib.YaraLibError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/groups")
def threat_groups():
    from app.core.threat import groups_index

    return {"groups": groups_index()}


@router.get("/atomic/{tid}")
def atomic(tid: str):
    from app.core.threat import atomic_tests

    if not tid or len(tid) > 12:
        raise HTTPException(status_code=400, detail="Bad technique id")
    return atomic_tests(tid.upper())


@router.post("/report")
def report(req: ReportRequest):
    from app.core.report import build_report

    text = build_report(_parse(req.rules), req.title, req.group, req.collected)
    return Response(content=text, media_type="text/html; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="sigma-forge-coverage-report.html"', "Access-Control-Expose-Headers": "Content-Disposition"})


@router.post("/generate-events")
def generate_events(req: RulesRequest):
    from app.core.eventgen import generate, to_jsonl

    _parse(req.rules)
    data = generate(req.rules)
    return {"rules": data["rules"], "count": len(data["events"]), "jsonl": to_jsonl(data["events"]) if data["events"] else ""}


@router.post("/rulegen")
def rulegen(req: RuleGenRequest):
    from app.core.rulegen import build_rule

    try:
        return build_rule(req.event, req.logsource, req.fields, req.title)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/rules/add-filter")
def rules_add_filter(req: AddFilterRequest):
    from app.core.rulegen import add_filter

    try:
        return {"content": add_filter(req.content, req.title, req.filters)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not add the filter: {exc}")


@router.get("/deploy/kinds")
def deploy_kinds():
    from app.core.deploy import KINDS

    return {"kinds": KINDS}


@router.post("/deploy")
def deploy_rules(req: DeployRequest):
    from app.core import team
    from app.core.deploy import DeployError, deploy

    if team.AUTH and team.REQUIRE_REVIEW and not (req.dry_run or DEMO):
        waiting = team.unapproved(req.rules)
        if waiting:
            raise HTTPException(status_code=400, detail=f"{len(waiting)} rules are not approved yet: " + ", ".join(waiting[:8]) + (" and more" if len(waiting) > 8 else ""))
    try:
        return deploy(_allow(req.rules, req.allowlist), req.kind, req.target, req.settings, req.options, req.field_mapping, req.dry_run or DEMO)
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except (DeployError, ConversionRequestError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/git/fetch")
def git_fetch(req: GitFetchRequest):
    _no_demo("GitHub sync")
    from app.core.gitsync import GitError, fetch

    try:
        return fetch(req.repo, req.ref, req.path, req.kind)
    except GitError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/yara/status")
def yara_status():
    from app.core.yara_engine import available

    return available()


@router.get("/samples/yara")
def sample_yara():
    base = SAMPLES_DIR.parent / "yara"
    rules = [{"name": p.name, "content": p.read_text(encoding="utf-8")} for p in sorted((base / "rules").glob("*.yar"))] if (base / "rules").exists() else []
    files = []
    if (base / "files").exists():
        import base64

        for p in sorted((base / "files").glob("*")):
            if p.is_file() and p.stat().st_size < 1_000_000:
                files.append({"name": p.name, "data": base64.b64encode(p.read_bytes()).decode()})
    return {"rules": rules, "files": files}


@router.post("/yara/check")
def yara_check(req: RulesRequest):
    from app.core.yara_engine import YaraError, check

    try:
        return check([(r.name, r.content) for r in req.rules])
    except YaraError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.post("/yara/scan")
async def yara_scan(rules: str = Form(...), files: list[UploadFile] = File(...)):
    from app.core.yara_engine import YaraError, scan

    try:
        raw = json.loads(rules)
        rule_files = [(str(r.get("name", "rules.yar")), str(r["content"])) for r in raw]
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    if not rule_files:
        raise HTTPException(status_code=400, detail="Add at least one YARA rule")
    targets = [(f.filename or "file", await f.read()) for f in files[:50]]
    try:
        return scan(rule_files, targets)
    except YaraError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/querygen/languages")
def querygen_languages():
    from app.core.querygen import LANGS

    return {"languages": LANGS}


@router.post("/querygen")
def querygen(req: QueryGenRequest):
    from app.core.querygen import QueryError, convert_query

    try:
        return convert_query(req.query, req.language, req.title, req.level, req.logsource)
    except QueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _local_only(request: Request):
    if DEMO:
        raise HTTPException(status_code=403, detail="This is a public demo. Machine scans are turned off here. Run Sigma Forge on your own computer to use them.")
    host = request.client.host if request.client else ""
    if host in ("127.0.0.1", "::1", "localhost", "testclient") or os.environ.get("SIGMA_FORGE_ALLOW_REMOTE_HUNT") == "1":
        return
    raise HTTPException(status_code=403, detail="Machine scans only run from the same computer. Set SIGMA_FORGE_ALLOW_REMOTE_HUNT=1 to allow it.")


@router.get("/hunt/status")
def hunt_status(request: Request):
    from app.core.hunt import status
    from app.core.yara_engine import available

    _local_only(request)
    return {**status(), "yara": available()}


@router.post("/hunt/events")
def hunt_events(req: HuntEventsRequest, request: Request):
    from app.core.hunt import collect, os_kind

    _local_only(request)
    if os_kind() not in ("windows", "linux", "macos"):
        raise HTTPException(status_code=400, detail="Live log scan works on Windows, Linux and macOS. Upload .evtx files instead.")
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    try:
        mapping = clean_mapping(req.field_mapping or {})
    except MappingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    blobs, stats = collect(req.channels, req.hours, req.max_events)
    if not blobs:
        raise HTTPException(status_code=400, detail="; ".join(s["error"] for s in stats if s["error"]) or "No events found in that time range")
    items = _allow(req.rules, req.allowlist)
    try:
        if mapping:
            from app.core.fieldmap import map_inputs

            items, _ = map_inputs(items, mapping)
        result = run_test(items, blobs, req.mode, options=ConvertOptions())
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except LogInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result["channels"] = stats
    return result


@router.post("/hunt/yara")
def hunt_yara(req: HuntYaraRequest, request: Request):
    from app.core.yara_engine import YaraError, scan_paths

    _local_only(request)
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one YARA rule")
    try:
        return scan_paths([(r.name, r.content) for r in req.rules], req.paths, req.recursive, req.max_files,
                          req.max_size_mb * 1024 * 1024, extensions=req.extensions)
    except YaraError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _mapped(rules, allowlist, field_mapping):
    try:
        mapping = clean_mapping(field_mapping or {})
    except MappingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    items = _allow(rules, allowlist)
    if mapping:
        from app.core.fieldmap import map_inputs

        items, _ = map_inputs(items, mapping)
    return [{"name": i.name, "content": i.content} for i in items]


def _job(kind, params, label="", scope=""):
    from app.core.huntjobs import JobError, start

    try:
        return start(kind, params, label, scope)
    except JobError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/hunt/jobs")
def hunt_jobs(request: Request):
    from app.core.huntjobs import all_jobs

    _local_only(request)
    return all_jobs()


@router.post("/hunt/jobs/live")
def hunt_job_live(req: HuntEventsRequest, request: Request):
    from app.core.hunt import os_kind

    _local_only(request)
    if os_kind() not in ("windows", "linux", "macos"):
        raise HTTPException(status_code=400, detail="Live log scan works on Windows, Linux and macOS. Upload .evtx files instead.")
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    rules = _mapped(req.rules, req.allowlist, req.field_mapping)
    return _job("live", {"rules": rules, "channels": req.channels, "hours": req.hours, "max_events": req.max_events, "mode": req.mode},
                "Live event logs", f"{', '.join(req.channels)}, last {req.hours:g} hours")


@router.post("/hunt/jobs/evtx")
async def hunt_job_evtx(
    request: Request,
    rules: str = Form(...),
    mode: str = Form("auto"),
    field_mapping: str = Form("{}"),
    allowlist: str = Form("[]"),
    files: list[UploadFile] = File(...),
):
    _local_only(request)
    try:
        raw = [RuleInput(**r) for r in json.loads(rules)]
        allow = json.loads(allowlist or "[]")
        fmap = json.loads(field_mapping or "{}")
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    if not raw:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    items = _mapped(raw, allow, fmap)
    blobs = [(u.filename or "events.json", await u.read()) for u in files[:20]]
    return _job("evtx", {"rules": items, "files": blobs, "mode": mode}, "Uploaded logs", ", ".join(n for n, _ in blobs))


@router.post("/hunt/jobs/yara")
def hunt_job_yara(req: HuntYaraRequest, request: Request):
    _local_only(request)
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one YARA rule")
    return _job("yara", {"rules": [(r.name, r.content) for r in req.rules], "paths": req.paths, "recursive": req.recursive, "max_files": req.max_files,
                         "max_size": req.max_size_mb * 1024 * 1024, "extensions": req.extensions}, "Files scanned", ", ".join(req.paths))


@router.post("/hunt/jobs/procs")
def hunt_job_procs(req: ProcessScanRequest, request: Request):
    _local_only(request)
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one YARA rule")
    return _job("procs", {"rules": [(r.name, r.content) for r in req.rules], "pids": req.pids}, "Processes scanned",
                f"{len(req.pids)} processes" if req.pids else "every running process")


@router.get("/hunt/jobs/{kind}")
def hunt_job_get(kind: str, request: Request):
    from app.core.huntjobs import get

    _local_only(request)
    job = get(kind)
    if not job:
        raise HTTPException(status_code=404, detail="No scan yet")
    return job


@router.post("/hunt/jobs/{kind}/cancel")
def hunt_job_cancel(kind: str, request: Request):
    from app.core.huntjobs import JobError, cancel

    _local_only(request)
    try:
        return cancel(kind)
    except JobError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.delete("/hunt/jobs/{kind}")
def hunt_job_clear(kind: str, request: Request):
    from app.core.huntjobs import JobError, clear

    _local_only(request)
    try:
        clear(kind)
    except JobError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"cleared": kind}


@router.get("/config")
def app_config():
    return {"app": APP_NAME, "version": APP_VERSION, "demo": DEMO}


@router.post("/hunt/report")
def hunt_report(req: HuntReportRequest):
    from app.core.report import build_hunt_report

    html = build_hunt_report(req.result, req.title, req.scope)
    name = "".join(c if c.isalnum() else "-" for c in (req.title or "hunt-report").lower()).strip("-")[:60] or "hunt-report"
    return Response(html, media_type="text/html; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}.html"'})


@router.post("/hunt/processes")
def hunt_processes(req: ProcessScanRequest, request: Request):
    from app.core.yara_engine import YaraError, scan_processes

    _local_only(request)
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one YARA rule")
    try:
        return scan_processes([(r.name, r.content) for r in req.rules], req.pids or None)
    except YaraError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/hunt/schedule")
def schedule_get(request: Request):
    from app.core import scheduler

    _local_only(request)
    return scheduler.public()


@router.post("/hunt/schedule")
def schedule_set(req: ScheduleRequest, request: Request):
    from app.core import scheduler
    from app.core.hunt import os_kind

    _local_only(request)
    if req.enabled and os_kind() not in ("windows", "linux", "macos"):
        raise HTTPException(status_code=400, detail="Scheduled hunts need Windows, Linux or macOS")
    rules = [{"name": r.name, "content": r.content} for r in req.rules] if req.rules is not None else None
    if req.enabled and not req.channels:
        raise HTTPException(status_code=400, detail="Pick at least one log")
    if req.enabled and rules is not None and not rules:
        raise HTTPException(status_code=400, detail="Pick at least one rule")
    if req.url and not req.url.lower().startswith(("https://", "http://")):
        raise HTTPException(status_code=400, detail="The webhook must start with https://")
    return scheduler.update(req.enabled, req.every_minutes, req.channels, rules, req.min_level, req.kind, req.url, req.health_watch, req.quiet_runs)


@router.post("/hunt/schedule/run")
def schedule_run(request: Request):
    from app.core import scheduler

    _local_only(request)
    entry = scheduler.run_once()
    return {"run": entry, "schedule": scheduler.public()}


@router.post("/hunt/schedule/test")
def schedule_test(request: Request):
    from app.core import scheduler

    _local_only(request)
    err = scheduler.send(scheduler.load(), f"{APP_NAME}: test message", ["If you can read this, scheduled hunt alerts will reach this channel."], [])
    if err:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


@router.post("/rules/ioc")
def rules_from_iocs(req: IocRequest):
    from app.core.ruletools import ioc_rules

    res = ioc_rules(req.text, req.name)
    if not res["total"]:
        raise HTTPException(status_code=400, detail="No IPs, domains, URLs, hashes or file names found in the text")
    return res


@router.post("/rules/explain")
def rules_explain(req: RulesRequest):
    from app.core.ruletools import explain_inputs

    return {"rules": explain_inputs(req.rules)}


@router.post("/rules/autofix")
def rules_autofix(req: AutofixRequest):
    from app.core.ruletools import autofix

    try:
        return autofix(req.content, req.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/library/updates")
def library_updates_check(req: RulesRequest):
    from app.core.ruletools import library_updates

    return library_updates(req.rules)


@router.post("/purple")
async def purple(
    rules: str = Form(...),
    techniques: str = Form("[]"),
    mode: str = Form("auto"),
    field_mapping: str = Form("{}"),
    allowlist: str = Form("[]"),
    files: list[UploadFile] = File(...),
):
    from app.core.attack import load_attack, resolve_technique
    from app.core.threat import atomic_tests

    try:
        items = _allow([RuleInput(**r) for r in json.loads(rules)], json.loads(allowlist or "[]"))
        wanted = [resolve_technique(str(t).strip().upper()) for t in json.loads(techniques or "[]") if str(t).strip()]
        mapping = clean_mapping(json.loads(field_mapping or "{}"))
    except (ValueError, TypeError, MappingError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    if not items:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    blobs = [((u.filename or "events.json"), await u.read()) for u in files[:20]]
    try:
        if mapping:
            from app.core.fieldmap import map_inputs

            items, _ = map_inputs(items, mapping)
        res = run_test(items, blobs, mode, options=ConvertOptions())
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except LogInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    known = load_attack().get("techniques", {})
    if not wanted:
        wanted = sorted({t for r in res["results"] for t in r.get("techniques", [])})
    rows = []
    for tid in dict.fromkeys(wanted):
        rel = [r for r in res["results"] if any(t == tid or t.startswith(tid + ".") or tid.startswith(t + ".") for t in r.get("techniques", []))]
        fired = [r for r in rel if r["hits"]]
        state = "detected" if fired else ("missed" if rel else "no_rule")
        at = atomic_tests(tid)
        rows.append({
            "id": tid,
            "name": (known.get(tid) or {}).get("name", tid),
            "state": state,
            "rules": [{"title": r["title"], "key": r["key"], "hits": r["hits"], "level": r["level"], "status": r["status"]} for r in rel],
            "atomic": len(at.get("tests", [])) + sum(x["count"] for x in at.get("subs", [])),
            "atomic_url": at.get("url", ""),
        })
    total = len(rows)
    det = sum(1 for r in rows if r["state"] == "detected")
    return {
        "summary": {"techniques": total, "detected": det, "missed": sum(1 for r in rows if r["state"] == "missed"),
                    "no_rule": sum(1 for r in rows if r["state"] == "no_rule"), "score": round(det * 100 / total) if total else 0,
                    "events": res["summary"]["events"]},
        "techniques": rows,
        "test": res,
    }
