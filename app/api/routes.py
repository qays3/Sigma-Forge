import json

import os

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response

from app.config import APP_NAME, APP_VERSION, SAMPLES_DIR
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
    HuntEventsRequest,
    HuntYaraRequest,
    QueryGenRequest,
    LibraryAddRequest,
    NavigatorRequest,
    ReportRequest,
    RuleGenRequest,
    RuleInput,
    RulesRequest,
)

router = APIRouter(prefix="/api")


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
        return convert(req.rules, req.target, req.format, req.options, req.field_mapping)
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
    for target in dict.fromkeys(req.targets):
        try:
            out.append(convert(req.rules, target, "default", req.options, req.field_mapping))
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
        filename, data, summary = build_export(req.rules, req.target, req.format, req.options, req.field_mapping, req.package, req.name)
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
    files: list[UploadFile] = File(...),
):
    try:
        raw = json.loads(rules)
        items = [RuleInput(**r) for r in raw]
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
    return library.start_sync()


@router.post("/library/upload")
async def library_upload(file: UploadFile = File(...)):
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
    limit: int = Query(50, ge=1, le=200),
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
    from app.core.deploy import DeployError, deploy

    try:
        return deploy(req.rules, req.kind, req.target, req.settings, req.options, req.field_mapping, req.dry_run)
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except (DeployError, ConversionRequestError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/git/fetch")
def git_fetch(req: GitFetchRequest):
    from app.core.gitsync import GitError, fetch

    try:
        return fetch(req.repo, req.ref, req.path)
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
    from app.core.hunt import collect, is_windows

    _local_only(request)
    if not is_windows():
        raise HTTPException(status_code=400, detail="Live log scan needs Sigma Forge running on Windows. Upload .evtx files instead.")
    if not req.rules:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    try:
        mapping = clean_mapping(req.field_mapping or {})
    except MappingError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    blobs, stats = collect(req.channels, req.hours, req.max_events)
    if not blobs:
        raise HTTPException(status_code=400, detail="; ".join(s["error"] for s in stats if s["error"]) or "No events found in that time range")
    items = req.rules
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
