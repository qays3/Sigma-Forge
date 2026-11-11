import json

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
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
from app.schemas import CompareRequest, ConvertOptions, ConvertRequest, ExportRequest, LibraryAddRequest, NavigatorRequest, RuleInput, RulesRequest

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
def sample_logs():
    folder = SAMPLES_DIR.parent / "logs"
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
def coverage_rules(req: RulesRequest):
    return coverage(_parse(req.rules))


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
