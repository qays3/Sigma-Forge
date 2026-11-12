import json

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from app.api.routes import _no_demo, _parse
from app.core.logtest import LogInputError
from app.core.parsing import InputLimitError
from app.schemas import (
    AutofixRequest,
    CaseReportRequest,
    ConvertOptions,
    CorrelationRequest,
    GithubPushRequest,
    RuleInput,
    RulesRequest,
    ThreatReportRequest,
    UnitTestRequest,
    WizardRequest,
)

router = APIRouter(prefix="/api")
MAX_FILES = 20


async def _blobs(files):
    return [((u.filename or "events.json"), await u.read()) for u in (files or [])[:MAX_FILES]]


def _rules(raw: str):
    try:
        return [RuleInput(**r) for r in json.loads(raw or "[]")]
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad rules: {exc}")


@router.post("/sysmon/config")
def sysmon_config(req: RulesRequest):
    from app.core.sysmon import build

    _parse(req.rules)
    res = build(req.rules)
    if not res["xml"] and not res["audit"] and not res["registry"]:
        raise HTTPException(status_code=400, detail="None of these rules use Windows logs that Sysmon or audit policy can turn on")
    return res


@router.post("/mappings/suggest")
async def mappings_suggest(rules: str = Form(...), files: list[UploadFile] = File(...)):
    from app.core.fieldsuggest import suggest

    items = _rules(rules)
    if not items:
        raise HTTPException(status_code=400, detail="Add at least one rule")
    try:
        _parse(items)
        return suggest(items, await _blobs(files))
    except LogInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/import/siem")
async def import_siem(kind: str = Form("auto"), include_disabled: bool = Form(False), files: list[UploadFile] = File(...)):
    from app.core.siemimport import import_rules

    texts = []
    for name, data in await _blobs(files):
        if len(data) > 20 * 1048576:
            raise HTTPException(status_code=413, detail=f"{name} is larger than 20 MB")
        try:
            texts.append((name, data.decode("utf-8-sig")))
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail=f"{name} is not UTF-8 text")
    res = import_rules(texts, kind, include_disabled)
    if not res["found"]:
        raise HTTPException(status_code=400, detail="No searches or rules found. Use savedsearches.conf, a Sentinel export or an Elastic rules ndjson file.")
    return res


@router.post("/github/push")
def github_push(req: GithubPushRequest):
    from app.core.githubpush import PushError, push

    _no_demo("Pushing to GitHub")
    try:
        return push(req.token, req.repo, [{"name": r.name, "content": r.content} for r in req.rules], req.branch, req.base,
                    req.folder, req.message, req.title, req.body, req.draft)
    except PushError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/rules/sigmahq")
def rules_sigmahq(req: RulesRequest):
    from app.core.sigmahq import check_inputs

    return check_inputs(req.rules)


@router.post("/rules/sigmahq/fix")
def rules_sigmahq_fix(req: AutofixRequest):
    from app.core.sigmahq import fix_rule

    try:
        return fix_rule(req.name or "rule.yml", req.content)
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/rules/unit")
def rules_unit(req: UnitTestRequest):
    from app.core.unittests import run_units

    if not req.tests:
        raise HTTPException(status_code=400, detail="No test cases. Add match and no match events to a rule first.")
    try:
        return run_units(req.rules, req.tests, req.mode if req.mode in ("off", "auto", "strict") else "off", ConvertOptions())
    except InputLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc))


@router.get("/wizard/taxonomy")
def wizard_taxonomy():
    from app.core.builders import taxonomy

    return taxonomy()


@router.post("/wizard/build")
def wizard_build(req: WizardRequest):
    from app.core.builders import build_from_spec

    try:
        return build_from_spec(req.spec)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/correlation/build")
def correlation_build(req: CorrelationRequest):
    from app.core.builders import build_correlation

    try:
        return build_correlation(req.spec, req.rules)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/threat/report")
def threat_report(req: ThreatReportRequest):
    from app.core.threatreport import analyze

    res = analyze(req.text, req.rules)
    if not res["techniques"] and not res["ioc_total"]:
        raise HTTPException(status_code=400, detail="No ATT&CK techniques or IOCs found in this text")
    return res


@router.get("/siem/targets")
def siem_targets():
    from app.core.siemsend import TARGETS

    return {"targets": [{"id": k, "name": v} for k, v in TARGETS.items()]}


@router.post("/siem/send")
async def siem_send(
    target: str = Form(...),
    url: str = Form(""),
    token: str = Form(""),
    index: str = Form(""),
    sourcetype: str = Form(""),
    host: str = Form(""),
    port: int = Form(514),
    protocol: str = Form("udp"),
    verify_tls: bool = Form(True),
    dry_run: bool = Form(False),
    events: str = Form(""),
    files: list[UploadFile] = File(default=[]),
):
    from app.core.logtest import LogDatabase, load_events
    from app.core.siemsend import SendError, send

    if not dry_run:
        _no_demo("Sending events to a SIEM")
    blobs = await _blobs(files)
    if events.strip():
        blobs.append(("events.json", events.encode("utf-8")))
    if not blobs:
        raise HTTPException(status_code=400, detail="Add log files or events")
    try:
        loaded = load_events(blobs)
        raws = [json.loads(json.dumps(e["raw"], default=str)) for e in loaded]
        LogDatabase(loaded)
        times = [e.get("ts") for e in loaded]
        return send(target, raws, url, token, index, sourcetype, host, port, protocol, verify_tls, dry_run, times=times)
    except LogInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except SendError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/cases/report")
def cases_report(req: CaseReportRequest):
    from app.core.report import build_case_report

    html = build_case_report(req.case)
    return Response(content=html, media_type="text/html", headers={"Content-Disposition": 'attachment; filename="case-report.html"'})


@router.get("/firecheck/platforms")
def firecheck_platforms():
    from app.core.firecheck import PLATFORMS

    return {"platforms": [{"id": k, **v} for k, v in PLATFORMS.items()]}


@router.post("/firecheck/start")
async def firecheck_start(
    rules: str = Form(...),
    platform: str = Form(...),
    target: str = Form(""),
    mode: str = Form("replay"),
    hours: float = Form(24),
    settings: str = Form("{}"),
    field_mapping: str = Form("{}"),
    sample: str = Form(""),
    files: list[UploadFile] = File(default=[]),
):
    from app.config import BASE_DIR
    from app.core.fieldmap import MappingError, clean_mapping
    from app.core.firecheck import FireError, start

    _no_demo("The fire check")
    items = _rules(rules)
    try:
        conf = json.loads(settings or "{}")
        mapping = clean_mapping(json.loads(field_mapping or "{}"))
    except (ValueError, MappingError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    blobs = await _blobs(files)
    if sample:
        path = BASE_DIR / "sample" / "logs" / "attack_chain_sysmon.jsonl"
        blobs.append((path.name, path.read_bytes()))
    try:
        _parse(items)
        jid = start({"rules": items, "platform": platform, "target": target, "mode": mode, "hours": max(0.1, min(hours, 720)),
                     "settings": conf if isinstance(conf, dict) else {}, "mapping": mapping, "files": blobs})
    except FireError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": jid}


@router.get("/firecheck/{jid}")
def firecheck_status(jid: str):
    from app.core.firecheck import status

    res = status(jid)
    if res is None:
        raise HTTPException(status_code=404, detail="This fire check is gone. Run it again.")
    return res
