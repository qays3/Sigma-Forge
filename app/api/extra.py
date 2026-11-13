import json
import re

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from app.api.routes import _no_demo, _parse
from app.core.logtest import LogInputError
from app.core.parsing import InputLimitError
from app.schemas import (
    AttackLogsRequest,
    AutofixRequest,
    CaseReportRequest,
    ConvertOptions,
    CorrelationRequest,
    CtiRequest,
    ResponseRequest,
    DeployRequest,
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
    attack: str = Form(""),
    files: list[UploadFile] = File(default=[]),
):
    from app.core.firecheck import FireError, start

    _no_demo("The fire check")
    params = _fire_params(rules, platform, target, mode, hours, settings, field_mapping, sample, attack, await _blobs(files))
    try:
        jid = start(params)
    except FireError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": jid}




@router.get("/attacklogs/techniques")
def attacklogs_catalog():
    from app.core.attacklogs import catalog

    return {"techniques": catalog()}


@router.post("/attacklogs")
def attacklogs_generate(req: AttackLogsRequest):
    from app.core.attacklogs import generate

    res = generate(req.techniques or None, req.host, req.user)
    if not res["events"]:
        raise HTTPException(status_code=400, detail="None of these techniques have built in attack logs yet")
    return res


def _fire_params(rules, platform, target, mode, hours, settings, field_mapping, sample, attack, blobs, keep_sample=False):
    from app.config import BASE_DIR
    from app.core.fieldmap import MappingError, clean_mapping

    items = _rules(rules)
    try:
        conf = json.loads(settings or "{}")
        mapping = clean_mapping(json.loads(field_mapping or "{}"))
    except (ValueError, MappingError) as exc:
        raise HTTPException(status_code=400, detail=f"Bad request: {exc}")
    if sample and not keep_sample:
        path = BASE_DIR / "sample" / "logs" / "attack_chain_sysmon.jsonl"
        blobs.append((path.name, path.read_bytes()))
    _parse(items)
    return {"rules": items, "platform": platform, "target": target, "mode": mode, "hours": max(0.1, min(hours, 720)),
            "settings": conf if isinstance(conf, dict) else {}, "mapping": mapping, "files": blobs,
            "attack": "rules" if attack == "rules" else [t for t in re.split(r"[\s,]+", attack) if t][:200]}


@router.get("/firecheck/schedule")
def firecheck_schedule_get():
    from app.core.fcschedule import public

    return public()


@router.post("/firecheck/schedule")
async def firecheck_schedule_set(
    enabled: bool = Form(...),
    every_hours: int = Form(24),
    kind: str = Form("slack"),
    url: str = Form(""),
    replace: bool = Form(False),
    rules: str = Form("[]"),
    platform: str = Form("splunk"),
    target: str = Form(""),
    mode: str = Form("replay"),
    hours: float = Form(24),
    settings: str = Form("{}"),
    field_mapping: str = Form("{}"),
    sample: str = Form(""),
    attack: str = Form(""),
    files: list[UploadFile] = File(default=[]),
):
    from app.core.fcschedule import update
    from app.core.firecheck import PLATFORMS, FireError, _client

    _no_demo("Scheduled fire checks")
    params = None
    if replace:
        params = _fire_params(rules, platform, target, mode, hours, settings, field_mapping, sample, attack, await _blobs(files), keep_sample=True)
        params["sample"] = bool(sample)
        if platform not in PLATFORMS:
            raise HTTPException(status_code=400, detail="Unknown platform")
        try:
            _client(platform, params["settings"])
        except FireError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    try:
        return update(enabled, every_hours, params, kind, url or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/firecheck/schedule/run")
def firecheck_schedule_run():
    import threading

    from app.core import fcschedule

    _no_demo("Scheduled fire checks")
    if not fcschedule.load().get("params"):
        raise HTTPException(status_code=400, detail="Nothing scheduled yet")
    if fcschedule._running:
        raise HTTPException(status_code=409, detail="It is already running")
    threading.Thread(target=fcschedule.run_once, daemon=True).start()
    return {"started": True}


@router.post("/drift")
def drift_check(req: DeployRequest):
    from app.api.routes import _allow
    from app.core.converter import ConversionRequestError
    from app.core.deploy import DeployError
    from app.core.drift import check

    _no_demo("The drift check")
    try:
        return check(_allow(req.rules, req.allowlist), req.kind, req.target, req.settings, req.options, req.field_mapping)
    except (DeployError, ConversionRequestError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"Unexpected answer from the platform: {exc}")


@router.post("/ci/workflow")
def ci_workflow(req: WizardRequest):
    from app.core.ciworkflow import generate

    try:
        return generate(req.spec)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/cti/pull")
def cti_pull(req: CtiRequest):
    from app.core.ctifeeds import FeedError, pull

    _no_demo("Pulling threat intel feeds")
    try:
        return pull(req.source, req.settings)
    except FeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/cti/expired")
def cti_expired(req: RulesRequest):
    from app.core.ctifeeds import expired

    return {"expired": expired(req.rules)}


@router.post("/rules/response")
def rules_response(req: ResponseRequest):
    from app.core.response import set_steps, suggest

    if req.steps is None:
        return {"steps": suggest(req.content)}
    out = set_steps(req.content, req.steps)
    from app.core.parsing import parse_file

    errs = [p.error for p in parse_file("rule.yml", out) if p.error]
    if errs:
        raise HTTPException(status_code=400, detail=errs[0])
    return {"content": out}


@router.get("/firecheck/{jid}")
def firecheck_status(jid: str):
    from app.core.firecheck import status

    res = status(jid)
    if res is None:
        raise HTTPException(status_code=404, detail="This fire check is gone. Run it again.")
    return res
