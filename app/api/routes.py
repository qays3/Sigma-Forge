from fastapi import APIRouter, HTTPException

from app.config import APP_NAME, APP_VERSION, SAMPLES_DIR
from app.core.analyzer import analyze
from app.core.attack import attack_available, load_attack
from app.core.converter import ConversionRequestError, convert
from app.core.coverage import coverage, navigator_layer
from app.core.parsing import InputLimitError, parse_inputs
from app.core.targets import available_targets
from app.schemas import ConvertRequest, NavigatorRequest, RulesRequest

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


@router.post("/analyze")
def analyze_rules(req: RulesRequest):
    return analyze(_parse(req.rules))


@router.post("/convert")
def convert_rules(req: ConvertRequest):
    try:
        return convert(req.rules, req.target, req.format, req.options)
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
