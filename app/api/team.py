from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core import team
from app.schemas import (
    CaseSaveRequest,
    LoginRequest,
    PasswordRequest,
    ReviewComment,
    ReviewDecision,
    ReviewRequest,
    TeamRemoveRequest,
    TeamRuleReplace,
    TeamRulesRequest,
    UserCreate,
    UserUpdate,
)

router = APIRouter(prefix="/api")


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _user(request: Request) -> dict:
    u = getattr(request.state, "user", None)
    if not team.AUTH:
        raise HTTPException(status_code=400, detail="Team mode is off. Start Sigma Forge with SIGMA_FORGE_AUTH=1.")
    if not u:
        raise HTTPException(status_code=401, detail="Sign in first")
    return u


def _err(exc: team.TeamError):
    raise HTTPException(status_code=exc.code, detail=str(exc))


def _cookie(request: Request, res: JSONResponse, token: str, max_age: int) -> JSONResponse:
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"
    res.set_cookie(team.COOKIE, token, max_age=max_age, httponly=True, samesite="strict", secure=secure, path="/")
    return res


@router.get("/auth/me")
def auth_me(request: Request):
    u = getattr(request.state, "user", None)
    return {"auth": team.AUTH, "setup_needed": team.setup_needed(), "user": u, "require_review": team.AUTH and team.REQUIRE_REVIEW, "roles": team.ROLES}


@router.post("/auth/setup")
def auth_setup(req: LoginRequest, request: Request):
    if not team.setup_needed():
        raise HTTPException(status_code=403, detail="Setup is already done")
    try:
        team.create_user(req.username, req.password, "admin", "setup")
        token, user = team.login(req.username, req.password)
    except team.TeamError as exc:
        _err(exc)
    team.audit(user["username"], "setup", "first admin created", _ip(request))
    return _cookie(request, JSONResponse({"user": user}), token, team.SESSION_HOURS * 3600)


@router.post("/auth/login")
def auth_login(req: LoginRequest, request: Request):
    if not team.AUTH:
        raise HTTPException(status_code=400, detail="Team mode is off")
    if not team.limiter.allow(f"login:{_ip(request)}", 10):
        raise HTTPException(status_code=429, detail="Too many sign in tries. Wait a minute.")
    try:
        token, user = team.login(req.username, req.password)
    except team.TeamError as exc:
        team.audit(req.username[:40], "login failed", "", _ip(request), exc.code)
        _err(exc)
    team.audit(user["username"], "login", "", _ip(request), 200)
    return _cookie(request, JSONResponse({"user": user}), token, team.SESSION_HOURS * 3600)


@router.post("/auth/logout")
def auth_logout(request: Request):
    u = getattr(request.state, "user", None)
    if u:
        team.audit(u["username"], "logout", "", _ip(request))
    res = JSONResponse({"ok": True})
    res.delete_cookie(team.COOKIE, path="/")
    return res


@router.post("/auth/password")
def auth_password(req: PasswordRequest, request: Request):
    u = _user(request)
    try:
        team.login(u["username"], req.current)
        team.update_user(u["username"], None, None, req.password, u["username"])
        token, user = team.login(u["username"], req.password)
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], "password changed", "", _ip(request))
    return _cookie(request, JSONResponse({"user": user}), token, team.SESSION_HOURS * 3600)


@router.get("/team/users")
def users_list(request: Request):
    _user(request)
    return {"users": [team.public_user(n, u) for n, u in sorted(team.users().items())], "roles": team.ROLES}


@router.post("/team/users")
def users_create(req: UserCreate, request: Request):
    u = _user(request)
    try:
        out = team.create_user(req.username, req.password, req.role, u["username"])
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], "user created", f"{out['username']} as {out['role']}", _ip(request))
    return out


@router.put("/team/users/{name}")
def users_update(name: str, req: UserUpdate, request: Request):
    u = _user(request)
    try:
        out = team.update_user(name, req.role, req.disabled, req.password, u["username"])
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], "user changed", f"{name}: role {out['role']}, disabled {out['disabled']}" + (", password reset" if req.password else ""), _ip(request))
    return out


@router.delete("/team/users/{name}")
def users_delete(name: str, request: Request):
    u = _user(request)
    try:
        team.delete_user(name, u["username"])
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], "user deleted", name, _ip(request))
    return {"ok": True}


@router.get("/team/audit")
def audit_list(request: Request, user: str = "", action: str = "", limit: int = 500):
    _user(request)
    return {"entries": team.read_audit(max(1, min(limit, 5000)), user, action)}


@router.get("/team/rules")
def rules_list(request: Request):
    _user(request)
    data = team.rules()
    states = {r["name"]: team.review_state(r["name"], r["content"]) for r in data["rules"]} if team.REQUIRE_REVIEW or team.reviews() else {}
    return {**data, "reviews": states}


@router.post("/team/rules")
def rules_add(req: TeamRulesRequest, request: Request):
    u = _user(request)
    res = team.add_rules([{"name": f.name, "content": f.content} for f in req.files], u["username"])
    team.audit(u["username"], "rules added", f"{len(req.files)} files, {res['added']} new", _ip(request))
    return res


@router.put("/team/rules")
def rules_replace(req: TeamRuleReplace, request: Request):
    u = _user(request)
    item = team.replace_rule(req.old_id, req.name, req.content, u["username"])
    team.audit(u["username"], "rule saved", req.name, _ip(request))
    return item


@router.post("/team/rules/remove")
def rules_remove(req: TeamRemoveRequest, request: Request):
    u = _user(request)
    n = team.remove_rules(req.ids)
    team.audit(u["username"], "rules removed", f"{n} rules", _ip(request))
    return {"removed": n}


@router.post("/team/rules/clear")
def rules_clear(request: Request):
    u = _user(request)
    team.clear_rules()
    team.audit(u["username"], "workspace cleared", "", _ip(request))
    return {"ok": True}


@router.get("/team/reviews")
def reviews_list(request: Request):
    _user(request)
    items = sorted(team.reviews().values(), key=lambda r: r.get("requested", ""), reverse=True)
    current = {r["name"]: r["content"] for r in team.rules()["rules"]}
    for r in items:
        r["outdated"] = r["name"] in current and team.chash(current[r["name"]]) != r["hash"]
        r["in_workspace"] = r["name"] in current
    return {"reviews": items, "require_review": team.REQUIRE_REVIEW}


@router.post("/team/reviews")
def reviews_request(req: ReviewRequest, request: Request):
    u = _user(request)
    r = team.request_review(req.name, req.content, req.note, u["username"])
    team.audit(u["username"], "review requested", req.name, _ip(request))
    return r


@router.post("/team/reviews/decide")
def reviews_decide(req: ReviewDecision, request: Request):
    u = _user(request)
    try:
        r = team.decide(req.name, req.decision, req.note, u["username"], u["role"])
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], f"review {req.decision}", req.name, _ip(request))
    return r


@router.post("/team/reviews/comment")
def reviews_comment(req: ReviewComment, request: Request):
    u = _user(request)
    try:
        return team.comment(req.name, req.text, u["username"])
    except team.TeamError as exc:
        _err(exc)


@router.get("/team/cases")
def cases_list(request: Request):
    _user(request)
    return {"cases": team.cases()}


@router.put("/team/cases")
def cases_save(req: CaseSaveRequest, request: Request):
    u = _user(request)
    try:
        c = team.save_case(req.case, u["username"])
    except team.TeamError as exc:
        _err(exc)
    team.audit(u["username"], "case saved", str(c.get("title", ""))[:120], _ip(request))
    return c


@router.delete("/team/cases/{cid}")
def cases_delete(cid: str, request: Request):
    u = _user(request)
    team.delete_case(cid)
    team.audit(u["username"], "case deleted", cid, _ip(request))
    return {"ok": True}
