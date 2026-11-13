from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.extra import router as extra_router
from app.api.routes import router
from app.api.team import router as team_router
from app.core import team
from app.config import APP_NAME, APP_VERSION, HOST, PORT, WEB_DIR

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Convert Sigma rules to 31 SIEM, EDR and log platforms and map them to MITRE ATT&CK.",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.include_router(router)
app.include_router(extra_router)
app.include_router(team_router)
app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

INDEX = WEB_DIR / "index.html"


@app.on_event("startup")
def start_scheduler():
    from app.core.scheduler import start_if_enabled

    start_if_enabled()
    from app.core.fcschedule import start_if_enabled as start_fire

    start_fire()


PUBLIC = ("/api/auth/me", "/api/auth/login", "/api/auth/setup", "/api/auth/logout", "/api/config")


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)
    ip = request.client.host if request.client else "?"
    if team.RATE_LIMIT and not team.limiter.allow(f"api:{ip}", team.RATE_LIMIT):
        return JSONResponse({"detail": "Too many requests. Slow down and try again in a minute."}, status_code=429)
    user = None
    if team.AUTH:
        method = request.method.upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("x-sigma-forge") != "1":
                return JSONResponse({"detail": "Missing the X-Sigma-Forge request header"}, status_code=403)
            origin = request.headers.get("origin")
            if origin and origin.split("://", 1)[-1] != request.headers.get("host", ""):
                return JSONResponse({"detail": "Cross site request blocked"}, status_code=403)
        user = team.session(request.cookies.get(team.COOKIE))
        request.state.user = user
        if path not in PUBLIC and not path.startswith("/api/auth/password"):
            if not user:
                return JSONResponse({"detail": "Sign in first"}, status_code=401)
            if not team.allowed(user["role"], method, path):
                return JSONResponse({"detail": f"Your role ({user['role']}) cannot do this"}, status_code=403)
    response = await call_next(request)
    if user and request.method.upper() not in ("GET", "HEAD", "OPTIONS") and not path.startswith(("/api/team", "/api/auth")):
        if not any(path.startswith(p) for p in team.VIEWER_POST_OK):
            team.audit(user["username"], f"{request.method} {path}", "", ip, response.status_code)
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.startswith("/api/"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
    path = request.url.path
    if path.endswith((".css", ".js", ".html")) or path == "/" or not path.startswith(("/assets", "/api")):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(INDEX)


@app.get("/{path:path}", include_in_schema=False)
def spa_fallback(path: str):
    if path.startswith("api/"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return FileResponse(INDEX)


def run():
    import uvicorn

    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    run()
