from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import APP_NAME, APP_VERSION, HOST, PORT, WEB_DIR

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Convert Sigma rules to Splunk, Elastic, Microsoft KQL and Wazuh, and map them to MITRE ATT&CK.",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.include_router(router)
app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

INDEX = WEB_DIR / "index.html"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
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
