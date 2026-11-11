FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SIGMA_FORGE_HOST=0.0.0.0 \
    SIGMA_FORGE_PORT=8000 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN python -m venv /opt/venv

COPY requirements.txt requirements-legacy.txt ./
RUN pip install -r requirements.txt && pip install --no-deps -r requirements-legacy.txt

COPY app ./app
COPY web ./web
COPY data ./data
COPY sample ./sample
COPY tools ./tools

ARG REFRESH_ATTACK=false
RUN if [ "$REFRESH_ATTACK" = "true" ]; then python tools/fetch_attack.py; fi

RUN useradd --create-home --uid 10001 forge && mkdir -p /app/library && chown -R forge:forge /app
USER forge

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["sh", "-c", "uvicorn app.main:app --host ${SIGMA_FORGE_HOST} --port ${SIGMA_FORGE_PORT} --proxy-headers"]
