FROM ghcr.io/astral-sh/uv:python3.12-trixie-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

ENV UV_NO_DEV=1
ENV UV_PYTHON_DOWNLOADS=0

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project
COPY pyproject.toml /app
COPY uv.lock /app
ADD authsign /app/authsign
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

FROM python:3.12-slim

WORKDIR /app

ADD pyproject.toml uv.lock /app
COPY --from=builder --chown=nonroot:nonroot /app /app

ADD authsign /app/authsign
ENV PATH="/app/.venv/bin:$PATH"

ADD README.md /app
ADD log.json /app

# override by using custom config.yaml, or setting the DOMAIN_OVERRIDE and EMAIL_OVERRIDE
ADD config.sample.yaml config.yaml

CMD ["uvicorn", "authsign.main:app", "--port", "8080", "--workers", "1", "--host", "0.0.0.0", "--log-config", "/app/log.json"]

