# syntax=docker/dockerfile:1

# One image, two roles: `serve` (the app, default) and `broker`.

FROM ghcr.io/astral-sh/uv:0.12.21 AS uv

FROM python:3.12-slim-trixie AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first, from the lock file only, so source changes keep this layer cached.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.12-slim-trixie
LABEL org.opencontainers.image.title="mailcow-mcp" \
      org.opencontainers.image.description="Self-hosted remote MCP server for mailcow" \
      org.opencontainers.image.source="https://github.com/nitramxx/mailcow-mcp" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin mcp \
    && install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["mailcow-mcp", "healthcheck"]
ENTRYPOINT ["mailcow-mcp"]
CMD ["serve"]
