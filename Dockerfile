FROM node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/index.html frontend/tsconfig.json frontend/vite.config.ts ./
COPY frontend/src ./src
COPY frontend/public ./public
RUN npm run build

FROM python:3.12-alpine3.24@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src ONJEON_FRONTEND_DIST=/app/frontend/dist
WORKDIR /app
RUN apk add --no-cache zlib=1.3.2-r1
COPY requirements-runtime.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-runtime.lock \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && addgroup -S -g 10001 onjeon \
    && adduser -S -D -H -u 10001 -G onjeon onjeon \
    && mkdir -p /app/data /app/.secrets \
    && chown -R onjeon:onjeon /app/data /app/.secrets \
    && chmod 700 /app/data /app/.secrets
COPY src ./src
COPY scripts/run_tls_server.py ./scripts/run_tls_server.py
COPY --from=web /web/dist ./frontend/dist
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"
CMD ["python", "-m", "uvicorn", "onjeon.api:create_default_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]
