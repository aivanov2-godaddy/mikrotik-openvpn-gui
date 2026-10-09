ARG VERSION=1.11.0
ARG REVISION=unknown
ARG SOURCE_URL=""

FROM public.ecr.aws/docker/library/python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72 AS routeros-rootfs

ARG VERSION
ARG REVISION
ARG INSTALL_REDIS=false

WORKDIR /app

# Runtime code is part of the immutable image. Production must not mount over /app.
COPY app.py automation.py config.py certificate_lifecycle.py connection_doctor.py diagnostic_bundle.py error_guidance.py event_safety.py exposure_doctor.py favicon.py icons.py integrations.py profile_diagnostics.py qr.py routeros.py security.py store.py templates.py telemetry_broker.py telemetry_canary.py telemetry_gateway.py telemetry_socketio.py telemetry_socketio_polling.py telemetry_runtime.py telemetry_state.py telemetry_supervisor.py routeros_binary.py ./
COPY asgi.py entrypoint.py requirements-runtime.txt requirements-redis.txt ./
COPY static ./static
COPY LICENSE /usr/share/licenses/mikrotik-openvpn-gui/LICENSE

# Keep the release identity available to the runtime without exposing build or
# runtime environment variables through the unauthenticated readiness route.
RUN printf '%s\n' "$VERSION" > /app/VERSION \
    && printf '%s\n' "$REVISION" > /app/REVISION \
    && python -m pip install --disable-pip-version-check --no-cache-dir --no-compile --target /app/runtime -r /app/requirements-runtime.txt \
    && if [ "$INSTALL_REDIS" = "true" ]; then python -m pip install --disable-pip-version-check --no-cache-dir --no-compile --target /app/runtime -r /app/requirements-redis.txt; fi

# The application prepares database ownership as root and then drops to UID/GID 65534.
RUN mkdir -p /data \
    && chmod 0700 /data

# RouterOS creates these runtime identity files itself and refuses to start an
# extracted image when they already exist in the root filesystem. Build a clean
# rootfs copy instead of using a recent external Dockerfile frontend.
RUN set -o pipefail \
    && mkdir /rootfs \
    && tar -C / \
        --exclude=./rootfs \
        --exclude=./dev \
        --exclude=./etc/hostname \
        --exclude=./etc/hosts \
        --exclude=./etc/resolv.conf \
        --exclude=./proc \
        --exclude=./run \
        --exclude=./sys \
        -cpf - . \
    | tar -C /rootfs -xpf - \
    && mkdir -p /rootfs/dev /rootfs/proc /rootfs/run /rootfs/sys

FROM scratch

ARG VERSION
ARG REVISION
ARG SOURCE_URL

LABEL org.opencontainers.image.title="MikroTik OpenVPN GUI" \
      org.opencontainers.image.description="A focused OpenVPN control plane for MikroTik RouterOS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=routeros-rootfs /rootfs/ /

WORKDIR /app

ENV APP_PORT=8080 \
    REDIRECT_PORT=8081 \
    SOCKETIO_ENGINE=asgi \
    DATABASE_PATH=/data/dashboard.sqlite \
    PYTHONPATH=/app/runtime \
    DROP_PRIVILEGES=true \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8080 8081
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz || exit 1

CMD ["python3", "-B", "/app/entrypoint.py"]
