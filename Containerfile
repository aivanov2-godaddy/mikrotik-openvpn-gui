# syntax=docker/dockerfile:1.19@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6

ARG VERSION=1.8.0
ARG REVISION=unknown
ARG SOURCE_URL=""

FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc AS routeros-rootfs

ARG VERSION
ARG REVISION

WORKDIR /app

# Runtime code is part of the immutable image. Production must not mount over /app.
COPY app.py automation.py config.py favicon.py icons.py integrations.py qr.py routeros.py security.py store.py templates.py ./
COPY static ./static
COPY LICENSE /usr/share/licenses/mikrotik-openvpn-gui/LICENSE

# Keep the release identity available to the runtime without exposing build or
# runtime environment variables through the unauthenticated readiness route.
RUN printf '%s\n' "$VERSION" > /app/VERSION \
    && printf '%s\n' "$REVISION" > /app/REVISION

# The application prepares database ownership as root and then drops to UID/GID 65534.
RUN mkdir -p /data \
    && chmod 0700 /data

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

# RouterOS creates these runtime identity files itself and refuses to start an
# extracted image when they already exist in the root filesystem.
COPY --from=routeros-rootfs \
    --exclude=etc/hostname \
    --exclude=etc/hosts \
    --exclude=etc/resolv.conf \
    / /

WORKDIR /app

ENV APP_PORT=8080 \
    REDIRECT_PORT=8081 \
    DATABASE_PATH=/data/dashboard.sqlite \
    DROP_PRIVILEGES=true \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8080 8081
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz || exit 1

CMD ["python3", "-B", "/app/app.py"]
