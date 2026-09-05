FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE_URL=""

LABEL org.opencontainers.image.title="MikroTik OpenVPN GUI" \
      org.opencontainers.image.description="A focused OpenVPN control plane for MikroTik RouterOS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"

WORKDIR /app

# Runtime code is part of the immutable image. Production must not mount over /app.
COPY app.py automation.py favicon.py icons.py qr.py routeros.py security.py store.py templates.py ./
COPY static ./static
COPY LICENSE /usr/share/licenses/mikrotik-openvpn-gui/LICENSE

# The application prepares database ownership as root and then drops to UID/GID 65534.
RUN mkdir -p /data \
    && chmod 0700 /data

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
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["python3", "-B", "/app/app.py"]
