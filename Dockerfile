# Hardened by the policy this tool enforces, and audited by it in CI.
# The only expected finding is HARD-09 (no HEALTHCHECK), which is LOW and does
# not apply to a one-shot CLI image: there is no service to probe.
FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d

LABEL org.opencontainers.image.title="dhaudit" \
      org.opencontainers.image.description="Docker hardening audit over hadolint, trivy and dockle" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/CristhianKapelinski/docker-hardening-audit"

WORKDIR /opt/dhaudit
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 10001 auditor

USER auditor
WORKDIR /work
ENTRYPOINT ["dhaudit"]
CMD ["--help"]
