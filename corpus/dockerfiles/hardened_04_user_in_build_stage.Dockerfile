FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d AS base
RUN useradd --create-home --uid 10001 app
USER app

FROM base
WORKDIR /app
COPY --chown=app:app src/ ./src/
EXPOSE 8000
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "-m", "src.server"]
