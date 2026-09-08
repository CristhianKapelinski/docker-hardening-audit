FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes --target=/deps -r requirements.txt

FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d
WORKDIR /app
COPY --from=build /deps /usr/local/lib/python3.12/site-packages
COPY src/ ./src/
RUN useradd --create-home --uid 10001 app
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "-m", "src.server"]
