FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d
WORKDIR /app
ADD vendor/wheels.tar.gz /opt/wheels/
COPY src/ ./src/
RUN pip install --no-cache-dir --no-index --find-links=/opt/wheels 'flask==3.0.3'
RUN useradd --create-home --uid 10001 app
USER app
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "-m", "src.server"]
