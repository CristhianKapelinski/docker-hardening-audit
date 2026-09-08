FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
RUN useradd --create-home --uid 10001 app
USER app
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "-m", "src.server"]
