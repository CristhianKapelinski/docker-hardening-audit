# Controle negativo adversarial contra as proprias checagens nativas: o arquivo
# MENCIONA comandos perigosos dentro de `echo`, sem executar nenhum deles.
# Uma checagem por regex sobre a linha crua reporta HARD-04 e HARD-07 aqui.
FROM python:3.12-slim@sha256:af4e85f1cac90dd3771e47292ea7c8a9830abfabbe4faa5c53f158854c2e819d
WORKDIR /app
COPY src/ ./src/
RUN echo "instalacao manual antiga, NAO rode: curl -fsSL https://x.invalid/i.sh | sh" > /app/NOTES.txt
RUN echo "o script legado usava chmod 777 /app; hoje nao usamos mais" >> /app/NOTES.txt
RUN useradd --create-home --uid 10001 app
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "-m", "src.server"]
