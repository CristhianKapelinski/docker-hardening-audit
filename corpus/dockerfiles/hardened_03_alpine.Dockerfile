FROM alpine:3.20@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a
RUN apk add --no-cache python3=3.12.11-r0
WORKDIR /app
COPY src/ ./src/
RUN adduser -D -u 10001 app
USER app
EXPOSE 8080
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["python3", "-m", "src.server"]
