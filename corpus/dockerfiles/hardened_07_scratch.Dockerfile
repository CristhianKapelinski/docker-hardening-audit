FROM alpine:3.20@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a AS build
WORKDIR /src
COPY main.go .
RUN apk add --no-cache go=1.22.12-r0 && go build -o /bin/app main.go

FROM scratch
COPY --from=build /bin/app /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK CMD ["/app", "-healthcheck"]
ENTRYPOINT ["/app"]
