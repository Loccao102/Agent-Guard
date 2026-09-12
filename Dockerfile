FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agentguard ./cmd/agentguard

FROM alpine:3.20
RUN addgroup -S agentguard && adduser -S agentguard -G agentguard
WORKDIR /app
COPY --from=build /out/agentguard /usr/local/bin/agentguard
COPY docker/agentguard.yaml /app/agentguard.yaml
RUN mkdir -p /app/.agentguard && chown -R agentguard:agentguard /app
USER agentguard
EXPOSE 7788
ENTRYPOINT ["agentguard"]
CMD ["run", "--config", "/app/agentguard.yaml"]
