# Gravity SOC Server (L2) - Docker
# Para despliegue rapido en cualquier maquina con Docker

FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY gravity-soc-server/ ./
RUN go mod tidy && go build -o gravity-server .

FROM alpine:latest
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /build/gravity-server .
COPY --from=builder /build/gravity-sysmon.xml ./gravity-sysmon.xml

# Crear directorios
RUN mkdir -p /app/reports /app/data

# Variables de entorno con defaults
ENV GRAVITY_PORT=:8443
ENV GRAVITY_DB_PATH=/app/data/gravity-soc.db
ENV GRAVITY_RETENTION_DAYS=30

EXPOSE 8443

VOLUME ["/app/data", "/app/reports"]

CMD ["./gravity-server"]