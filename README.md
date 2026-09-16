# Gravity-SOC

Lightweight distributed SOC platform in Go. Client-server architecture for real-time security monitoring and incident response.

![Go](https://img.shields.io/badge/Go-%3E%3D1.22-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20ARM-blue)

Centro de Operaciones de Seguridad (SOC) distribuido, ligero y asimetrico.

## Arquitectura

```
                          Gravity SOC Server (L2)
                          ========================
                          - SQLite WAL (events + correlations)
                          - Motor de correlacion en memoria
                          - Watchdog de sensores
                          - Retencion nocturna automatica
                          - API REST + Reportes PDF
                          - Deployable en Docker
                          |
              +-----------+-----------+
              |                       |
     Agent L1 (Windows)        Agent L1 (Linux/Pi)
     ==================        ==================
     - Sysmon EventLog         - DNS log tailer
     - wevtutil polling        - Unbound / DNS-spy
     - EventIDs 1,3,8,11,      - Regex IPv4 + IPv6
       12,13,22                - Alertas DNS
     - Checkpoint atomico      - Backoff exponencial
     - API key auth            - API key auth
              |                       |
              +-----------+-----------+
                          |
                    HTTP POST + JSON
                    X-API-Key header
```

## Roles de cada componente

### Agent L1 - Windows (Endpoint Sensor)

| Rol | Descripcion |
|-----|-------------|
| Sensor de host | Lee eventos de Sysmon via `wevtutil` (sin CGO) |
| EventIDs cubiertos | 1 (process create), 3 (network), 8 (remote thread), 11 (file), 12/13 (registry), 22 (DNS) |
| Normalizacion | UTF-16 a UTF-8, filtrado ASCII, dominios en lowercase |
| Checkpoint | `.gravity-checkpoint` con escritura atomica (temp + rename) |
| Envio | HTTP POST con backoff exponencial (1s a 60s), API key header |
| Requiere | Sysmon instalado + permisos de administrador |

### Agent L1 - Linux/Raspberry Pi (Network Sensor)

| Rol | Descripcion |
|-----|-------------|
| Sensor de borde | Tails log DNS (Unbound o formato DNS_ALERT) |
| Deteccion | Regex para IPv4 e IPv6, tipos A/AAAA/TXT/CNAME/PTR/MX/SRV/HTTPS/ANY |
| Alertas | Marca `dns_alert` severity=high para dominios maliciosos |
| Envio | HTTP POST con backoff exponencial, API key header |
| Requiere | Log DNS accesible (Unbound, Pi-hole, dns-spy) |

### Server L2 (Cerebro Correlador)

| Rol | Descripcion |
|-----|-------------|
| Ingesta | Recibe eventos via `/api/v1/events` con API key + MaxBytesReader (1MB) |
| Persistencia | SQLite WAL con tablas `events` y `correlations` |
| Correlacion | Empareja `dns_alert` (borde) con `network_dns` (endpoint) por dominio en ventana temporal |
| Alertas consolidadas | Persiste en tabla `correlations` + webhook opcional |
| Watchdog | Detecta sensores silenciosos >60s |
| Retencion | Purga automatica de eventos >N dias (default 30) |
| Reportes | PDF diario via `/api/v1/reports/daily` |
| API REST | Stats, correlaciones, eventos recientes para sec-dashboard |

## Correlacion de eventos

El motor de correlacion funciona en dos niveles:

### 1. Tiempo real (en memoria)

```
1. Pi Zero detecta DNS_ALERT para "botnet-server.ru" (severity=high)
   -> Se almacena en dnsAlertCache con deadline = now + 10s

2. Windows endpoint hace DNS query a "botnet-server.ru" (Sysmon EventID 22)
   -> Se busca en dnsAlertCache

3. Match dentro de la ventana de 10s
   -> ALERTA CONSOLIDADA L2
   -> Se persiste en tabla correlations
   -> Se envia webhook si configurado
```

### 2. Historico (SQL)

La tabla `correlations` guarda todas las alertas consolidadas con:
- Timestamp
- Dominio
- Endpoint host + IP
- Proceso culpable + GUID
- Agent ID

Consultable via `/api/v1/correlations` o usada en el reporte PDF diario.

## Puesta en marcha

### Opcion A: Compilacion local (Makefile)

```bash
# Compilar todo (server + agent windows + agent linux)
make all

# Solo servidor
make server

# Solo agent para Windows
make agent-windows

# Solo agent para Raspberry Pi (ARM)
make agent-linux
```

### Opcion B: Docker (servidor L2)

```bash
docker build -t gravity-soc-server .
docker run -d \
  -p 8443:8443 \
  -v gravity-data:/app/data \
  -v gravity-reports:/app/reports \
  -e GRAVITY_API_KEY=tu-clave-secreta \
  gravity-soc-server
```

### Opcion C: Manual

```bash
# Servidor
cd gravity-soc-server
go mod tidy
go build -o gravity-server .

# Agent Windows
cd gravity-soc-agent
GOOS=windows GOARCH=amd64 go build -o gravity-agent.exe .

# Agent Linux ARM (Pi Zero 2 W)
GOOS=linux GOARCH=arm go build -o gravity-agent-linux .
```

### Configuracion

Copia `.env.example` a `.env` y ajusta:

```bash
# Servidor
GRAVITY_PORT=:8443
GRAVITY_API_KEY=tu-clave-secreta
GRAVITY_RETENTION_DAYS=30
GRAVITY_WEBHOOK_URL=https://hooks.slack.com/services/XXX

# Agente
GRAVITY_SERVER_URL=http://ip-del-servidor:8443/api/v1/events
GRAVITY_API_KEY=tu-clave-secreta
```

## Ejecutar

```bash
# 1. Arrancar servidor L2
./gravity-server

# 2. Arrancar agent en Windows (como admin)
./gravity-agent.exe

# 3. Arrancar agent en Raspberry Pi
GRAVITY_SERVER_URL=http://ip-servidor:8443/api/v1/events ./gravity-agent-linux
```

## Endpoints API

| Ruta | Metodo | Descripcion |
|------|--------|-------------|
| `/api/v1/events` | POST | Ingesta de eventos (agentes L1) |
| `/api/v1/health` | GET | Health check del servidor |
| `/api/v1/stats` | GET | Estadisticas diarias + estado de agentes |
| `/api/v1/correlations` | GET | Correlaciones confirmadas (JSON) |
| `/api/v1/events/recent` | GET | Ultimos N eventos (default 50) |
| `/api/v1/reports/daily` | GET | Generar reporte PDF |

Todas las rutas excepto `/health` requieren `X-API-Key` header si `GRAVITY_API_KEY` esta configurada.

## Integracion con sec-dashboard / Splunk

### Polling desde sec-dashboard

```bash
# Stats del dia
curl -H "X-API-Key: tu-clave" http://servidor:8443/api/v1/stats

# Correlaciones confirmadas
curl -H "X-API-Key: tu-clave" http://servidor:8443/api/v1/correlations

# Eventos recientes
curl -H "X-API-Key: tu-clave" http://servidor:8443/api/v1/events/recent?limit=100
```

### Webhook a sec-dashboard

```bash
export GRAVITY_WEBHOOK_URL=https://sec.sammideblas.com/api/ingest
```

Cada correlacion confirmada enviara un POST JSON con el detalle de la alerta.

### Splunk HEC

Los eventos se pueden reenviar a Splunk desde sec-dashboard o con un script:

```bash
# Ejemplo: reenviar correlaciones a Splunk
curl -H "X-API-Key: tu-clave" http://servidor:8443/api/v1/correlations | \
  curl -H "Authorization: Splunk TOKEN" -d @- https://splunk:8088/services/collector
```

## Variables de entorno

### Servidor (L2)

| Variable | Default | Descripcion |
|----------|---------|-------------|
| `GRAVITY_PORT` | `:8443` | Puerto de escucha |
| `GRAVITY_DB_PATH` | `./gravity-soc.db` | Ruta SQLite |
| `GRAVITY_API_KEY` | (vacio) | API key para auth |
| `GRAVITY_CORRELATION_WINDOW` | `10s` | Ventana de correlacion |
| `GRAVITY_RETENTION_DAYS` | `30` | Dias de retencion |
| `GRAVITY_WEBHOOK_URL` | (vacio) | Webhook para alertas |

### Agente (L1)

| Variable | Default | Descripcion |
|----------|---------|-------------|
| `GRAVITY_SERVER_URL` | `http://127.0.0.1:8443/api/v1/events` | URL del servidor L2 |
| `GRAVITY_API_KEY` | (vacio) | API key (debe coincidir) |
| `GRAVITY_LOG_PATH` | `/var/log/soc_alerts.log` | Log DNS (Linux) |

## Requisitos

- Go >= 1.22
- Windows: Sysmon instalado + permisos admin
- Linux: log DNS accesible (Unbound, Pi-hole, dns-spy)
- Raspberry Pi Zero 2 W: ARMv6 (GOARCH=arm)
- Raspberry Pi 5: ARM64 (GOARCH=arm64)

## Licencia

MIT -- ver [LICENSE](LICENSE).

---

## Contacto

- Pagina: [sammideblas.com](https://sammideblas.com)
- Email: analista@sammideblas.com
