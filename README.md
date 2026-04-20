# Gravity-SOC
Centro de Operaciones de Seguridad (SOC) distribuido, ligero y asimétrico. 
## 1. Arquitectura General

Gravity SOC opera basado en un esquema cliente-servidor de L2/L1, diseñado bajo la premisa del mínimo consumo y el paso de variables ultra-rápido en memoria, huyendo todo lo posible de la compilación cruzada dependiente de lenguajes como C (CGO).

Se compone de **dos repositorios o módulos principales**:

### A. Gravity SOC Agent (Capa L1 - Sensores)
El agente de Gravity SOC es un ejecutable polimórfico escrito en `Go` que se adapta silenciosamente al sistema operativo en el que se despliega.
- **Windows (Host L1)**: Se engancha limpiamente al registro de Windows y abstrae toda la lógica compleja de interconectarse a los registros `ETW (Event Tracing for Windows)`. Aprovechando `wevtutil`, el agente lee de forma cíclica e inversa los eventos generados por Sysmon (Sysinternals) esquivando binarios incompatibles en el runtime de Go. Especializado en capturar:
  - Creación de procesos y comandos (`EventID: 1`).
  - Conexiones de red internas y a dominios exteriores (`EventID: 3`).
  - Mutaciones en el sistema / Inyecciones de memoria remotas (`EventID: 8`).
  - Lecturas sobre archivos de gran peso / Registro de DNS del host.
- **Linux (Network L1 / Raspberry Pi Zero 2 W)**: Desempeñando el papel de centinela silencioso dentro de la red corporativa/casera, el agente intercepta logs volátiles de un servidor DNS local (como Unbound) que expone las resoluciones. Si un dispositivo intenta buscar un "malicious.com" (ya esté camuflado, ya sea una ráfaga o una botnet), el agente captura el paquete instantáneamente apoyado por su lectura asíncrona robusta.

**Envío Resiliente:** Ambos agentes emplean un bus de eventos (Memory Channel), limitando la huella RAM a no más de 1000 eventos retenidos en simultáneo. Un emisor en forma de bucle enviará mediante peticiones `POST` cifradas todos los eventos, dotado de reintentos exponenciales automáticos de hasta 1 minuto para prevenir congelación o caída general del servidor (L2). 

### B. Gravity SOC Server (Capa L2 - Cerebro y Correlador)
Desplegado típicamente en un sistema algo mayor (como una Raspberry Pi 5 o servidor local), el "Cerebro" ingiere la telemetría continua de todos los L1 de la red.
- **Motor SQLite**: Usando configuraciones PRAGMA exclusivas para rendimiento transaccional (`WAL` y `Synchronous = NORMAL`), mantiene el récord histórico en una base de datos de disco local capaz de tolerar flujos muy violentos de escritura con *locks* mínimos.
- **Correlación Real en Segundos**: Usa consultas matemáticas cruzadas en tiempo real para emparejar piezas aisladas. Un `dns_alert` captado por el router y un `network_dns` generado por Sysmon en Windows se unen por su nombre de dominio y línea temporal (delta máximo de ~10 segundos) evidenciando "qué máquina de la red fue la que causó el disparo general".
- **Generador de Reportes en PDF**: Diariamente genera y renderiza de forma autónoma (apoyado en el paquete *GoFPDF*) informes ejecutivos y tabulados en un archivo plano en la carpeta `/reports/` informando de la jornada (ingestas globales y emparejamientos confirmados).

---

## 2. Historial de Crisis y Evolución Tecnológica (Wall of Bugs)

Durante la fase intensiva de despliegue real en ecosistemas Windows y pruebas cruzadas, detectamos problemas críticos en el manejo y fiabilidad del agente debido a la naturaleza brutal de la API de Windows, lo que forzó diversas iteraciones de diseño del agente y del servidor de Gravity SOC, consolidando su invulnerabilidad:

1. **El Asesino del UTF-16 (Sysmon Windows XML)**: Los shells y el `Event Log API` nativa de Windows soltaban ocasionalmente basura *little-endian* a 16-bits (o nulos `0x00` inyectados). Para solucionarlo, el agente integró uno de los *handlers* más limpios y destructivos del entorno **(Filtro de Aniquilación de Lista Blanca)** que destripa radicalmente y reconstruye todo bytes en un `UTF-8` validado matemáticamente.
2. **Crash de Conexión de Capa 1 y Freeze Local**: Se descubrieron caídas completas del Agente al ser incapaz de contactar al servidor, llenando el bus de memoria e imposibilitando las lecturas a `wevtutil`. El agente fue mutado y todos los procesos (el capturador, el comprobador sysmon, etc) se modificaron al estándar "cero-bloqueos" de Go (`select/default`), reventando o ignorando eventos sobrantes para jamás comprometer el estado funcional de la máquina anfitriona. 
3. **Ghost Hostnames (Filtración de la Interfaz)**: Variables y marcadores en crudo (`os.Open` con memory leaks) obligaron a abstraer el cálculo del agente `AgentID` mediante cacheado persistente antes del *Runtime*, salvando file handles. Se aplicó el uso guardado en memoria disco con un pseudo-caché (`.gravity-checkpoint`) para sobrevivir a los reinicios de Windows sin re-lanzar un aluvión de alertas viejas.
4. **Resiliencia SQL (Cerebro Ciego)**: Al realizar la comparativa SQL para cruzar los eventos en la mesa de correlación (Agente Network VS Agente Windows), `database/sql` de Go sufría silenciosas paradas cardíacas debido a celdas SQLite desiertas (`NULL`). Fue subsanado empleando `TrimSpace`, `COALESCE` en inyección pura por SQL, relax de las métricas zonales y variables independientes por agente.

---

## 3. Pasos de Despliegue y Ejecución

*Es requisito contar con `Go >= 1.22` y acceso a administrador para enganchar a disco y redes si deseas ejecutar los binarios.*

### Compilar y Arrancar el Agente (Terminal Autorizada)
```bash
# Entrar a la carpeta del Agente
cd gravity-soc-agent

# Descargar módulos necesarios
go mod tidy 

# 1. COMPILAR LINUX (Sensor PI)
$env:GOOS="linux"; $env:GOARCH="arm"  # (o "arm64" dependiendo de kernel)
go build -o gravity-agent-linux

# 2. COMPILAR WINDOWS (Endpoint)
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -o gravity-agent.exe

# Ejecutar Agent Win (En Powershell/CMD de Admin)
.\gravity-agent.exe
```

### Compilar y Arrancar el Servidor L2
```bash
# Entrar a la carpeta Server
cd gravity-soc-server

go mod tidy
go build -o gravity-server.exe

# Ejecución simple (se arranca WebServer)
# Recibirá POSTS en /api/v1/events
.\gravity-server.exe
```

*Nota: Asegúrate de tener `wevtutil` funcional y Microsoft Sysmon correctamente configurado si testeas el agente de host en Windows.*

---

## 4. Diagrama Rápido del Flujo

1. **Pi Zero (Tailer.go)** Lee silenciosamente un fichero de log Unbound. Encuentra que alguien solicita `botnet-server.ru`. Como es regex crítico, empaqueta a `dns_alert` y lo manda por HTTP al Servidor L2 Pi 5.
2. **Windows 11 (Sysmon_windows.go)**: En el bucle de wevtutil extrae que Microsoft Edge ha solicitado DNS para `botnet-server.ru` y originó un hilo. Filtra, destruye impurezas y lo empaqueta a `network_dns`. Lo manda al L2 Pi 5.
3. **Servidor L2 (Pi 5)**: El `correlator` al expirar la ventana SQL (`ABS <= 10 seg`), emparenta el dominio `botnet-server.ru`. Muestra la `source_ip` de Windows y confirma la brecha en un informe limpio PDF.
