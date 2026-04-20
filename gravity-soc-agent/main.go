package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"gravity-soc-agent/collector"
	"gravity-soc-agent/models"
	"gravity-soc-agent/sender"
	"gravity-soc-agent/tailer"
)

func checkAdminPrivileges() {
	if runtime.GOOS == "windows" {
		// Comprobar privilegios de administrador en Windows
		// En Windows, los administradores suelen tener acceso a SID "S-1-5-32-544"
		// La forma rápida pero fiable sin CGO es intentar leer una clave de registro o abrir servicio
		// o bien usar os/user:
		f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			log.Fatalf("[CRITICAL] El Agente de Gravity SOC en Windows requiere privilegios de ADMINISTRADOR. Por favor, ejecute como Administrador.")
		}
		f.Close()
	}
}

func main() {
	log.Println("Iniciando Gravity SOC Agent...")
	
	checkAdminPrivileges()

	// Contexto cancelable para apagado seguro
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Interceptar señales de sistema (Ctrl+C, SIGTERM)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Canal interno para pasar eventos (Buffer de 1000 eventos en RAM)
	eventsChan := make(chan models.Event, 1000)

	// === LÓGICA DE SENSORES MULTIPLATAFORMA ===
	log.Printf("Plataforma detectada: %s_%s", runtime.GOOS, runtime.GOARCH)

	if runtime.GOOS == "windows" {
		// Sensor Endpoint L1 (Windows): Sysmon ETW
		go collector.StartSysmonCollector(ctx, eventsChan)
	} else {
		// Sensor de Borde L1 (Pi2W): Parseo de logs DNS
		logFilePath := os.Getenv("GRAVITY_LOG_PATH")
		if logFilePath == "" {
			logFilePath = "/var/log/soc_alerts.log"
		}
		go tailer.StartUnboundTailer(ctx, logFilePath, eventsChan)
	}

	var hostname string
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		if runtime.GOOS == "windows" {
			hostname = "win-unknown"
		} else {
			hostname = "linux-unknown"
		}
	}
	agentID := "sensor-" + runtime.GOOS + "-" + hostname

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				evt := models.Event{
					Timestamp: time.Now().UTC(),
					AgentID:   agentID,
					OS:        runtime.GOOS,
					EventType: "agent_heartbeat",
					Severity:  "info",
					RawMessage: "heartbeat_ping",
					Source: models.Source{Hostname: hostname},
				}
				select {
				case eventsChan <- evt:
				default:
					log.Println("[WARNING] Canal interno lleno. Descartando heartbeat.")
				}
			}
		}
	}()

	// === LÓGICA DE ENVÍO ===
	// Lanzar Sender para enviar a la Pi 5 en L2
	pi5ServerURL := os.Getenv("GRAVITY_SERVER_URL")
	if pi5ServerURL == "" {
		pi5ServerURL = "http://192.168.1.100:8443/api/v1/events"
	}
	go sender.StartHTTPSender(ctx, pi5ServerURL, eventsChan)

	// Esperar terminación
	<-sigs
	log.Println("Señal de apagado recibida. Cerrando agente...")
	cancel()
	time.Sleep(200 * time.Millisecond) // Margen de cierre
	log.Println("Apagado completo. Adiós.")
}
