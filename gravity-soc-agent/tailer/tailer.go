package tailer

import (
	"context"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"gravity-soc-agent/models"

	"github.com/nxadm/tail"
)

// Tip: Las expresiones regulares compiladas fuera del loop evitan que la CPU ARM
// despilfarre ciclos compilando el patrón en cada nueva línea del log. Son ultra-rápidas.

// unboundRegex busca patrones estándar: info: 192.168.1.50 example.com. A IN
var unboundRegex = regexp.MustCompile(`(?i)(?:info:\s+)?(\d{1,3}(?:\.\d{1,3}){3})\s+([a-zA-Z0-9._-]+?)\.?\s+([A-Z0-9]+)\s+IN`)

// dnsSpyRegex busca una hipotética estructura de alerta: DNS_ALERT: Client: 192.168.1.50 -> malicious.com (A)
var dnsSpyRegex = regexp.MustCompile(`(?i)DNS_ALERT.*?(\d{1,3}(?:\.\d{1,3}){3}).*?([a-zA-Z0-9._-]+).*?(A|AAAA|TXT|CNAME|PTR|MX|SRV|HTTPS|ANY)`)

// StartUnboundTailer lee un archivo de log línea a línea sin bloquear y emite structs JSON
func StartUnboundTailer(ctx context.Context, filepath string, outChan chan<- models.Event) {
	// Configuración de Tail robusta: sigue rotaciones, no falla si el archivo no existe aún
	t, err := tail.TailFile(filepath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, // Empezar directamente al EOF
	})
	if err != nil {
		log.Printf("[ERROR] Fallo al iniciar tail en %s: %v. El sensor de log no enviará datos.", filepath, err)
		return
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "linux-unknown"
	}
	agentID := "sensor-linux-" + hostname

	log.Printf("Sensor L1 (Tail) escuchando log volátil en %s", filepath)

	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case line := <-t.Lines:
			if line.Err != nil || line.Text == "" {
				continue
			}

			text := line.Text
			
			// Variables para extraer los campos del log
			var ip, domain, qType, severity, eventType string
			
			// Intentamos primero con la alerta de gravedad alta (dns-spy)
			if strings.Contains(text, "DNS_ALERT") {
				matches := dnsSpyRegex.FindStringSubmatch(text)
				if len(matches) >= 4 {
					ip = matches[1]
					domain = matches[2]
					qType = strings.ToUpper(matches[3])
					severity = "high"
					eventType = "dns_alert"
				}
			} else {
				// Evaluamos toda línea restante como tráfico general de DNS (unbound)
				matches := unboundRegex.FindStringSubmatch(text)
				if len(matches) >= 4 {
					ip = matches[1]
					domain = matches[2]
					qType = strings.ToUpper(matches[3])
					severity = "info"
					eventType = "network_dns"
				}
			}

			// Normalizar dominio para coincidir perfectamente con la ventana 5s de correlación L2
			domain = strings.ToLower(domain)
			domain = strings.TrimSuffix(domain, ".")

			// Si detectamos correctamente el Regex (tenemos los datos), montamos y mandamos el evento
			if ip != "" && domain != "" && qType != "" {
				event := models.Event{
					Timestamp: time.Now().UTC(),
					AgentID:   agentID,
					OS:        "linux",
					EventType: eventType,
					Severity:  severity,
					Source: models.Source{
						IP: ip,
					},
					Destination: models.Destination{
						Domain: domain, 
						Port:   53,
					},
					Payload: models.Payload{
						DNSQueryType: qType,
					},
					RawMessage: text,
				}

				// Al canal de memoria concurrente (Cero bloqueo)
				select {
				case outChan <- event:
				default:
					// Ignoramos o logueamos warning para no bloquear el bucle del tailer
					log.Printf("[WARNING] Canal interno lleno. Descartando evento de dns_tailer.")
				}
			}
		}
	}
}
