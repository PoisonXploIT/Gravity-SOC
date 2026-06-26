package correlator

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gravity-soc-server/db"
	"gravity-soc-server/models"
)

// Motor de correlacion en memoria (Ventana Temporal)
// Mantiene un cache temporal de alertas DNS del sensor de borde (Pi2W)
// para cruzar con eventos DNS de endpoints Windows.

type CacheItem struct {
	Event    models.Event
	Deadline time.Time
}

type AgentInfo struct {
	AgentID  string    `json:"agent_id"`
	LastSeen time.Time `json:"last_seen"`
	Silent   bool      `json:"silent"`
}

var (
	dnsAlertCache     = make(map[string]CacheItem)
	agentHealthCache  = make(map[string]time.Time)
	mu                sync.Mutex
	healthMu          sync.Mutex
	correlationWindow time.Duration
)

func init() {
	correlationWindow = 10 * time.Second
	if windowStr := os.Getenv("GRAVITY_CORRELATION_WINDOW"); windowStr != "" {
		if d, err := time.ParseDuration(windowStr); err == nil {
			correlationWindow = d
		}
	}
	log.Printf("[CORRELATOR] Ventana de correlacion: %s", correlationWindow)
}

// GetCorrelationWindow devuelve la ventana configurada (para API)
func GetCorrelationWindow() string {
	return correlationWindow.String()
}

// GetAgentStatus devuelve el estado de todos los agentes conocidos (para API)
func GetAgentStatus() []AgentInfo {
	healthMu.Lock()
	defer healthMu.Unlock()

	var agents []AgentInfo
	for agentID, lastSeen := range agentHealthCache {
		agents = append(agents, AgentInfo{
			AgentID:  agentID,
			LastSeen: lastSeen,
			Silent:   time.Since(lastSeen) > 60*time.Second,
		})
	}
	return agents
}

// ProcessEvent evalua y enruta un evento recien llegado
func ProcessEvent(event models.Event) {
	// Signo de vida para CUALQUIER evento
	healthMu.Lock()
	agentHealthCache[event.AgentID] = time.Now()
	healthMu.Unlock()

	if event.EventType == "agent_heartbeat" {
		return
	}

	// Normalizacion de dominio
	normalizedDomain := strings.TrimSpace(event.Destination.Domain)
	normalizedDomain = strings.ToLower(normalizedDomain)
	normalizedDomain = strings.TrimSuffix(normalizedDomain, ".")
	event.Destination.Domain = normalizedDomain

	// Logica 1: Alerta DNS desde el sensor de borde (Pi2W)
	if event.EventType == "dns_alert" && event.Severity == "high" {
		mu.Lock()
		dnsAlertCache[normalizedDomain] = CacheItem{
			Event:    event,
			Deadline: time.Now().Add(correlationWindow),
		}
		mu.Unlock()
		log.Printf("[CORRELATOR] ALERTA L1 (Borde) Indexada: dominio malicioso %s. Esperando endpoints...", normalizedDomain)
	}

	// Logica 2: Evento DNS desde Windows Sysmon (EventID 22)
	if event.EventType == "network_dns" && event.OS == "windows" {
		mu.Lock()
		cached, exists := dnsAlertCache[normalizedDomain]
		mu.Unlock()

		if exists && time.Now().Before(cached.Deadline) {
			// === ALERTA CONSOLIDADA L2 ===
			log.Printf("\n[!!! ALERTA CONSOLIDADA L2 !!!]")
			log.Printf("-> Dominio malicioso '%s' detectado por sensor perimetral", normalizedDomain)
			log.Printf("-> Endpoint origen: %s (IP: %s)", event.Source.Hostname, event.Source.IP)
			log.Printf("-> Proceso culpable: %s (GUID: %s)", event.Process.Name, event.Process.ProcessGuid)
			log.Printf("=====================================\n")

			// Persistir correlacion en SQLite
			err := db.InsertCorrelation(db.CorrelationRecord{
				Timestamp:    time.Now().UTC(),
				Domain:       normalizedDomain,
				EndpointHost: event.Source.Hostname,
				EndpointIP:   event.Source.IP,
				ProcessName:  event.Process.Name,
				ProcessGUID:  event.Process.ProcessGuid,
				AgentID:      event.AgentID,
			})
			if err != nil {
				log.Printf("[CORRELATOR] Error guardando correlacion en DB: %v", err)
			}

			// Webhook opcional (Slack, TheHive, Wazuh, sec-dashboard)
			sendWebhook(normalizedDomain, event)
		}
	}
}

// sendWebhook envia una alerta a un endpoint externo si esta configurado
func sendWebhook(domain string, event models.Event) {
	webhookURL := os.Getenv("GRAVITY_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}

	// Import minimal para no anadir dependencias pesadas
	// El webhook es un POST JSON simple
	go func() {
		// Construir payload manualmente para evitar importar encoding/json aqui
		// si ya se importa en otros paquetes
		alert := struct {
			AlertType   string `json:"alert_type"`
			Domain      string `json:"domain"`
			Endpoint    string `json:"endpoint"`
			Process     string `json:"process"`
			Severity    string `json:"severity"`
			Timestamp   string `json:"timestamp"`
		}{
			AlertType: "consolidated_dns_correlation",
			Domain:    domain,
			Endpoint:  event.Source.Hostname + " (" + event.Source.IP + ")",
			Process:   event.Process.Name,
			Severity:  "critical",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		_ = alert // El envio real se implementaria con net/http.Post
		log.Printf("[WEBHOOK] Alerta preparada para %s (domain=%s endpoint=%s)", webhookURL, domain, event.Source.Hostname)
	}()
}

// CleanupCache limpia entradas antiguas periodicamente
func CleanupCache() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		mu.Lock()
		for domain, item := range dnsAlertCache {
			if time.Now().After(item.Deadline) {
				delete(dnsAlertCache, domain)
			}
		}
		mu.Unlock()
	}
}

// StartWatchdog monitoriza caidas de agentes
func StartWatchdog() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		healthMu.Lock()
		for agentID, lastSeen := range agentHealthCache {
			if time.Since(lastSeen) > 60*time.Second {
				log.Printf("\n[ALERTA CRITICA SOC]")
				log.Printf("-> El sensor L1 '%s' NO RESPONDE.", agentID)
				log.Printf("-> Lleva %v silencioso (Limite: 60s).", time.Since(lastSeen).Round(time.Second))
				log.Printf("-> Posibles causas: Corte de red, caida de nodo o agente detenido.")
				log.Printf("=====================================\n")
				delete(agentHealthCache, agentID)
			}
		}
		healthMu.Unlock()
	}
}

// StartRetentionJob ejecuta purga nocturna de eventos antiguos
func StartRetentionJob() {
	retentionDays := 30
	if d := os.Getenv("GRAVITY_RETENTION_DAYS"); d != "" {
		if n, err := parseInt(d); err == nil && n > 0 {
			retentionDays = n
		}
	}

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Ejecutar una vez al inicio
	runRetention(retentionDays)

	for range ticker.C {
		runRetention(retentionDays)
	}
}

func runRetention(days int) {
	deleted, err := db.PurgeOldEvents(days)
	if err != nil {
		log.Printf("[RETENTION] Error en purga: %v", err)
		return
	}
	if deleted > 0 {
		log.Printf("[RETENTION] %d eventos purgados (> %d dias)", deleted, days)
	}
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errParseInt
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errParseInt = &parseErr{}

type parseErr struct{}

func (e *parseErr) Error() string { return "invalid integer" }