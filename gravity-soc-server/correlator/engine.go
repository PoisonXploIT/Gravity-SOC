package correlator

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gravity-soc-server/models"
)

// Motor de correlación en memoria (Ventana Temporal)
// Mantiene un caché temporal de alertas de L1 (Pi2W) para cruzar con Eventos L1 (Windows)

type CacheItem struct {
	Event    models.Event
	Deadline time.Time
}

var (
	dnsAlertCache     = make(map[string]CacheItem) // Clave: Dominio
	agentHealthCache = make(map[string]time.Time)
	mu                sync.Mutex
	healthMu          sync.Mutex
	correlationWindow time.Duration
)

func init() {
	// Ventana de correlación configurable (default: 10s)
	correlationWindow = 10 * time.Second
	if windowStr := os.Getenv("GRAVITY_CORRELATION_WINDOW"); windowStr != "" {
		if d, err := time.ParseDuration(windowStr); err == nil {
			correlationWindow = d
		}
	}
	log.Printf("[CORRELATOR] Ventana de correlación: %s", correlationWindow)
}

// ProcessEvent evalúa y enruta un evento recién llegado
func ProcessEvent(event models.Event) {
	// Signo de Vida para CUALQUIER evento
	healthMu.Lock()
	agentHealthCache[event.AgentID] = time.Now()
	healthMu.Unlock()

	// Si es sólo un latido, no lo metemos al motor heurístico
	if event.EventType == "agent_heartbeat" {
		return
	}

	// 0. Normalización Total de Dominio
	normalizedDomain := strings.TrimSpace(event.Destination.Domain)
	normalizedDomain = strings.ToLower(normalizedDomain)
	normalizedDomain = strings.TrimSuffix(normalizedDomain, ".")
	event.Destination.Domain = normalizedDomain // Para consistencia

	// Lógica 1: Si llega una Alerta DNS desde la Pi2W (Alta severidad)
	if event.EventType == "dns_alert" && event.Severity == "high" {
		mu.Lock()
		// Lo guardamos en caché temporal por 5 segundos
		dnsAlertCache[normalizedDomain] = CacheItem{
			Event:    event,
			Deadline: time.Now().Add(correlationWindow),
		}
		mu.Unlock()
		log.Printf("[CORRELATOR] ALERTA L1 (Pi2W) Indexada: Dominio malicioso %s. Esperando a Windows...", normalizedDomain)
	}

	// Lógica 2: Si llega un Evento de Windows Sysmon (e.g. 22 - DNS)
	// Comparamos dominios con logs en vivo
	if event.EventType == "network_dns" && event.OS == "windows" {
		mu.Lock()
		cached, exists := dnsAlertCache[normalizedDomain]
		mu.Unlock()

		log.Printf("[DEBUG] Comparando Amenaza: [%s] con Evento Sysmon: [%s] | Exists: %v", normalizedDomain, normalizedDomain, exists)

		// ¿Se hizo esta consulta en los últimos 5 segundos desde la Pi2W?
		if exists && time.Now().Before(cached.Deadline) {
			
			// === ALERTA CONSOLIDADA (L2) ===
			log.Printf("\n[!!! ALERTA CONSOLIDADA L2 !!!]")
			log.Printf("-> El dominio malicioso '%s' detectado por el sensor perimetral (Pi2W)", normalizedDomain)
			log.Printf("-> Acaba de ser originado por el Endpoint: %s (IP: %s)", event.Source.Hostname, event.Source.IP)
			log.Printf("-> Proceso Culpable: %s (GUID: %s)", event.Process.Name, event.Process.ProcessGuid)
			log.Printf("=====================================\n")

			// Aquí en un SOC real enviaríamos un Webhook a Slack, Thehive o Wazuh.
		}
	}
}

// CleanupCache limpia entradas antiguas periódicamente
func CleanupCache() {
	for {
		time.Sleep(2 * time.Second)
		mu.Lock()
		for domain, item := range dnsAlertCache {
			if time.Now().After(item.Deadline) {
				delete(dnsAlertCache, domain)
			}
		}
		mu.Unlock()
	}
}

// StartWatchdog monitoriza caídas de agentes (Llamar desde main.go L2)
func StartWatchdog() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		healthMu.Lock()
		for agentID, lastSeen := range agentHealthCache {
			if time.Since(lastSeen) > 60*time.Second {
				log.Printf("\n[ALERTA CRITICA SOC]")
				log.Printf("-> El sensor L1 '%s' NO RESPONDE.", agentID)
				log.Printf("-> Lleva %v silencioso (Limite: 60s).", time.Since(lastSeen).Round(time.Second))
				log.Printf("-> Posibles causas: Corte de red, caida de nodo o agente detenido.")
				log.Printf("=====================================\n")
				// Se borra del caché para no spamear infinitamente
				delete(agentHealthCache, agentID)
			}
		}
		healthMu.Unlock()
	}
}
