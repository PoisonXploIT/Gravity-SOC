package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"gravity-soc-server/correlator"
	"gravity-soc-server/db"
	"gravity-soc-server/models"
	"gravity-soc-server/reports"
)

// StartServer levanta un servidor HTTP ligero en el puerto especificado
func StartServer(port string) {
	// Rutas existentes
	http.HandleFunc("/api/v1/events", handleEvent)
	http.HandleFunc("/api/v1/health", handleHealth)
	http.HandleFunc("/api/v1/reports/daily", handleDailyReport)

	// Nuevas rutas para integracion con sec-dashboard / Splunk
	http.HandleFunc("/api/v1/stats", handleStats)
	http.HandleFunc("/api/v1/correlations", handleCorrelations)
	http.HandleFunc("/api/v1/events/recent", handleRecentEvents)

	// CORS basico para sec-dashboard
	http.HandleFunc("/api/v1/", corsMiddleware)

	log.Printf("[API] Receptor L2 escuchando en el puerto %s...", port)

	// En produccion usar ListenAndServeTLS para mTLS
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Error critico al iniciar el API Server: %v", err)
	}
}

// getAPIKey devuelve la clave configurada via env o vacio (modo abierto)
func getAPIKey() string {
	return os.Getenv("GRAVITY_API_KEY")
}

// authenticate verifica el header X-API-Key contra la clave configurada
func authenticate(r *http.Request) bool {
	key := getAPIKey()
	if key == "" {
		return true // Sin clave configurada = modo abierto (backward compat)
	}
	provided := r.Header.Get("X-API-Key")
	return provided == key
}

// corsMiddleware anade headers CORS para sec-dashboard
func corsMiddleware(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
	w.WriteHeader(http.StatusOK)
}

// handleHealth es un endpoint de estado para diagnosticar si L2 esta vivo
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"up"}`))
}

// handleEvent recibe el JSON enviado por los Agentes L1 (Pi2W / Windows)
func handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Autenticacion: API key si esta configurada
	if !authenticate(r) {
		log.Printf("[API] Evento rechazado: API key invalida o ausente")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
		return
	}

	defer r.Body.Close()

	// Limitar tamano del body a 1MB para prevenir DoS
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var event models.Event
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		log.Printf("Error decodificando evento: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid json"}`))
		return
	}

	// Validacion basica de campos obligatorios
	if event.AgentID == "" || event.EventType == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"missing required fields: agent_id, event_type"}`))
		return
	}

	// 1. Guardar persistentemente en SQLite (omitir heartbeats)
	if event.EventType != "agent_heartbeat" {
		err = db.InsertEvent(event)
		if err != nil {
			log.Printf("[DB] Error de insercion: %v", err)
		}
	}

	// 2. Pasar el evento por el motor de correlacion
	correlator.ProcessEvent(event)

	// Responder al agente
	if event.EventType != "agent_heartbeat" {
		log.Printf("[API] Evento procesado: agent=%s type=%s domain=%s", event.AgentID, event.EventType, event.Destination.Domain)
	}

	w.WriteHeader(http.StatusAccepted) // HTTP 202
}

// handleDailyReport dispara la generacion del reporte PDF bajo demanda
func handleDailyReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	filePath, err := reports.GenerateDailyReport()
	if err != nil {
		http.Error(w, "Error al generar informe: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Reporte diario generado exitosamente",
		"file":    filePath,
	})
}

// handleStats devuelve estadisticas diarias en JSON para sec-dashboard
func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	stats, err := db.GetDailyStats()
	if err != nil {
		http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
		return
	}

	agentStatus := correlator.GetAgentStatus()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats":         stats,
		"agents":        agentStatus,
		"correlation_window": correlator.GetCorrelationWindow(),
	})
}

// handleCorrelations devuelve correlaciones confirmadas en JSON
func handleCorrelations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Filtrar por limite query param (default 100)
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := parsePositiveInt(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	matches, err := db.GetDailyCorrelations()
	if err != nil {
		http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
		return
	}

	// Aplicar limite en la aplicacion
	if len(matches) > limit {
		matches = matches[:limit]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":         len(matches),
		"correlations":  matches,
	})
}

// handleRecentEvents devuelve los ultimos N eventos para sec-dashboard
func handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := parsePositiveInt(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	events, err := db.GetRecentEvents(limit)
	if err != nil {
		http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":  len(events),
		"events": events,
	})
}

// parsePositiveInt parsea un entero positivo desde string
func parsePositiveInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, io.ErrUnexpectedEOF
		}
		n = n*10 + int(c-'0')
		if n > 100000 {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}