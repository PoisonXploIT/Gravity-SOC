package api

import (
	"encoding/json"
	"log"
	"net/http"

	"gravity-soc-server/correlator"
	"gravity-soc-server/db"
	"gravity-soc-server/models"
	"gravity-soc-server/reports"
)

// StartServer levanta un servidor HTTP ligero en el puerto especificado
func StartServer(port string) {
	http.HandleFunc("/api/v1/events", handleEvent)
	http.HandleFunc("/api/v1/health", handleHealth)
	http.HandleFunc("/api/v1/reports/daily", handleDailyReport)

	log.Printf("[API] Receptor L2 escuchando en el puerto %s...", port)
	
	// En producción usaríamos http.ListenAndServeTLS para mTLS
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Error crítico al iniciar el API Server: %v", err)
	}
}

// handleHealth es un endpoint de estado para diagnosticar si L2 está vivo
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"up"}`))
}

// handleEvent recibe el JSON enviado por los Agentes L1 (Pi2W / Windows)
func handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Memory Optimization: Close body immediately using defer to avoid leaks on decode errors
	defer r.Body.Close()

	var event models.Event
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		log.Printf("Error decodificando evento: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 1. Guardar persistentemente el evento en SQLite en la Pi 5 (omitir si es un ping de health)
	if event.EventType != "agent_heartbeat" {
		err = db.InsertEvent(event)
		if err != nil {
			log.Printf("[DB] Error de inserción: %v", err)
		}
	}

	// 2. Pasar el evento por el Cerebro de Correlación
	correlator.ProcessEvent(event)

	// Responder al agente
	if event.EventType != "agent_heartbeat" {
		log.Printf("[API] Evento procesado: agent=%s type=%s domain=%s", event.AgentID, event.EventType, event.Destination.Domain)
	}

	w.WriteHeader(http.StatusAccepted) // HTTP 202
}

// handleDailyReport dispara la generación del reporte PDF bajo demanda
func handleDailyReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
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
