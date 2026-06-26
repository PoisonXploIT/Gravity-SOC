package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"gravity-soc-server/api"
	"gravity-soc-server/correlator"
	"gravity-soc-server/db"
)

func main() {
	log.Println("===============================================")
	log.Println("GRAVITY SOC SERVER (Cerebro L2)")
	log.Println("===============================================")

	// 1. Inicializar base de datos (WAL)
	dbPath := os.Getenv("GRAVITY_DB_PATH")
	if dbPath == "" {
		dbPath = "./gravity-soc.db"
	}
	db.InitDB(dbPath)

	// 2. Iniciar limpieza del cache de correlacion
	go correlator.CleanupCache()

	// 3. Watchdog de sensores (heartbeat)
	go correlator.StartWatchdog()

	// 4. Retencion nocturna de eventos
	go correlator.StartRetentionJob()

	// 5. Puerto configurable (default :8443)
	port := os.Getenv("GRAVITY_PORT")
	if port == "" {
		port = ":8443"
	}

	// 6. Levantar API
	go api.StartServer(port)

	// Mostrar configuracion
	apiKey := os.Getenv("GRAVITY_API_KEY")
	webhookURL := os.Getenv("GRAVITY_WEBHOOK_URL")
	log.Printf("[CONFIG] Puerto: %s", port)
	log.Printf("[CONFIG] API Key: %v", apiKey != "")
	log.Printf("[CONFIG] Webhook: %v", webhookURL != "")
	log.Printf("[CONFIG] Endpoints: /api/v1/events | /api/v1/stats | /api/v1/correlations | /api/v1/events/recent | /api/v1/health")

	// Mantener vivo hasta señal de apagado
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("\n[INFO] Apagando el Cerebro L2 ordenadamente...")
	db.DB.Close()
	log.Println("Base de datos sincronizada y cerrada.")
}