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
	log.Println("⚡ GRAVITY SOC SERVER ⚡ (Cerebro L2 - Pi 5)")
	log.Println("===============================================")

	// 1. Inicializar la base de datos persistente optimizada (WAL)
	db.InitDB("./gravity-soc.db")

	// 2. Iniciar el basurero del caché de correlación
	go correlator.CleanupCache()

	// 2.b Iniciar el perro guardián de sensores (Heartbeat Watchdog)
	go correlator.StartWatchdog()

	// 3. Levantar Endpoint de Ingesta (API)
	// Escuchamos en *:8443 (usaremos HTTP por ahora localmente, en prod HTTPS)
	go api.StartServer(":8443")

	// Mantener vivo hasta recibir señal de apagado
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("\n[INFO] Apagando el Cerebro L2 ordenadamente...")
	db.DB.Close()
	log.Println("Base de datos sincronizada y cerrada.")
}
