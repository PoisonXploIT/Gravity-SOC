package db

import (
	"database/sql"
	"log"
	"strings"

	"gravity-soc-server/models"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDB inicializa la base de datos SQLite optimizada
func InitDB(filepath string) {
	// PRAGMAS críticos para SOC:
	// _pragma=journal_mode(WAL): Escrituras no bloquean lecturas.
	// _pragma=synchronous(NORMAL): Mucho más rápido, a riesgo ínfimo si se va la luz.
	var err error
	// modernc.org/sqlite usa _pragma para estas directivas
	DB, err = sql.Open("sqlite", filepath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		log.Fatalf("Error abriendo DB: %v", err)
	}

	// Forzar 1 conexión concurrente a la base de datos sqlite en escritura para evitar busys (WAL en Go + sqlite lo agradece)
	DB.SetMaxOpenConns(1)

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		agent_id TEXT,
		os TEXT,
		event_type TEXT,
		severity TEXT,
		source_ip TEXT,
		destination_ip TEXT,
		domain TEXT,
		process_name TEXT,
		process_guid TEXT,
		raw_message TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_domain ON events(domain);
	CREATE INDEX IF NOT EXISTS idx_time ON events(timestamp);
	`

	_, err = DB.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Error creando esquema DB: %v", err)
	}

	log.Println("[DB] SQLite (WAL) Inicializada.")
}

// InsertEvent guarda un evento individual
func InsertEvent(e models.Event) error {
	query := `INSERT INTO events (timestamp, agent_id, os, event_type, severity, source_ip, destination_ip, domain, process_name, process_guid, raw_message)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, e.Timestamp, e.AgentID, e.OS, e.EventType, e.Severity,
		e.Source.IP, e.Destination.IP, e.Destination.Domain, e.Process.Name, e.Process.ProcessGuid, e.RawMessage)
	return err
}

// StatsDaily representa las métricas diarias
type StatsDaily struct {
	TotalEvents   int
	NetworkAlerts int
	HostAlerts    int
}

// CorrelationMatch representa una amenaza consolidada en DB
type CorrelationMatch struct {
	Timestamp   string
	Domain      string
	Host        string
	EventType   string
}

// GetDailyStats obtiene las métricas globales de hoy
func GetDailyStats() (StatsDaily, error) {
	var stats StatsDaily
	
	// Usamos localtime para obtener los eventos del día actual según el reloj del servidor
	queryTotal := `SELECT COUNT(*) FROM events WHERE date(timestamp, 'localtime') = date('now', 'localtime')`
	err := DB.QueryRow(queryTotal).Scan(&stats.TotalEvents)
	if err != nil {
		return stats, err
	}

	queryNet := `SELECT COUNT(*) FROM events WHERE date(timestamp, 'localtime') = date('now', 'localtime') AND event_type = 'dns_alert'`
	err = DB.QueryRow(queryNet).Scan(&stats.NetworkAlerts)
	if err != nil {
		return stats, err
	}

	queryHost := `SELECT COUNT(*) FROM events WHERE date(timestamp, 'localtime') = date('now', 'localtime') AND os = 'windows' AND severity IN ('high', 'critical')`
	err = DB.QueryRow(queryHost).Scan(&stats.HostAlerts)
	
	return stats, err
}

// GetDailyCorrelations busca coincidencias donde un dns_alert y un network_dns ocurren en el mismo dominio
// el mismo día. En este sistema simplificado lo emularemos con una consulta a las alertas críticas de Windows
// o combinaciones directas de dominio de alta severidad para la tabla del reporte.
func GetDailyCorrelations() ([]CorrelationMatch, error) {
	var matches []CorrelationMatch
	
	// Buscamos eventos de red originados en Windows que hayan accedido a dominios que la Pi Zero marcó como dns_alert
	// Relajamos las fechas por ahora y verificamos simplemente que vengan de agentes distintos
	query := `
		SELECT COALESCE(e1.timestamp, ''), COALESCE(e1.domain, ''), COALESCE(e1.source_ip, '0.0.0.0'), COALESCE(e1.event_type, 'unknown')
		FROM events e1
		JOIN events e2 ON LOWER(e1.domain) = LOWER(e2.domain)
		WHERE e1.event_type = 'network_dns' 
		  AND e2.event_type = 'dns_alert'
		  AND e1.agent_id != e2.agent_id
		  -- AND date(e1.timestamp, 'localtime') = date('now', 'localtime')
		  -- AND date(e2.timestamp, 'localtime') = date('now', 'localtime')
		  AND ABS(strftime('%s', e1.timestamp) - strftime('%s', e2.timestamp)) <= 10
		ORDER BY e1.timestamp DESC
	`
	
	log.Printf("[DEBUG SQL] Executing Correlation Query:\n%s", query)
	
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var m CorrelationMatch
		err := rows.Scan(&m.Timestamp, &m.Domain, &m.Host, &m.EventType)
		if err != nil {
			log.Printf("[DEBUG SQL] Error escaneando fila de correlación: %v", err)
			continue
		}
		
		// Trim en el Scan
		m.Timestamp = strings.TrimSpace(m.Timestamp)
		m.Domain = strings.TrimSpace(m.Domain)
		m.Host = strings.TrimSpace(m.Host)
		m.EventType = strings.TrimSpace(m.EventType)
		
		matches = append(matches, m)
	}
	
	return matches, nil
}

