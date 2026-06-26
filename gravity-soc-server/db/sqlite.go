package db

import (
	"database/sql"
	"log"
	"strings"
	"time"

	"gravity-soc-server/models"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDB inicializa la base de datos SQLite optimizada
func InitDB(filepath string) {
	var err error
	DB, err = sql.Open("sqlite", filepath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		log.Fatalf("Error abriendo DB: %v", err)
	}

	// WAL permite multiples lectores concurrentes con un solo escritor
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
	CREATE INDEX IF NOT EXISTS idx_agent ON events(agent_id);

	CREATE TABLE IF NOT EXISTS correlations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME,
		domain TEXT,
		endpoint_host TEXT,
		endpoint_ip TEXT,
		process_name TEXT,
		process_guid TEXT,
		agent_id TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_corr_domain ON correlations(domain);
	CREATE INDEX IF NOT EXISTS idx_corr_time ON correlations(timestamp);
	`

	_, err = DB.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Error creando esquema DB: %v", err)
	}

	log.Println("[DB] SQLite (WAL) inicializada. Tablas: events, correlations")
}

// InsertEvent guarda un evento individual
func InsertEvent(e models.Event) error {
	query := `INSERT INTO events (timestamp, agent_id, os, event_type, severity, source_ip, destination_ip, domain, process_name, process_guid, raw_message)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	ts := e.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	_, err := DB.Exec(query, ts, e.AgentID, e.OS, e.EventType, e.Severity,
		e.Source.IP, e.Destination.IP, e.Destination.Domain, e.Process.Name, e.Process.ProcessGuid, e.RawMessage)
	return err
}

// CorrelationRecord representa una correlacion confirmada para persistir
type CorrelationRecord struct {
	Timestamp    time.Time
	Domain       string
	EndpointHost string
	EndpointIP   string
	ProcessName  string
	ProcessGUID  string
	AgentID      string
}

// InsertCorrelation guarda una correlacion confirmada en SQLite
func InsertCorrelation(c CorrelationRecord) error {
	query := `INSERT INTO correlations (timestamp, domain, endpoint_host, endpoint_ip, process_name, process_guid, agent_id)
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	ts := c.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	_, err := DB.Exec(query, ts, c.Domain, c.EndpointHost, c.EndpointIP, c.ProcessName, c.ProcessGUID, c.AgentID)
	return err
}

// StatsDaily representa las metricas diarias
type StatsDaily struct {
	TotalEvents     int `json:"total_events"`
	NetworkAlerts   int `json:"network_alerts"`
	HostAlerts      int `json:"host_alerts"`
	Correlations    int `json:"correlations"`
}

// CorrelationMatch representa una amenaza consolidada para el reporte
type CorrelationMatch struct {
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	Host      string `json:"host"`
	EventType string `json:"event_type"`
}

// RecentEvent representa un evento reciente para la API
type RecentEvent struct {
	ID          int    `json:"id"`
	Timestamp   string `json:"timestamp"`
	AgentID     string `json:"agent_id"`
	OSType      string `json:"os"`
	EventType   string `json:"event_type"`
	Severity    string `json:"severity"`
	SourceIP    string `json:"source_ip"`
	Domain      string `json:"domain"`
	ProcessName string `json:"process_name"`
}

// GetDailyStats obtiene las metricas globales de hoy
func GetDailyStats() (StatsDaily, error) {
	var stats StatsDaily

	queryTotal := `SELECT COUNT(*) FROM events WHERE date(timestamp) = date('now')`
	err := DB.QueryRow(queryTotal).Scan(&stats.TotalEvents)
	if err != nil {
		return stats, err
	}

	queryNet := `SELECT COUNT(*) FROM events WHERE date(timestamp) = date('now') AND event_type = 'dns_alert'`
	err = DB.QueryRow(queryNet).Scan(&stats.NetworkAlerts)
	if err != nil {
		return stats, err
	}

	queryHost := `SELECT COUNT(*) FROM events WHERE date(timestamp) = date('now') AND os = 'windows' AND severity IN ('high', 'critical')`
	err = DB.QueryRow(queryHost).Scan(&stats.HostAlerts)
	if err != nil {
		return stats, err
	}

	queryCorr := `SELECT COUNT(*) FROM correlations WHERE date(timestamp) = date('now')`
	err = DB.QueryRow(queryCorr).Scan(&stats.Correlations)

	return stats, err
}

// GetDailyCorrelations busca correlaciones confirmadas del dia
func GetDailyCorrelations() ([]CorrelationMatch, error) {
	var matches []CorrelationMatch

	// Primero intentar la tabla correlations (mas precisa)
	queryCorrTable := `
		SELECT COALESCE(timestamp, ''), COALESCE(domain, ''), COALESCE(endpoint_host, '0.0.0.0'), 'consolidated_alert'
		FROM correlations
		WHERE date(timestamp) = date('now')
		ORDER BY timestamp DESC
		LIMIT 500
	`
	rows, err := DB.Query(queryCorrTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var m CorrelationMatch
		err := rows.Scan(&m.Timestamp, &m.Domain, &m.Host, &m.EventType)
		if err != nil {
			continue
		}
		m.Timestamp = strings.TrimSpace(m.Timestamp)
		m.Domain = strings.TrimSpace(m.Domain)
		m.Host = strings.TrimSpace(m.Host)
		m.EventType = strings.TrimSpace(m.EventType)
		matches = append(matches, m)
	}
	rows.Close()

	// Si la tabla correlations tiene datos, usar esos
	if len(matches) > 0 {
		return matches, nil
	}

	// Fallback: query SQL con JOIN (metodo original, con date filter + LIMIT corregidos)
	query := `
		SELECT COALESCE(e1.timestamp, ''), COALESCE(e1.domain, ''), COALESCE(e1.source_ip, '0.0.0.0'), COALESCE(e1.event_type, 'unknown')
		FROM events e1
		JOIN events e2 ON LOWER(e1.domain) = LOWER(e2.domain)
		WHERE e1.event_type = 'network_dns'
		  AND e2.event_type = 'dns_alert'
		  AND e1.agent_id != e2.agent_id
		  AND date(e1.timestamp) = date('now')
		  AND date(e2.timestamp) = date('now')
		  AND ABS(strftime('%s', e1.timestamp) - strftime('%s', e2.timestamp)) <= 10
		ORDER BY e1.timestamp DESC
		LIMIT 500
	`

	rows, err = DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var m CorrelationMatch
		err := rows.Scan(&m.Timestamp, &m.Domain, &m.Host, &m.EventType)
		if err != nil {
			continue
		}
		m.Timestamp = strings.TrimSpace(m.Timestamp)
		m.Domain = strings.TrimSpace(m.Domain)
		m.Host = strings.TrimSpace(m.Host)
		m.EventType = strings.TrimSpace(m.EventType)
		matches = append(matches, m)
	}

	return matches, nil
}

// GetRecentEvents devuelve los ultimos N eventos para la API
func GetRecentEvents(limit int) ([]RecentEvent, error) {
	var events []RecentEvent

	query := `
		SELECT id, timestamp, agent_id, os, event_type, severity, source_ip, domain, process_name
		FROM events
		ORDER BY id DESC
		LIMIT ?
	`
	rows, err := DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var e RecentEvent
		err := rows.Scan(&e.ID, &e.Timestamp, &e.AgentID, &e.OSType, &e.EventType, &e.Severity, &e.SourceIP, &e.Domain, &e.ProcessName)
		if err != nil {
			continue
		}
		e.Timestamp = strings.TrimSpace(e.Timestamp)
		events = append(events, e)
	}

	return events, nil
}

// PurgeOldEvents elimina eventos mas antiguos que el numero de dias especificado
func PurgeOldEvents(days int) (int64, error) {
	result, err := DB.Exec(`DELETE FROM events WHERE timestamp < datetime('now', ?)`, "-"+itoa(days)+" days")
	if err != nil {
		return 0, err
	}
	deleted, _ := result.RowsAffected()
	return deleted, nil
}

// itoa convierte int a string sin importar strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}