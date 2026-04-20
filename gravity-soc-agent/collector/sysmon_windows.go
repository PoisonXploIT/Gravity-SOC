//go:build windows
package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"gravity-soc-agent/models"
)

// SysmonEvent simplifica la estructura XML devuelta por el Event Log (Eventvwr)
type SysmonEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID       int `xml:"EventID"`
		EventRecordID int `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime time.Time `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// StartSysmonCollector se suscribe a "Microsoft-Windows-Sysmon/Operational"
// usando la API de Eventos de Windows (wevtapi.dll - EvtSubscribe)
func StartSysmonCollector(ctx context.Context, outChan chan<- models.Event) {
	log.Println("Sensor L1 (Windows) iniciando suscripción ETW/EventLog a Sysmon")

	// NOTA DE ARQUITECTURA: 
	// Usamos wevtutil (polling cada 3s) en lugar de EvtSubscribe (CGO nativo)
	// para mantener compilación cruzada sin dependencias C.

	go startRealSysmonCollector(ctx, outChan)
}

// parseSysmonEvent procesa el struct XML pre-parseado al ECS unificado
func parseSysmonEvent(se SysmonEvent, outChan chan<- models.Event, hostname string) {
	// Extraer dinámicamente el EventData
	dataMap := make(map[string]string)
	for _, d := range se.EventData.Data {
		dataMap[d.Name] = d.Value
	}

	eventID := se.System.EventID
	
	// Mapeo Base ECS
	event := models.Event{
		Timestamp: se.System.TimeCreated.SystemTime,
		AgentID:   "sensor-win-" + hostname,
		OS:        "windows",
		Severity:  "info",
		Source:    models.Source{Hostname: hostname},
		Payload: models.Payload{
			SysmonEventID: &eventID,
		},
	}

	// Enriquecimiento condicional según el Event ID
	switch eventID {
	case 1: // Process Creation
		event.EventType = "process_creation"
		event.Process = models.Process{
			Name:        dataMap["Image"],
			CommandLine: dataMap["CommandLine"],
			HashSHA256:  dataMap["Hashes"],
			ProcessGuid: dataMap["ProcessGuid"], // VITAL para linaje
			ParentImage: dataMap["ParentImage"],
		}
	case 3: // Network Connection
		event.EventType = "network_connection"
		event.Process = models.Process{
			Name:        dataMap["Image"],
			ProcessGuid: dataMap["ProcessGuid"],
		}
		event.Source.IP = dataMap["SourceIp"]
		event.Destination.IP = dataMap["DestinationIp"]
		if host, ok := dataMap["DestinationHostname"]; ok && host != "" {
			event.Destination.Domain = strings.ToLower(strings.TrimSuffix(host, "."))
		} else {
			event.Destination.Domain = dataMap["DestinationIp"] // IPs no necesitan normalización
		}
	case 8: // Create Remote Thread
		event.EventType = "create_remote_thread"
		event.Severity = "high" // PoisonXploIT suele inyectar memoria
		event.Process = models.Process{
			Name:        dataMap["SourceImage"],
			ProcessGuid: dataMap["SourceProcessGuid"],
		}
	case 11: // File Create
		event.EventType = "file_creation"
		event.Process = models.Process{
			Name:        dataMap["Image"],
			ProcessGuid: dataMap["ProcessGuid"],
		}
	case 12, 13: // Registry Event
		event.EventType = "registry_event"
		event.Process = models.Process{
			Name:        dataMap["Image"],
			ProcessGuid: dataMap["ProcessGuid"],
		}
	case 22: // DNS Query
		event.EventType = "network_dns"
		event.Process = models.Process{
			Name:        dataMap["Image"],
			ProcessGuid: dataMap["ProcessGuid"],
		}
		rawDomain := strings.ToLower(dataMap["QueryName"])
		rawDomain = strings.TrimSuffix(rawDomain, ".")
		event.Destination.Domain = rawDomain
		event.Severity = "medium" // Las queries de sysmon suelen ser de endpoints, lo vigilamos
	}

	// Enviamos al Canal en Memoria (no bloqueante)
	select {
	case outChan <- event:
	default:
		log.Printf("[WARNING] Canal interno lleno. Descartando evento Sysmon (%d).", eventID)
	}
}

func toUTF8(b []byte) []byte {
	// Verificar BOM
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
		u16s := make([]uint16, len(b)/2)
		for i := 0; i < len(b)-1; i += 2 {
			u16s[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
		}
		return []byte(string(utf16.Decode(u16s)))
	}
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		b = b[2:]
		u16s := make([]uint16, len(b)/2)
		for i := 0; i < len(b)-1; i += 2 {
			u16s[i/2] = binary.BigEndian.Uint16(b[i : i+2])
		}
		return []byte(string(utf16.Decode(u16s)))
	}

	// Conversión Forzada: Si detectamos múltiples bytes nulos intercalados,
	// asumimos que es UTF-16LE sin BOM (típico de wevtutil).
	nullCount := 0
	for _, v := range b {
		if v == 0x00 {
			nullCount++
		}
	}
	
	// Si más del 10% de los bytes son nulos, asumimos UTF-16LE
	if len(b) > 0 && float64(nullCount)/float64(len(b)) > 0.10 {
		u16s := make([]uint16, len(b)/2)
		for i := 0; i < len(b)-1; i += 2 {
			u16s[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
		}
		return []byte(string(utf16.Decode(u16s)))
	}

	return b // De base suponemos UTF-8
}

// strictASCIIXML aplica un filtro radical de lista blanca
// Sólo permite: Tab (0x09), LF (0x0A), CR (0x0D), y el rango imprimible ASCII (0x20 a 0x7E)
func strictASCIIXML(b []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(b))
	for _, c := range b {
		if c == 0x09 || c == 0x0A || c == 0x0D || (c >= 0x20 && c <= 0x7E) {
			buf.WriteByte(c)
		}
	}
	return buf.Bytes()
}

func startRealSysmonCollector(ctx context.Context, outChan chan<- models.Event) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastRecordID int
	checkpointFile := ".gravity-checkpoint"

	// Cargar último RecordID si existe
	if b, err := os.ReadFile(checkpointFile); err == nil {
		var id int32
		if len(b) >= 4 {
			id = int32(binary.LittleEndian.Uint32(b))
			lastRecordID = int(id)
			log.Printf("Checkpoint de Sysmon cargado: RecordID = %d", lastRecordID)
		}
	}

	// Cache de hostname
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-win-host"
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Usar wevtutil para capturar eventos de Sysmon recientes sin CGO
			// Se filtran desde el origen en Windows para reducir overhead
			query := `*[System[(EventID=1 or EventID=3 or EventID=8 or EventID=11 or EventID=12 or EventID=13 or EventID=22)]]`
			
			// /c:50 limita al bloque de los últimos 50 eventos (sobrado con nuestras exclusiones)
			// /rd:true = reverse direction (más recientes primero)
			cmd := exec.Command("wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", "/f:xml", "/c:50", "/rd:true", "/q:"+query)
			
			// Hacemos bypass al output del O.S. (viene sin tag Root y sin salto de línea general)
			out, err := cmd.Output()
			if err != nil || len(out) == 0 {
				continue
			}

			// 1. Forzar UTF-8 (conversión desde UTF-16 si es necesario)
			utf8Data := toUTF8(out)

			// 2. Filtro de Seguridad Blanco (ASCII Puro)
			cleanedData := strictASCIIXML(utf8Data)

			// 3. Header Scrubber: Buscar <Event
			// A veces hay basura antes del primer <Event
			firstEventIdx := bytes.Index(cleanedData, []byte("<Event "))
			if firstEventIdx != -1 {
				cleanedData = cleanedData[firstEventIdx:]
			}

			// 4. Resiliencia: procesar evento por evento
			// Separar eventos por la etiqueta <Event
			eventsRaw := bytes.Split(cleanedData, []byte("<Event "))

			// Iterar de lo antiguo a lo nuevo (reverse de wevtutil)
			for i := len(eventsRaw) - 1; i >= 0; i-- {
				block := eventsRaw[i]
				if len(bytes.TrimSpace(block)) == 0 {
					continue
				}

				// Header Scrubber previene inyecciones forzando un array seguro
				singleXML := make([]byte, 0, 7+len(block))
				singleXML = append(singleXML, []byte("<Event ")...)
				singleXML = append(singleXML, block...)

				var se SysmonEvent
				if err := xml.Unmarshal(singleXML, &se); err != nil {
					log.Printf("[WARNING] Ignorando evento fallido por sintaxis XML: %v", err)
					
					// Debug de Emergencia: Imprimir hex de los primeros bytes
					debugLen := 10
					if len(singleXML) < 10 {
						debugLen = len(singleXML)
					}
					log.Printf("[DEBUG] Hex de los primeros 10 bytes: %x", singleXML[:debugLen])
					continue
				}

				if se.System.EventRecordID > lastRecordID {
					// Guardar marcador de progreso y emitir al pipeline principal
					lastRecordID = se.System.EventRecordID
					
					// Escribir a checkpoint file de manera ofuscada/ligera
					buf := make([]byte, 4)
					binary.LittleEndian.PutUint32(buf, uint32(lastRecordID))
					_ = os.WriteFile(checkpointFile, buf, 0644)
					
					parseSysmonEvent(se, outChan, hostname)
				}
			}
		}
	}
}
