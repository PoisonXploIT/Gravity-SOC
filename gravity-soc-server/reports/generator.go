package reports

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gravity-soc-server/db"

	"github.com/jung-kurt/gofpdf"
)

// GenerateDailyReport extrae datos de la BD y crea un informe PDF en /reports/
func GenerateDailyReport() (string, error) {
	// 1. Obtener Estadísticas
	stats, err := db.GetDailyStats()
	if err != nil {
		log.Printf("[REPORTS] Error obteniendo estadísticas: %v", err)
		return "", err
	}

	correlations, err := db.GetDailyCorrelations()
	if err != nil {
		log.Printf("[REPORTS] Error obteniendo correlaciones: %v", err)
		return "", err
	}
	
	log.Printf("[DEBUG] Correlaciones encontradas por SQL JOIN: %d", len(correlations))

	// 2. Preparar Configuración
	hostname, _ := os.Hostname()
	dateStr := time.Now().Format("2006-01-02")
	
	// Crear carpeta si no existe
	reportsDir := "./reports"
	if err := os.MkdirAll(reportsDir, os.ModePerm); err != nil {
		return "", err
	}
	
	fileName := fmt.Sprintf("reporte_%s.pdf", time.Now().Format("20060102"))
	filePath := filepath.Join(reportsDir, fileName)

	// 3. Crear PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	
	// Título / Cabecera
	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(0, 10, "GRAVITY SOC - Informe Diario de Seguridad", "", 1, "C", false, 0, "")
	pdf.Ln(5)

	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(0, 8, fmt.Sprintf("Fecha: %s", dateStr), "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Hostname Servidor L2: %s", hostname), "", 1, "L", false, 0, "")
	pdf.Ln(10)

	// Manejo de Resiliencia: Si no hay eventos
	if stats.TotalEvents == 0 && len(correlations) == 0 {
		pdf.SetFont("Arial", "I", 14)
		pdf.SetTextColor(0, 128, 0) // Verde
		pdf.CellFormat(0, 20, "SIN AMENAZAS DETECTADAS - Todo despejado.", "", 1, "C", false, 0, "")
		
		err = pdf.OutputFileAndClose(filePath)
		if err != nil {
			return "", err
		}
		return filePath, nil
	}

	// Resumen de Estadisticas (A falta de grafica compleja de barras, dibujamos barras simples con celdas)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Resumen de Actividad")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(80, 8, "Eventos Totales Ingestados:", "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("%d", stats.TotalEvents), "", 1, "L", false, 0, "")

	pdf.CellFormat(80, 8, "Alertas Sensor de Red (Pi Zero L1):", "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("%d", stats.NetworkAlerts), "", 1, "L", false, 0, "")

	pdf.CellFormat(80, 8, "Alertas Criticas Host (Windows L1):", "", 0, "L", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("%d", stats.HostAlerts), "", 1, "L", false, 0, "")
	pdf.Ln(15)

	// Tabla de Amenazas
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Amenazas Confirmadas (Correlaciones)")
	pdf.Ln(10)

	if len(correlations) == 0 {
		pdf.SetFont("Arial", "I", 12)
		pdf.Cell(0, 10, "No se registraron correlaciones directas de impacto en esta jornada.")
		pdf.Ln(10)
	} else {
		// Encabezado de la tabla
		pdf.SetFont("Arial", "B", 12)
		pdf.SetFillColor(200, 200, 200)
		pdf.CellFormat(40, 10, "Hora", "1", 0, "C", true, 0, "")
		pdf.CellFormat(60, 10, "Dominio", "1", 0, "C", true, 0, "")
		pdf.CellFormat(40, 10, "Host Afectado", "1", 0, "C", true, 0, "")
		pdf.CellFormat(50, 10, "Tipo de Evento", "1", 1, "C", true, 0, "")

		// Filas
		pdf.SetFont("Arial", "", 10)
		for _, m := range correlations {
			pdf.CellFormat(40, 10, m.Timestamp, "1", 0, "C", false, 0, "")
			pdf.CellFormat(60, 10, m.Domain, "1", 0, "L", false, 0, "")
			pdf.CellFormat(40, 10, m.Host, "1", 0, "C", false, 0, "")
			pdf.CellFormat(50, 10, m.EventType, "1", 1, "C", false, 0, "")
		}
	}

	err = pdf.OutputFileAndClose(filePath)
	if err != nil {
		log.Printf("[REPORTS] Error guardando PDF: %v", err)
		return "", err
	}

	log.Printf("[REPORTS] Informe diario generado: %s", filePath)
	return filePath, nil
}
