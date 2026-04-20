package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"gravity-soc-agent/models"
)

// StartHTTPSender lee eventos del canal de RAM y los envía a la base L2
func StartHTTPSender(ctx context.Context, serverURL string, inChan <-chan models.Event) {
	// Cliente HTTP optimizado para reutilizar conexiones (Keep-Alive)
	client := &http.Client{
		Timeout: 5 * time.Second,
		// Transport: AQUÍ SE CONFIGURA EL mTLS más adelante (tls.Config)
	}

	log.Printf("Sender HTTP activo hacia: %s", serverURL)

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-inChan:
			payloadBytes, err := json.Marshal(event)
			if err != nil {
				log.Printf("Error serializando JSON de evento: %v", err)
				continue
			}

			// Bucle de reintento local con Backoff Exponencial
			backoff := 1 * time.Second
			maxBackoff := 60 * time.Second

			for {
				// Recrear buffer en cada intento (el anterior fue consumido por client.Do)
				req, err := http.NewRequestWithContext(ctx, "POST", serverURL, bytes.NewBuffer(payloadBytes))
				if err != nil {
					break // Error irrecuperable de creación de petición, descartar
				}
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if err != nil {
					log.Printf("[WARNING] Fallo de conexión a L2 (%v). Reintentando en %v...", err, backoff)
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
						// Exponencial
						backoff *= 2
						if backoff > maxBackoff {
							backoff = maxBackoff
						}
						continue
					}
				}

				statusCode := resp.StatusCode
				
				// Drenar el body completamente para asegurar reutilización de conexión
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if statusCode >= 200 && statusCode <= 299 {
					log.Printf("[+] Evento enviado a L2: type=%s | Status: %d", event.EventType, statusCode)
					break // Salir del bucle de reintento, éxito
				} else if statusCode >= 400 && statusCode <= 499 {
					log.Printf("[WARNING] L2 rechazó permanentemente (Status: %d). EVENTO DESCARTADO.", statusCode)
					break // Descartar evento
				} else {
					// 5xx u otros temporales: forzar backoff
					log.Printf("[WARNING] L2 respondió con error temporal: %d. Reintentando en %v...", statusCode, backoff)
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
						backoff *= 2
						if backoff > maxBackoff {
							backoff = maxBackoff
						}
						continue
					}
				}
			}
		}
	}
}
