//go:build !windows
package collector

import (
	"context"
	"log"

	"gravity-soc-agent/models"
)

// StartSysmonCollector es una función inactiva para evitar fallos de compilación cruzada en Linux/ARM
func StartSysmonCollector(ctx context.Context, outChan chan<- models.Event) {
	log.Println("Sensor de Sysmon inactivado: El entorno de ejecución no es Windows.")
	<-ctx.Done()
}
