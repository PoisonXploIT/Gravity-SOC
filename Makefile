.PHONY: all agent-server agent-windows agent-linux server clean

GO ?= go

all: server agent-windows agent-linux

# Gravity SOC Server (L2) - compilar para la maquina actual
server:
	cd gravity-soc-server && $(GO) mod tidy && $(GO) build -o gravity-server .

# Agent para Windows (endpoint L1)
agent-windows:
	cd gravity-soc-agent && $(GO) mod tidy && $(GO) build -o gravity-agent.exe .

# Agent para Linux ARM (Raspberry Pi Zero 2 W)
agent-linux:
	cd gravity-soc-agent && $(GO) mod tidy && \
	GOOS=linux GOARCH=arm $(GO) build -o gravity-agent-linux .

# Agent para Linux ARM64 (Raspberry Pi 5)
agent-linux-arm64:
	cd gravity-soc-agent && $(GO) mod tidy && \
	GOOS=linux GOARCH=arm64 $(GO) build -o gravity-agent-arm64 .

# Compilar todo para Windows (servidor + agente)
agent-server: server agent-windows

# Limpiar binarios
clean:
	rm -f gravity-soc-server/gravity-server
	rm -f gravity-soc-server/gravity-server.exe
	rm -f gravity-soc-agent/gravity-agent
	rm -f gravity-soc-agent/gravity-agent.exe
	rm -f gravity-soc-agent/gravity-agent-linux
	rm -f gravity-soc-agent/gravity-agent-arm64