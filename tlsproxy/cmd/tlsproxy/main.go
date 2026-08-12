package main

import (
	"log"
	"os"

	"github.com/spacecomputer-io/orbitport/tlsproxy/internal/proxy"
)

func main() {
	config := proxy.Config{
		ListenAddr: envOrDefault("ORBITPORT_TLS_PROXY_LISTEN_ADDR", "127.0.0.1:8443"),
		TargetURL:  envOrDefault("ORBITPORT_TLS_PROXY_TARGET_URL", "http://127.0.0.1:8080"),
	}

	server, err := proxy.New(config)
	if err != nil {
		log.Fatalf("configure Orbitport TLS proxy: %v", err)
	}

	log.Printf("starting Orbitport TLS proxy on %s, forwarding to %s", config.ListenAddr, config.TargetURL)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("serve Orbitport TLS proxy: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
