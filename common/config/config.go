package config

import (
	"os"
	"strings"
)

type Config struct {
	Port   string
	Device string
	Filter string
}

func Load() Config {
	port := os.Getenv("DOGNOSE_PORT")
	if port == "" {
		port = "8080"
	}

	filter := os.Getenv("DOGNOSE_FILTER")
	if filter == "" {
		filter = "tcp"
	}

	return Config{
		Port:   port,
		Device: strings.TrimSpace(os.Getenv("DOGNOSE_DEVICE")),
		Filter: filter,
	}
}
