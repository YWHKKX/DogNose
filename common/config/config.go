package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port         string
	Device       string
	Filter       string
	SnapshotLen  int32
	Promiscuous  bool
	BufferSize   int
	SavePCAP     bool
}

func Load() Config {
	cfg := Config{
		Port:        envOr("DOGNOSE_PORT", "8080"),
		Device:      strings.TrimSpace(os.Getenv("DOGNOSE_DEVICE")),
		Filter:      envOr("DOGNOSE_FILTER", "tcp or udp"),
		SnapshotLen: int32(envInt("DOGNOSE_SNAPSHOT", 65535)),
		Promiscuous: envBool("DOGNOSE_PROMISCUOUS", false),
		BufferSize:  envInt("DOGNOSE_BUFFER", 2000),
		SavePCAP:    envBool("DOGNOSE_SAVE_PCAP", false),
	}

	port := flag.String("port", cfg.Port, "web server port")
	device := flag.String("device", cfg.Device, "network device name or description")
	filter := flag.String("filter", cfg.Filter, "BPF filter expression")
	snapshot := flag.Int("snapshot", int(cfg.SnapshotLen), "pcap snapshot length")
	promiscuous := flag.Bool("promiscuous", cfg.Promiscuous, "enable promiscuous mode")
	buffer := flag.Int("buffer", cfg.BufferSize, "in-memory packet ring buffer size")
	savePCAP := flag.Bool("save-pcap", cfg.SavePCAP, "save captured packets to saves/*.pcap")
	flag.Parse()

	cfg.Port = *port
	cfg.Device = strings.TrimSpace(*device)
	cfg.Filter = *filter
	cfg.SnapshotLen = int32(*snapshot)
	cfg.Promiscuous = *promiscuous
	cfg.BufferSize = *buffer
	cfg.SavePCAP = *savePCAP

	if cfg.BufferSize < 100 {
		cfg.BufferSize = 100
	}
	if cfg.SnapshotLen < 64 {
		cfg.SnapshotLen = 64
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
