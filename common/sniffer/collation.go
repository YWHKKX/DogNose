package sniffer

import "strings"

func isHTTP(payload string) bool {
	return strings.HasPrefix(payload, "GET ") ||
		strings.HasPrefix(payload, "POST ") ||
		strings.HasPrefix(payload, "HTTP/") ||
		strings.Contains(payload, "Host:") ||
		strings.Contains(payload, "Content-Type:")
}
