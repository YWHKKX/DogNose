package sniffer

import "strings"

func isHTTP(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	s := string(payload)
	return strings.HasPrefix(s, "GET ") ||
		strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") ||
		strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "HEAD ") ||
		strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "PATCH ") ||
		strings.HasPrefix(s, "HTTP/") ||
		strings.Contains(s, "Host:") ||
		strings.Contains(s, "Content-Type:")
}
