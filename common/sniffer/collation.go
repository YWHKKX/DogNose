package sniffer

import "strings"

func isHTTP(payload []byte) bool {
	if len(payload) < 4 {
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
		strings.HasPrefix(s, "CONNECT ") ||
		strings.HasPrefix(s, "HTTP/")
}
