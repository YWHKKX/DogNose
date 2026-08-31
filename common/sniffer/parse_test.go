package sniffer

import "testing"

func TestIsHTTP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"GET / HTTP/1.1\r\n", true},
		{"POST /api HTTP/1.1\r\n", true},
		{"HTTP/1.1 200 OK\r\n", true},
		{"CONNECT example.com:443 HTTP/1.1\r\n", true},
		{"not http", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isHTTP([]byte(c.in)); got != c.want {
			t.Fatalf("isHTTP(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestLooksLikeTLS(t *testing.T) {
	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01}
	if !looksLikeTLS(tlsHello) {
		t.Fatal("expected TLS ClientHello-looking record")
	}
	if looksLikeTLS([]byte("GET /")) {
		t.Fatal("HTTP should not look like TLS")
	}
}

func TestParseHTTPRequestAndResponse(t *testing.T) {
	req := parseHTTP([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"))
	if req.Method != "GET" || req.URI != "/index.html" || req.IsResponse {
		t.Fatalf("unexpected request parse: %+v", req)
	}
	if req.Headers["Host"] != "example.com" || req.ContentLen != 3 {
		t.Fatalf("unexpected headers: %+v", req)
	}

	resp := parseHTTP([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	if !resp.IsResponse || resp.StatusCode != 404 || resp.StatusText != "Not Found" {
		t.Fatalf("unexpected response parse: %+v", resp)
	}
}

func TestTCPFlagsJoin(t *testing.T) {
	// smoke: ensure empty input path of joinFilters
	if got := joinFilters(nil); got != "" {
		t.Fatalf("joinFilters(nil)=%q", got)
	}
	if got := joinFilters([]string{"tcp", "udp"}); got != "(tcp) and (udp)" {
		t.Fatalf("joinFilters got %q", got)
	}
}

func TestFormatAddrs(t *testing.T) {
	if got := formatHWAddr([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("formatHWAddr=%q", got)
	}
	if got := formatIPv4Bytes([]byte{192, 168, 1, 1}); got != "192.168.1.1" {
		t.Fatalf("formatIPv4Bytes=%q", got)
	}
	if formatHWAddr([]byte{1, 2}) != "" || formatIPv4Bytes([]byte{1}) != "" {
		t.Fatal("short slices should return empty")
	}
}

func TestEndpointSummary(t *testing.T) {
	info := &PacketInfo{
		Protocol: "TCP",
		IPv4:     IPv4Info{SrcIP: "1.1.1.1", DstIP: "8.8.8.8"},
		TCP:      TCPInfo{SrcPort: 1234, DstPort: 443},
	}
	got := endpointSummary(info)
	if got != "1.1.1.1:1234 → 8.8.8.8:443" {
		t.Fatalf("endpointSummary=%q", got)
	}
}
