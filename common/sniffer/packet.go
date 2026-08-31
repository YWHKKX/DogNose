package sniffer

type PacketInfo struct {
	FrameID       int          `json:"frame_id"`
	CaptureTime   string       `json:"capture_time"`
	Interface     string       `json:"interface"`
	WireBytes     int          `json:"wire_bytes"`
	CapturedBytes int          `json:"captured_bytes"`
	Protocol      string       `json:"protocol"`
	Summary       string       `json:"summary,omitempty"`
	Ethernet      EthernetInfo `json:"ethernet"`
	ARP           ARPInfo      `json:"arp"`
	IPv6          IPv6Info     `json:"ipv6"`
	IPv4          IPv4Info     `json:"ipv4"`
	ICMP          ICMPInfo     `json:"icmp"`
	TCP           TCPInfo      `json:"tcp"`
	UDP           UDPInfo      `json:"udp"`
	DNS           DNSInfo      `json:"dns"`
	TLS           TLSInfo      `json:"tls"`
	HTTP          HTTPInfo     `json:"http"`
	RawData       []byte       `json:"raw_data,omitempty"`
}

type EthernetInfo struct {
	SrcMAC      string `json:"src_mac"`
	DstMAC      string `json:"dst_mac"`
	EtherType   string `json:"ether_type"`
	StreamIndex int    `json:"stream_index"`
}

type ARPInfo struct {
	Operation string `json:"operation,omitempty"`
	SenderMAC string `json:"sender_mac,omitempty"`
	SenderIP  string `json:"sender_ip,omitempty"`
	TargetMAC string `json:"target_mac,omitempty"`
	TargetIP  string `json:"target_ip,omitempty"`
}

type IPv6Info struct {
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	NextHeader string `json:"next_header,omitempty"`
	HopLimit   uint8  `json:"hop_limit,omitempty"`
}

type IPv4Info struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	TTL      uint8  `json:"ttl,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	ID       uint16 `json:"id,omitempty"`
	Flags    string `json:"flags,omitempty"`
}

type ICMPInfo struct {
	Version  int    `json:"version,omitempty"`
	TypeCode string `json:"type_code,omitempty"`
	Type     uint8  `json:"type,omitempty"`
	Code     uint8  `json:"code,omitempty"`
	Checksum uint16 `json:"checksum,omitempty"`
	ID       uint16 `json:"id,omitempty"`
	Seq      uint16 `json:"seq,omitempty"`
}

type UDPInfo struct {
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	DataLen int    `json:"data_len"`
}

type TCPInfo struct {
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Seq     uint32 `json:"seq"`
	Ack     uint32 `json:"ack"`
	DataLen int    `json:"data_len"`
	Flags   string `json:"flags,omitempty"`
	Window  uint16 `json:"window,omitempty"`
}

type DNSInfo struct {
	ID        uint16   `json:"id,omitempty"`
	QR        bool     `json:"qr"`
	Opcode    string   `json:"opcode,omitempty"`
	Questions []string `json:"questions,omitempty"`
	Answers   []string `json:"answers,omitempty"`
}

type TLSInfo struct {
	ContentType string `json:"content_type,omitempty"`
	Version     string `json:"version,omitempty"`
	Handshake   string `json:"handshake,omitempty"`
	SNI         string `json:"sni,omitempty"`
}

type HTTPInfo struct {
	Method     string            `json:"method"`
	URI        string            `json:"uri"`
	Version    string            `json:"version,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	StatusText string            `json:"status_text,omitempty"`
	Headers    map[string]string `json:"headers"`
	ContentLen int               `json:"content_len"`
	ResponseIn int               `json:"response_in"`
	IsResponse bool              `json:"is_response"`
}

type CaptureStats struct {
	Running         bool              `json:"running"`
	Paused          bool              `json:"paused"`
	Device          string            `json:"device"`
	Filter          string            `json:"filter"`
	TotalPackets    uint64            `json:"total_packets"`
	BufferedCount   int               `json:"buffered_count"`
	BufferCapacity  int               `json:"buffer_capacity"`
	Clients         int               `json:"clients"`
	BytesCaptured   uint64            `json:"bytes_captured"`
	DroppedBatches  uint64            `json:"dropped_batches"`
	PacketsPerSec   float64           `json:"packets_per_sec"`
	StartedAt       string            `json:"started_at,omitempty"`
	SavingPCAP      bool              `json:"saving_pcap"`
	ProtocolCounts  map[string]uint64 `json:"protocol_counts"`
	TopTalkers      []TalkerStat      `json:"top_talkers"`
}

type TalkerStat struct {
	IP      string `json:"ip"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
