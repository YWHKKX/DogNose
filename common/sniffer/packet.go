package sniffer

type PacketInfo struct {
	FrameID       int          `json:"frame_id"`
	CaptureTime   string       `json:"capture_time"`
	Interface     string       `json:"interface"`
	WireBytes     int          `json:"wire_bytes"`
	CapturedBytes int          `json:"captured_bytes"`
	Protocol      string       `json:"protocol"`
	Ethernet      EthernetInfo `json:"ethernet"`
	IPv6          IPv6Info     `json:"ipv6"`
	IPv4          IPv4Info     `json:"ipv4"`
	TCP           TCPInfo      `json:"tcp"`
	UDP           UDPInfo      `json:"udp"`
	HTTP          HTTPInfo     `json:"http"`
	RawData       []byte       `json:"raw_data"`
}

type EthernetInfo struct {
	SrcMAC      string `json:"src_mac"`
	DstMAC      string `json:"dst_mac"`
	EtherType   string `json:"ether_type"`
	StreamIndex int    `json:"stream_index"`
}

type IPv6Info struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
}

type IPv4Info struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
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
}

type HTTPInfo struct {
	Method     string            `json:"method"`
	URI        string            `json:"uri"`
	Headers    map[string]string `json:"headers"`
	ContentLen int               `json:"content_len"`
	ResponseIn int               `json:"response_in"`
}
