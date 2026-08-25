package sniffer

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parsePacket(packet gopacket.Packet, frameID int, iface string) *PacketInfo {
	metadata := packet.Metadata()
	info := &PacketInfo{
		FrameID:       frameID,
		CaptureTime:   metadata.Timestamp.Format("2006-01-02 15:04:05.000000"),
		Interface:     iface,
		WireBytes:     metadata.Length,
		Protocol:      "Unknown",
		CapturedBytes: metadata.CaptureLength,
		HTTP:          HTTPInfo{Headers: make(map[string]string)},
	}

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		info.Ethernet = EthernetInfo{
			SrcMAC:    eth.SrcMAC.String(),
			DstMAC:    eth.DstMAC.String(),
			EtherType: eth.EthernetType.String(),
		}
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		info.IPv6 = IPv6Info{
			SrcIP: ipv6.SrcIP.String(),
			DstIP: ipv6.DstIP.String(),
		}
		info.Protocol = "IPv6"
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		info.IPv4 = IPv4Info{
			SrcIP:    ipv4.SrcIP.String(),
			DstIP:    ipv4.DstIP.String(),
			TTL:      ipv4.TTL,
			Protocol: ipv4.Protocol.String(),
		}
		info.Protocol = "IPv4"
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		info.UDP = UDPInfo{
			SrcPort: uint16(udp.SrcPort),
			DstPort: uint16(udp.DstPort),
			DataLen: len(udp.Payload),
		}
		info.Protocol = "UDP"
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		info.TCP = TCPInfo{
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Seq:     tcp.Seq,
			Ack:     tcp.Ack,
			DataLen: len(tcp.Payload),
			Flags:   tcpFlags(tcp),
			Window:  tcp.Window,
		}
		info.Protocol = "TCP"
	}

	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		info.DNS = parseDNS(dns)
		info.Protocol = "DNS"
		return info
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) == 0 {
			return info
		}

		if looksLikeTLS(payload) {
			info.TLS = parseTLS(payload)
			info.Protocol = "TLS"
			info.RawData = payload
			return info
		}

		if isHTTP(payload) {
			info.HTTP = parseHTTP(payload)
			info.Protocol = "HTTP"
			info.RawData = payload
		}
	}

	return info
}

func tcpFlags(tcp *layers.TCP) string {
	flags := make([]string, 0, 8)
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	return strings.Join(flags, ",")
}

func parseDNS(dns *layers.DNS) DNSInfo {
	info := DNSInfo{
		ID:     dns.ID,
		QR:     dns.QR,
		Opcode: dns.OpCode.String(),
	}
	for _, q := range dns.Questions {
		info.Questions = append(info.Questions, string(q.Name)+" "+q.Type.String())
	}
	for _, a := range dns.Answers {
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if a.IP != nil {
				info.Answers = append(info.Answers, fmt.Sprintf("%s %s %s", string(a.Name), a.Type.String(), a.IP.String()))
			}
		case layers.DNSTypeCNAME:
			info.Answers = append(info.Answers, fmt.Sprintf("%s CNAME %s", string(a.Name), string(a.CNAME)))
		default:
			info.Answers = append(info.Answers, fmt.Sprintf("%s %s", string(a.Name), a.Type.String()))
		}
	}
	return info
}

func looksLikeTLS(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	// TLS record: ContentType(1) + Version(2) + Length(2)
	ct := payload[0]
	major, minor := payload[1], payload[2]
	if ct < 20 || ct > 23 {
		return false
	}
	if major != 0x03 {
		return false
	}
	if minor > 0x04 {
		return false
	}
	return true
}

func parseTLS(payload []byte) TLSInfo {
	info := TLSInfo{}
	if len(payload) < 5 {
		return info
	}

	switch payload[0] {
	case 20:
		info.ContentType = "ChangeCipherSpec"
	case 21:
		info.ContentType = "Alert"
	case 22:
		info.ContentType = "Handshake"
	case 23:
		info.ContentType = "ApplicationData"
	default:
		info.ContentType = fmt.Sprintf("Unknown(%d)", payload[0])
	}

	info.Version = tlsVersion(payload[1], payload[2])

	if payload[0] == 22 && len(payload) > 5 {
		hs := payload[5]
		info.Handshake = tlsHandshakeType(hs)
		if hs == 1 { // ClientHello
			info.SNI = extractSNI(payload[5:])
		}
	}
	return info
}

func tlsVersion(major, minor byte) string {
	switch {
	case major == 0x03 && minor == 0x00:
		return "SSL 3.0"
	case major == 0x03 && minor == 0x01:
		return "TLS 1.0"
	case major == 0x03 && minor == 0x02:
		return "TLS 1.1"
	case major == 0x03 && minor == 0x03:
		return "TLS 1.2"
	case major == 0x03 && minor == 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("%d.%d", major, minor)
	}
}

func tlsHandshakeType(t byte) string {
	switch t {
	case 1:
		return "ClientHello"
	case 2:
		return "ServerHello"
	case 11:
		return "Certificate"
	case 12:
		return "ServerKeyExchange"
	case 14:
		return "ServerHelloDone"
	case 16:
		return "ClientKeyExchange"
	default:
		return fmt.Sprintf("Type(%d)", t)
	}
}

// extractSNI walks ClientHello extensions looking for server_name (0x0000).
func extractSNI(handshake []byte) string {
	// handshake: type(1) + length(3) + ClientHello body
	if len(handshake) < 43 {
		return ""
	}
	offset := 4 // skip handshake header
	if offset+2 > len(handshake) {
		return ""
	}
	offset += 2 // client version
	offset += 32 // random
	if offset >= len(handshake) {
		return ""
	}
	sessionLen := int(handshake[offset])
	offset++
	offset += sessionLen
	if offset+2 > len(handshake) {
		return ""
	}
	cipherLen := int(handshake[offset])<<8 | int(handshake[offset+1])
	offset += 2 + cipherLen
	if offset >= len(handshake) {
		return ""
	}
	compLen := int(handshake[offset])
	offset++
	offset += compLen
	if offset+2 > len(handshake) {
		return ""
	}
	extLen := int(handshake[offset])<<8 | int(handshake[offset+1])
	offset += 2
	end := offset + extLen
	if end > len(handshake) {
		end = len(handshake)
	}
	for offset+4 <= end {
		extType := int(handshake[offset])<<8 | int(handshake[offset+1])
		l := int(handshake[offset+2])<<8 | int(handshake[offset+3])
		offset += 4
		if offset+l > end {
			break
		}
		if extType == 0 && l >= 5 {
			// server_name list
			data := handshake[offset : offset+l]
			if len(data) < 5 {
				break
			}
			// list length(2) + name type(1) + name length(2) + name
			nameLen := int(data[3])<<8 | int(data[4])
			if 5+nameLen <= len(data) && data[2] == 0 {
				return string(data[5 : 5+nameLen])
			}
		}
		offset += l
	}
	return ""
}

func parseHTTP(payload []byte) HTTPInfo {
	httpInfo := HTTPInfo{Headers: make(map[string]string)}
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return httpInfo
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if strings.HasPrefix(lines[0], "HTTP/") {
		httpInfo.IsResponse = true
		if len(parts) >= 2 {
			httpInfo.Version = parts[0]
			if code, err := strconv.Atoi(parts[1]); err == nil {
				httpInfo.StatusCode = code
			}
		}
		if len(parts) >= 3 {
			httpInfo.StatusText = parts[2]
		}
	} else if len(parts) >= 2 {
		httpInfo.Method = parts[0]
		httpInfo.URI = parts[1]
		if len(parts) >= 3 {
			httpInfo.Version = parts[2]
		}
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if colon := strings.Index(line, ":"); colon > 0 {
			key := strings.TrimSpace(line[:colon])
			value := strings.TrimSpace(line[colon+1:])
			httpInfo.Headers[key] = value
			if strings.EqualFold(key, "Content-Length") {
				if n, err := strconv.Atoi(value); err == nil {
					httpInfo.ContentLen = n
				}
			}
		}
	}
	return httpInfo
}
