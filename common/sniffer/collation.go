package sniffer

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/GolangProject/DogNose/common/utils"
)

func isHTTP(payload []byte) bool {
	if len(payload) < 8 {
		return false
	}

	// 检测HTTP方法
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("DELETE "),
	}
	for _, m := range methods {
		if len(payload) >= len(m) && bytes.Equal(payload[:len(m)], m) {
			return true
		}
	}

	// 检测HTTP响应
	return bytes.HasPrefix(payload, []byte("HTTP/"))
}

func CollationPayload(payload []byte) string {
	var ret string

	if len(payload) < 5 {
		utils.Errorf("[Payload] Too short (%d bytes)", len(payload))
		return ""
	}

	if isHTTP(payload) {
		return fmt.Sprintf("[HTTP] %s\n", string(payload[:min(len(payload), 128)]))
	}

	// SSL/TLS记录头解析
	contentType := payload[0]
	version := hex.EncodeToString(payload[1:3])
	length := uint16(payload[3])<<8 | uint16(payload[4])

	// 常见SSL/TLS内容类型
	var contentTypeStr string
	switch contentType {
	case 0x14:
		contentTypeStr = "ChangeCipherSpec"
	case 0x15:
		contentTypeStr = "Alert"
	case 0x16:
		contentTypeStr = "Handshake"
	case 0x17:
		contentTypeStr = "ApplicationData"
	case 0x18:
		contentTypeStr = "Heartbeat"
	default:
		contentTypeStr = fmt.Sprintf("Unknown(0x%x)", contentType)
	}

	ret += fmt.Sprintf("[SSL/TLS] Type:%s(%d) Version:%s Length:%d\n",
		contentTypeStr, contentType, version, length)

	ret += fmt.Sprintf("Hex Dump (first 64 bytes):\n%s",
		hex.Dump(payload[:min(len(payload), 64)]))

	return ret
}
