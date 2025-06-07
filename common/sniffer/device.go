package sniffer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GolangProject/DogNose/common/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func decodeGBK(s string) string {
	result, _, _ := transform.String(simplifiedchinese.GBK.NewDecoder(), s)
	return result
}

type Device struct {
	snapshotLen  int32
	promiscuous  bool
	timeout      time.Duration
	targetDevice string
	filters      []string
	packetLimit  int
	packetSource *gopacket.PacketSource
}

func NewDevice(packetLimits ...int) *Device {
	packetLimit := 0
	if len(packetLimits) > 0 {
		packetLimit = packetLimits[0]
	}

	return &Device{
		snapshotLen: 1024,
		promiscuous: false,
		timeout:     30 * time.Second,
		packetLimit: packetLimit,
	}
}

func (d *Device) GetTargetDevice() string {
	return d.targetDevice
}

func (d *Device) GetFilters() []string {
	return d.filters
}

func (d *Device) SetFilters(filters []string) {
	d.filters = filters
}

func (d *Device) AddFilter(filter string) {
	d.filters = append(d.filters, filter)
}

func (d *Device) MakeFilter() string {
	return strings.Join(d.filters, " && ")
}

func (d *Device) FindDevices(target string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		utils.Errorf(err.Error())
	}
	fmt.Println("===============================================")
	fmt.Println("Devices found: ", len(devices))
	for _, device := range devices {
		fmt.Println("-----------------------------------------------")
		fmt.Println("Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
		if device.Description == target {
			d.targetDevice = device.Name
		}
	}
	fmt.Println("===============================================")
	if d.GetTargetDevice() == "" {
		utils.Errorf("No suitable network device found")
		return
	}

	utils.Infof("Using device: %s", d.GetTargetDevice())
}

func (d *Device) Run() {
	handle, err := pcap.OpenLive(d.targetDevice, d.snapshotLen, d.promiscuous, d.timeout)
	if err != nil {
		utils.Errorf(decodeGBK(err.Error()))
	}

	err = handle.SetBPFFilter(d.MakeFilter())
	if err != nil {
		utils.Errorf(err.Error())
		return
	}

	d.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	d.packetSource.NoCopy = true
}

func (d *Device) CapturePackets(isSave ...bool) (ret []*PacketInfo) {
	if d.packetSource == nil {
		utils.Errorf("Packet source is not initialized. Please run Run() first")
		return nil
	}

	Save := func(gopacket.Packet) {}
	if len(isSave) > 0 && isSave[0] {
		saveFile := time.Now().Format("2006_01_02_15-04") + ".pcap"
		currentDir, _ := os.Getwd()
		savePath := filepath.Join(currentDir, "saves", saveFile)

		var w *pcapgo.Writer
		_, err := os.Stat(savePath)
		if err != nil {
			utils.Warnf("Storage Path: %s does not exist, creating new file", savePath)
			f, _ := os.Create(savePath)
			w = pcapgo.NewWriter(f)
			w.WriteFileHeader(uint32(d.snapshotLen), layers.LinkTypeEthernet)
		} else {
			f, _ := os.OpenFile(savePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			w = pcapgo.NewWriter(f)
		}

		Save = func(packet gopacket.Packet) {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}

	frameCount := 0
	for timeout := time.After(1 * time.Second); ; {
		select {
		case <-timeout:
			return ret
		case packet := <-d.packetSource.Packets():
			Save(packet)
			frameCount++
			packetInfo := parsePacket(packet, frameCount, d.targetDevice)
			// formatOutput(packetInfo)
			ret = append(ret, packetInfo)
		}
	}
}

func parsePacket(packet gopacket.Packet, frameID int, iface string) *PacketInfo {
	metadata := packet.Metadata()
	info := &PacketInfo{
		FrameID:       frameID,
		CaptureTime:   metadata.Timestamp.String(),
		Interface:     iface,
		WireBytes:     metadata.Length,
		Protocol:      "Unknown",
		CapturedBytes: metadata.CaptureLength,
	}

	// 解析以太网层
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		info.Ethernet = EthernetInfo{
			SrcMAC:      eth.SrcMAC.String(),
			DstMAC:      eth.DstMAC.String(),
			EtherType:   eth.EthernetType.String(),
			StreamIndex: 0,
		}
	}

	// 解析IPv6层
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		info.IPv6 = IPv6Info{
			SrcIP: ipv6.SrcIP.String(),
			DstIP: ipv6.DstIP.String(),
		}
	}

	// 解析IPv4层
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		info.IPv4 = IPv4Info{
			SrcIP: ipv4.SrcIP.String(),
			DstIP: ipv4.DstIP.String(),
		}
	}

	// 解析UDP层
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.UDP = UDPInfo{
			SrcPort: uint16(udp.SrcPort),
			DstPort: uint16(udp.DstPort),
		}
	}

	// 解析TCP层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.TCP = TCPInfo{
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Seq:     tcp.Seq,
			Ack:     tcp.Ack,
			DataLen: len(tcp.Payload),
		}
	}

	// 解析Payload层
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 4 && strings.HasPrefix(string(payload), "POST") {
			info.HTTP = parseHTTP(payload)
			info.Protocol = "HTTP"
			info.RawData = payload
		}
		if len(payload) > 3 && strings.HasPrefix(string(payload), "GET") {
			info.HTTP = parseHTTP(payload)
			info.Protocol = "HTTP"
			info.RawData = payload
		}
	}

	return info
}

func parseHTTP(payload []byte) HTTPInfo {
	httpInfo := HTTPInfo{Headers: make(map[string]string)}
	lines := strings.Split(string(payload), "\r\n")

	// 解析请求行
	if len(lines) > 0 {
		parts := strings.Split(lines[0], " ")
		if len(parts) >= 2 {
			httpInfo.Method = parts[0]
			httpInfo.URI = parts[1]
		}
	}

	// 解析头部
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if colon := strings.Index(line, ":"); colon > 0 {
			key := strings.TrimSpace(line[:colon])
			value := strings.TrimSpace(line[colon+1:])
			httpInfo.Headers[key] = value

			if key == "Content-Length" {
				if len, err := strconv.Atoi(value); err == nil {
					httpInfo.ContentLen = len
				}
			}
		}
	}
	return httpInfo
}

func formatOutput(info *PacketInfo) {
	fmt.Printf("Frame %d: %d bytes on wire (%d bits), %d bytes captured (%d bits) on interface %s\n",
		info.FrameID, info.WireBytes, info.WireBytes*8,
		info.CapturedBytes, info.CapturedBytes*8, info.Interface)

	fmt.Println("Ethernet II, Src:", info.Ethernet.SrcMAC, "Dst:", info.Ethernet.DstMAC)
	fmt.Println("    Destination:", info.Ethernet.DstMAC)
	fmt.Println("    Source:", info.Ethernet.SrcMAC)
	fmt.Println("    Type:", info.Ethernet.EtherType)
	fmt.Println("    [Stream index: ", info.Ethernet.StreamIndex, "]")

	if info.IPv6.SrcIP != "" {
		fmt.Println("Internet Protocol Version 6, Src:", info.IPv6.SrcIP, "Dst:", info.IPv6.DstIP)
	}
	if info.IPv4.SrcIP != "" {
		fmt.Println("Internet Protocol Version 4, Src:", info.IPv4.SrcIP, "Dst:", info.IPv4.DstIP)
	}

	if info.TCP.SrcPort != 0 {
		fmt.Printf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d\n",
			info.TCP.SrcPort, info.TCP.DstPort, info.TCP.Seq, info.TCP.Ack, info.TCP.DataLen)
	}
	if info.UDP.SrcPort != 0 {
		fmt.Printf("User Datagram Protocol, Src Port: %d, Dst Port: %d\n", info.UDP.SrcPort, info.UDP.DstPort)
	}

	if info.HTTP.Method != "" {
		fmt.Println("Hypertext Transfer Protocol")
		fmt.Printf("    %s %s HTTP/1.1\\r\\n", info.HTTP.Method, info.HTTP.URI)
		for k, v := range info.HTTP.Headers {
			fmt.Printf("    %s: %s\\r\\n", k, v)
		}
		fmt.Println("    \\r\\n")
		fmt.Println("    [Full request URI: http://" + info.HTTP.Headers["Host"] + info.HTTP.URI + "]")
		fmt.Printf("    File Data: %d bytes\n", info.HTTP.ContentLen)
	}

	if len(info.RawData) > 0 {
		fmt.Println("Data (", len(info.RawData), "bytes)")
		fmt.Printf("    Data […]: %x\n", info.RawData[:min(64, len(info.RawData))])
		fmt.Printf("    [Length: %d]\n", len(info.RawData))
	}
	fmt.Println("--------------------------------------------------")
}
