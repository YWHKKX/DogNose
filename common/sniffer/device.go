package sniffer

import (
	"fmt"
	"os"
	"path/filepath"
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

func (d *Device) FindDevices() {
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
		if device.Description == "Microsoft" && len(device.Addresses) == 4 {
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
}

func (d *Device) GetColumn(isSave ...bool) string {
	if d.packetSource == nil {
		utils.Errorf("Packet source is not initialized. Please run Run() first")
		return ""
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

	data := ""
	if packet, err := d.packetSource.NextPacket(); err == nil {
		Save(packet)

		var SrcIP, DstIP interface{}
		var SrcPort, DstPort uint16

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			SrcIP = ip.SrcIP
			DstIP = ip.DstIP
		} else {
			SrcIP = "Unknown"
			DstIP = "Unknown"
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			SrcPort = uint16(tcp.SrcPort)
			DstPort = uint16(tcp.DstPort)
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			SrcPort = uint16(udp.SrcPort)
			DstPort = uint16(udp.DstPort)
		}

		tableRow := 45
		line := fmt.Sprintf("%s:%d -> %s:%d", SrcIP, SrcPort, DstIP, DstPort)
		data += fmt.Sprintf("[%s%s]\n[%s]\n", line, strings.Repeat(" ", tableRow-len(line)), strings.Repeat("-", tableRow))
	}
	return data
}

func (d *Device) GetData(isSave ...bool) string {
	if d.packetSource == nil {
		utils.Errorf("Packet source is not initialized. Please run Run() first")
		return ""
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

	data := ""
	packetCount := 0
	for packet := range d.packetSource.Packets() {
		if packetCount > d.packetLimit {
			break
		}
		packetCount++
		Save(packet)

		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			data += fmt.Sprintf("[Ethernet] %s -> %s\n", eth.SrcMAC, eth.DstMAC)
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			data += fmt.Sprintf("[IP] %s -> %s\n", ip.SrcIP, ip.DstIP)
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			data += fmt.Sprintf(
				"[TCP] Port: %d -> %d | Flags: SYN=%t ACK=%t FIN=%t RST=%t PSH=%t URG=%t\n",
				tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST, tcp.PSH, tcp.URG,
			)
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			data += fmt.Sprintf("[UDP] Port: %d -> %d\n", udp.SrcPort, udp.DstPort)
		}
		if payloadLayer := packet.ApplicationLayer(); payloadLayer != nil {
			payload := payloadLayer.Payload()
			data += CollationPayload(payload)
		}
		data += "-------------------------------------------------------------------------\n"
	}
	return data
}

func (d *Device) ShowData() {
	if d.packetSource == nil {
		utils.Errorf("Packet source is not initialized. Please run Run() first")
		return
	}

	index := 0
	for packet := range d.packetSource.Packets() {
		if index > d.packetLimit {
			break
		}
		index++

		fmt.Println("-----------------------------------------------")
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			utils.Infof("[Ethernet] %s -> %s", eth.SrcMAC, eth.DstMAC)
		}
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			utils.Infof("[IP] %s -> %s", ip.SrcIP, ip.DstIP)
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			utils.Infof(
				"[TCP] Port: %d -> %d | Flags: SYN=%t ACK=%t FIN=%t RST=%t PSH=%t URG=%t",
				tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST, tcp.PSH, tcp.URG,
			)
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			utils.Infof(
				"[UDP] Port: %d -> %d",
				udp.SrcPort, udp.DstPort,
			)
		}
		if payloadLayer := packet.ApplicationLayer(); payloadLayer != nil {
			payload := payloadLayer.Payload()
			hexDumpWithSpaces := "\n"
			for i, b := range payload {
				hexDumpWithSpaces += fmt.Sprintf("%02x ", b)
				if (i+1)%32 == 0 {
					hexDumpWithSpaces += "\n"
				}
			}
			utils.Infof("[Payload] Hex: %s", hexDumpWithSpaces)
		}
	}
}
