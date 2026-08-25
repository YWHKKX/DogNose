package sniffer

import (
	"fmt"
	"sync"
	"time"

	"github.com/GolangProject/DogNose/common/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func decodeGBK(s string) string {
	result, _, _ := transform.String(simplifiedchinese.GBK.NewDecoder(), s)
	return result
}

type DeviceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

type Device struct {
	mu           sync.Mutex
	snapshotLen  int32
	promiscuous  bool
	timeout      time.Duration
	targetDevice string
	filters      []string
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
}

func NewDevice(snapshotLen int32, promiscuous bool) *Device {
	if snapshotLen <= 0 {
		snapshotLen = 65535
	}
	return &Device{
		snapshotLen: snapshotLen,
		promiscuous: promiscuous,
		timeout:     500 * time.Millisecond,
	}
}

func (d *Device) GetTargetDevice() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.targetDevice
}

func (d *Device) GetFilters() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.filters))
	copy(out, d.filters)
	return out
}

func (d *Device) SetFilters(filters []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = filters
}

func (d *Device) AddFilter(filter string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = append(d.filters, filter)
}

func (d *Device) MakeFilter() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return joinFilters(d.filters)
}

func joinFilters(filters []string) string {
	parts := make([]string, 0, len(filters))
	for _, f := range filters {
		if f != "" {
			parts = append(parts, "("+f+")")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += " and " + parts[i]
	}
	return result
}

func ListDevices() ([]DeviceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	result := make([]DeviceInfo, 0, len(devices))
	for _, device := range devices {
		info := DeviceInfo{
			Name:        device.Name,
			Description: device.Description,
		}
		for _, address := range device.Addresses {
			if address.IP != nil {
				info.Addresses = append(info.Addresses, address.IP.String())
			}
		}
		result = append(result, info)
	}
	return result, nil
}

func (d *Device) FindDevices(target string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		utils.Errorf(err.Error())
		return
	}

	fmt.Println("===============================================")
	fmt.Println("Devices found: ", len(devices))
	for _, device := range devices {
		fmt.Println("-----------------------------------------------")
		fmt.Println("Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}

		if target != "" && (device.Description == target || device.Name == target) {
			d.mu.Lock()
			d.targetDevice = device.Name
			d.mu.Unlock()
			continue
		}

		d.mu.Lock()
		empty := d.targetDevice == ""
		d.mu.Unlock()
		if target == "" && empty && hasActiveAddress(device.Addresses) {
			d.mu.Lock()
			d.targetDevice = device.Name
			d.mu.Unlock()
		}
	}
	fmt.Println("===============================================")

	if d.GetTargetDevice() == "" {
		utils.Errorf("No suitable network device found")
		return
	}

	utils.Infof("Using device: %s", d.GetTargetDevice())
}

func hasActiveAddress(addresses []pcap.InterfaceAddress) bool {
	for _, address := range addresses {
		if address.IP != nil && !address.IP.IsLoopback() {
			return true
		}
	}
	return false
}

func (d *Device) Open() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.targetDevice == "" {
		return fmt.Errorf("target device is not set")
	}
	if d.handle != nil {
		d.handle.Close()
		d.handle = nil
		d.packetSource = nil
	}

	handle, err := pcap.OpenLive(d.targetDevice, d.snapshotLen, d.promiscuous, d.timeout)
	if err != nil {
		return fmt.Errorf("%s", decodeGBK(err.Error()))
	}

	filter := joinFilters(d.filters)
	if filter != "" {
		if err = handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return err
		}
	}

	d.handle = handle
	d.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	d.packetSource.NoCopy = true
	utils.Infof("Packet capture opened with filter: %q", filter)
	return nil
}

// Deprecated: use Open.
func (d *Device) Run() error {
	return d.Open()
}

func (d *Device) UpdateFilter(filter string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.filters = nil
	if filter != "" {
		d.filters = []string{filter}
	}
	if d.handle == nil {
		return nil
	}
	expr := joinFilters(d.filters)
	if expr == "" {
		expr = "ip or ip6"
	}
	if err := d.handle.SetBPFFilter(expr); err != nil {
		return err
	}
	utils.Infof("BPF filter updated to: %q", expr)
	return nil
}

func (d *Device) Packets() <-chan gopacket.Packet {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.packetSource == nil {
		return nil
	}
	return d.packetSource.Packets()
}

func (d *Device) SnapshotLen() int32 {
	return d.snapshotLen
}

func (d *Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handle != nil {
		d.handle.Close()
		d.handle = nil
		d.packetSource = nil
	}
}
