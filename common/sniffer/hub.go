package sniffer

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GolangProject/DogNose/common/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type talkerAcc struct {
	packets uint64
	bytes   uint64
}

type Hub struct {
	device     *Device
	bufferSize int
	savePCAP   bool

	mu        sync.RWMutex
	running   bool
	paused    bool
	startedAt time.Time
	stopCh    chan struct{}
	clients   map[chan []*PacketInfo]struct{}

	ring   []*PacketInfo
	ringPos int
	ringLen int

	frame  uint64
	total  uint64
	bytes  uint64
	drops  uint64

	protoCounts map[string]uint64
	talkers     map[string]*talkerAcc

	writer   *pcapgo.Writer
	pcapFile *os.File
	pcapPath string
}

func NewHub(device *Device, bufferSize int, savePCAP bool) *Hub {
	if bufferSize < 100 {
		bufferSize = 100
	}
	return &Hub{
		device:      device,
		bufferSize:  bufferSize,
		savePCAP:    savePCAP,
		clients:     make(map[chan []*PacketInfo]struct{}),
		ring:        make([]*PacketInfo, bufferSize),
		protoCounts: make(map[string]uint64),
		talkers:     make(map[string]*talkerAcc),
	}
}

func (h *Hub) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return nil
	}
	if err := h.device.Open(); err != nil {
		return err
	}
	if h.savePCAP {
		if err := h.openPCAPLocked(); err != nil {
			utils.Warnf("pcap save disabled: %v", err)
			h.savePCAP = false
		}
	}
	h.running = true
	h.paused = false
	h.startedAt = time.Now()
	h.stopCh = make(chan struct{})
	go h.loop(h.stopCh)
	utils.Info("Capture hub started")
	return nil
}

func (h *Hub) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	close(h.stopCh)
	h.running = false
	h.paused = false
	h.mu.Unlock()

	h.device.Close()
	h.closePCAP()
	utils.Info("Capture hub stopped")
}

func (h *Hub) Pause() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paused = true
}

func (h *Hub) Resume() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paused = false
}

func (h *Hub) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ring = make([]*PacketInfo, h.bufferSize)
	h.ringPos = 0
	h.ringLen = 0
	h.protoCounts = make(map[string]uint64)
	h.talkers = make(map[string]*talkerAcc)
	atomic.StoreUint64(&h.total, 0)
	atomic.StoreUint64(&h.bytes, 0)
	atomic.StoreUint64(&h.frame, 0)
	atomic.StoreUint64(&h.drops, 0)
}

func (h *Hub) SetFilter(filter string) error {
	return h.device.UpdateFilter(filter)
}

func (h *Hub) Snapshot() []*PacketInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.snapshotLocked()
}

func (h *Hub) GetPacket(frameID int) *PacketInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := 0; i < h.ringLen; i++ {
		idx := (h.ringPos - h.ringLen + i + h.bufferSize) % h.bufferSize
		p := h.ring[idx]
		if p != nil && p.FrameID == frameID {
			return p
		}
	}
	return nil
}

func (h *Hub) StartPCAP() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.writer != nil {
		return h.pcapPath, nil
	}
	if err := h.openPCAPLocked(); err != nil {
		return "", err
	}
	h.savePCAP = true
	return h.pcapPath, nil
}

func (h *Hub) StopPCAP() {
	h.closePCAP()
	h.mu.Lock()
	h.savePCAP = false
	h.mu.Unlock()
}

func (h *Hub) Subscribe() (chan []*PacketInfo, []*PacketInfo) {
	ch := make(chan []*PacketInfo, 16)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[ch] = struct{}{}
	return ch, h.snapshotLocked()
}

func (h *Hub) Unsubscribe(ch chan []*PacketInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
}

func (h *Hub) Stats() CaptureStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	started := ""
	pps := 0.0
	if !h.startedAt.IsZero() {
		started = h.startedAt.Format(time.RFC3339)
		elapsed := time.Since(h.startedAt).Seconds()
		if elapsed > 0 {
			pps = float64(atomic.LoadUint64(&h.total)) / elapsed
		}
	}
	proto := make(map[string]uint64, len(h.protoCounts))
	for k, v := range h.protoCounts {
		proto[k] = v
	}
	return CaptureStats{
		Running:        h.running,
		Paused:         h.paused,
		Device:         h.device.GetTargetDevice(),
		Filter:         h.device.MakeFilter(),
		TotalPackets:   atomic.LoadUint64(&h.total),
		BufferedCount:  h.ringLen,
		BufferCapacity: h.bufferSize,
		Clients:        len(h.clients),
		BytesCaptured:  atomic.LoadUint64(&h.bytes),
		DroppedBatches: atomic.LoadUint64(&h.drops),
		PacketsPerSec:  pps,
		StartedAt:      started,
		SavingPCAP:     h.writer != nil,
		ProtocolCounts: proto,
		TopTalkers:     h.topTalkersLocked(8),
	}
}

func (h *Hub) snapshotLocked() []*PacketInfo {
	out := make([]*PacketInfo, 0, h.ringLen)
	for i := 0; i < h.ringLen; i++ {
		idx := (h.ringPos - h.ringLen + i + h.bufferSize) % h.bufferSize
		out = append(out, h.ring[idx])
	}
	return out
}

func (h *Hub) topTalkersLocked(n int) []TalkerStat {
	list := make([]TalkerStat, 0, len(h.talkers))
	for ip, acc := range h.talkers {
		list = append(list, TalkerStat{IP: ip, Packets: acc.packets, Bytes: acc.bytes})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Bytes == list[j].Bytes {
			return list[i].Packets > list[j].Packets
		}
		return list[i].Bytes > list[j].Bytes
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func (h *Hub) loop(stop <-chan struct{}) {
	packets := h.device.Packets()
	if packets == nil {
		return
	}

	batch := make([]*PacketInfo, 0, 64)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := make([]*PacketInfo, len(batch))
		copy(out, batch)
		batch = batch[:0]
		h.broadcast(out)
	}

	for {
		select {
		case <-stop:
			flush()
			return
		case <-ticker.C:
			flush()
		case packet, ok := <-packets:
			if !ok {
				flush()
				return
			}
			h.mu.RLock()
			paused := h.paused
			h.mu.RUnlock()
			if paused {
				continue
			}
			info := h.ingest(packet)
			batch = append(batch, info)
			if len(batch) >= 64 {
				flush()
			}
		}
	}
}

func (h *Hub) ingest(packet gopacket.Packet) *PacketInfo {
	frame := atomic.AddUint64(&h.frame, 1)
	info := parsePacket(packet, int(frame), h.device.GetTargetDevice())
	atomic.AddUint64(&h.total, 1)
	atomic.AddUint64(&h.bytes, uint64(info.CapturedBytes))

	h.mu.Lock()
	h.ring[h.ringPos] = info
	h.ringPos = (h.ringPos + 1) % h.bufferSize
	if h.ringLen < h.bufferSize {
		h.ringLen++
	}
	h.protoCounts[info.Protocol]++
	h.recordTalkerLocked(info)
	writer := h.writer
	h.mu.Unlock()

	if writer != nil {
		_ = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	return info
}

func (h *Hub) recordTalkerLocked(info *PacketInfo) {
	add := func(ip string) {
		if ip == "" {
			return
		}
		acc := h.talkers[ip]
		if acc == nil {
			acc = &talkerAcc{}
			h.talkers[ip] = acc
		}
		acc.packets++
		acc.bytes += uint64(info.CapturedBytes)
	}
	if info.IPv4.SrcIP != "" {
		add(info.IPv4.SrcIP)
		add(info.IPv4.DstIP)
	} else if info.IPv6.SrcIP != "" {
		add(info.IPv6.SrcIP)
		add(info.IPv6.DstIP)
	} else if info.ARP.SenderIP != "" {
		add(info.ARP.SenderIP)
		add(info.ARP.TargetIP)
	}
}

func (h *Hub) broadcast(batch []*PacketInfo) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- batch:
		default:
			atomic.AddUint64(&h.drops, 1)
		}
	}
}

func (h *Hub) openPCAPLocked() error {
	if err := os.MkdirAll("saves", 0o755); err != nil {
		return err
	}
	name := time.Now().Format("2006_01_02_15-04-05") + ".pcap"
	path := filepath.Join("saves", name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(h.device.SnapshotLen()), layers.LinkTypeEthernet); err != nil {
		f.Close()
		return err
	}
	h.pcapFile = f
	h.writer = w
	h.pcapPath = path
	utils.Infof("Saving packets to %s", path)
	return nil
}

func (h *Hub) closePCAP() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pcapFile != nil {
		_ = h.pcapFile.Close()
		h.pcapFile = nil
		h.writer = nil
		h.pcapPath = ""
	}
}
