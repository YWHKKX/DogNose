package sniffer

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GolangProject/DogNose/common/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

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

	buffer []*PacketInfo
	frame  uint64
	total  uint64
	bytes  uint64

	writer   *pcapgo.Writer
	pcapFile *os.File
}

func NewHub(device *Device, bufferSize int, savePCAP bool) *Hub {
	if bufferSize < 100 {
		bufferSize = 100
	}
	return &Hub{
		device:     device,
		bufferSize: bufferSize,
		savePCAP:   savePCAP,
		clients:    make(map[chan []*PacketInfo]struct{}),
		buffer:     make([]*PacketInfo, 0, bufferSize),
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
	h.buffer = h.buffer[:0]
	atomic.StoreUint64(&h.total, 0)
	atomic.StoreUint64(&h.bytes, 0)
	atomic.StoreUint64(&h.frame, 0)
}

func (h *Hub) SetFilter(filter string) error {
	return h.device.UpdateFilter(filter)
}

func (h *Hub) Subscribe() (chan []*PacketInfo, []*PacketInfo) {
	ch := make(chan []*PacketInfo, 16)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[ch] = struct{}{}
	snapshot := make([]*PacketInfo, len(h.buffer))
	copy(snapshot, h.buffer)
	return ch, snapshot
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
	if !h.startedAt.IsZero() {
		started = h.startedAt.Format(time.RFC3339)
	}
	return CaptureStats{
		Running:       h.running,
		Paused:        h.paused,
		Device:        h.device.GetTargetDevice(),
		Filter:        h.device.MakeFilter(),
		TotalPackets:  atomic.LoadUint64(&h.total),
		BufferedCount: len(h.buffer),
		Clients:       len(h.clients),
		BytesCaptured: atomic.LoadUint64(&h.bytes),
		StartedAt:     started,
	}
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
	h.buffer = append(h.buffer, info)
	if len(h.buffer) > h.bufferSize {
		h.buffer = h.buffer[len(h.buffer)-h.bufferSize:]
	}
	writer := h.writer
	h.mu.Unlock()

	if writer != nil {
		_ = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	return info
}

func (h *Hub) broadcast(batch []*PacketInfo) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- batch:
		default:
			// slow client: drop batch to avoid blocking capture
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
	}
}
