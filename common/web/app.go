package web

import (
	"fmt"
	"net/http"

	"github.com/GolangProject/DogNose/common/config"
	"github.com/GolangProject/DogNose/common/sniffer"
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/gorilla/websocket"
)

type App struct {
	cfg    config.Config
	device *sniffer.Device
}

func NewApp(cfg config.Config) *App {
	return &App{cfg: cfg}
}

func (a *App) Run() {
	a.device = sniffer.NewDevice(0)
	a.device.FindDevices(a.cfg.Device)
	if a.device.GetTargetDevice() == "" {
		utils.Fatalf("No suitable network device found. Set DOGNOSE_DEVICE or check available interfaces.")
	}

	if a.cfg.Filter != "" {
		a.device.AddFilter(a.cfg.Filter)
	}

	if err := a.device.Run(); err != nil {
		utils.Fatalf("Failed to start packet capture: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./templates")))
	mux.HandleFunc("/sniffer", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./templates/sniffer.html")
	})
	mux.HandleFunc("/api/devices", a.handleDevices)
	mux.HandleFunc("/packets", a.handlePackets)

	addr := fmt.Sprintf(":%s", a.cfg.Port)
	utils.Infof("Starting web server on http://127.0.0.1%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		utils.Fatalf("Web server failed: %v", err)
	}
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	devices, err := sniffer.ListDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = writeJSON(w, devices)
}

func (a *App) handlePackets(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		utils.Errorf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			utils.Debug("WebSocket client disconnected")
			return
		default:
			packets := a.device.CapturePackets(false)
			if len(packets) == 0 {
				continue
			}
			if err := conn.WriteJSON(map[string][]*sniffer.PacketInfo{
				"packets": packets,
			}); err != nil {
				utils.Debugf("WebSocket write failed: %v", err)
				return
			}
		}
	}
}
