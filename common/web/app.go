package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/GolangProject/DogNose/common/config"
	"github.com/GolangProject/DogNose/common/sniffer"
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/gorilla/websocket"
)

type App struct {
	cfg  config.Config
	hub  *sniffer.Hub
	upgr websocket.Upgrader
}

func NewApp(cfg config.Config) *App {
	return &App{
		cfg: cfg,
		upgr: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

func (a *App) Run() {
	device := sniffer.NewDevice(a.cfg.SnapshotLen, a.cfg.Promiscuous)
	device.FindDevices(a.cfg.Device)
	if device.GetTargetDevice() == "" {
		utils.Fatalf("No suitable network device found. Set DOGNOSE_DEVICE or --device.")
	}
	if a.cfg.Filter != "" {
		device.AddFilter(a.cfg.Filter)
	}

	a.hub = sniffer.NewHub(device, a.cfg.BufferSize, a.cfg.SavePCAP)
	if err := a.hub.Start(); err != nil {
		utils.Fatalf("Failed to start packet capture: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./templates")))
	mux.HandleFunc("/sniffer", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./templates/sniffer.html")
	})
	mux.HandleFunc("/api/devices", a.handleDevices)
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/capture/pause", a.handlePause)
	mux.HandleFunc("/api/capture/resume", a.handleResume)
	mux.HandleFunc("/api/capture/clear", a.handleClear)
	mux.HandleFunc("/api/filter", a.handleFilter)
	mux.HandleFunc("/packets", a.handlePackets)

	addr := fmt.Sprintf(":%s", a.cfg.Port)
	utils.Infof("Starting web server on http://127.0.0.1%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		a.hub.Stop()
		utils.Fatalf("Web server failed: %v", err)
	}
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := sniffer.ListDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, devices)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.hub.Stats())
}

func (a *App) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.hub.Pause()
	writeJSON(w, a.hub.Stats())
}

func (a *App) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.hub.Resume()
	writeJSON(w, a.hub.Stats())
}

func (a *App) handleClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.hub.Clear()
	writeJSON(w, a.hub.Stats())
}

func (a *App) handleFilter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{"filter": a.hub.Stats().Filter})
	case http.MethodPut, http.MethodPost:
		var body struct {
			Filter string `json:"filter"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := a.hub.SetFilter(body.Filter); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, a.hub.Stats())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handlePackets(w http.ResponseWriter, r *http.Request) {
	conn, err := a.upgr.Upgrade(w, r, nil)
	if err != nil {
		utils.Errorf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ch, snapshot := a.hub.Subscribe()
	defer a.hub.Unsubscribe(ch)

	if len(snapshot) > 0 {
		if err := conn.WriteJSON(map[string]interface{}{
			"type":    "snapshot",
			"packets": snapshot,
		}); err != nil {
			return
		}
	}

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
		case batch, ok := <-ch:
			if !ok {
				return
			}
			if err := conn.WriteJSON(map[string]interface{}{
				"type":    "packets",
				"packets": batch,
			}); err != nil {
				utils.Debugf("WebSocket write failed: %v", err)
				return
			}
		}
	}
}
