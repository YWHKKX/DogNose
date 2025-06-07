package web

import (
	"net/http"

	"github.com/GolangProject/DogNose/common/sniffer"
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/gorilla/websocket"
)

type App struct {
}

func NewApp() *App {
	return &App{}
}

func (a *App) Run() {
	device := sniffer.NewDevice(0)
	device.FindDevices("Intel(R) Wi-Fi 6 AX201 160MHz")
	device.AddFilter("tcp")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./templates")))

	mux.HandleFunc("/sniffer", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./templates/sniffer.html")
	})

	mux.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
		device.Run()

		conn, _ := websocket.Upgrade(w, r, nil, 1024, 1024)
		if conn == nil {
			http.Error(w, "Could not upgrade connection", http.StatusInternalServerError)
			return
		}

		for {
			packets := device.CapturePackets(false)
			if len(packets) == 0 {
				continue
			}
			conn.WriteJSON(map[string][]*sniffer.PacketInfo{
				"packets": packets,
			})
		}
	})

	utils.Infof("Starting web server on http://127.0.0.1:8080")
	http.ListenAndServe(":8080", mux)
}
