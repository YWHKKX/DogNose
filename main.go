package main

import (
	"github.com/GolangProject/DogNose/common/config"
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/GolangProject/DogNose/common/web"
)

func main() {
	cfg := config.Load()
	utils.Debug("Starting packet capture...")

	app := web.NewApp(cfg)
	app.Run()
}
