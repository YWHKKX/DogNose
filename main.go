package main

import (
	"github.com/GolangProject/DogNose/common/config"
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/GolangProject/DogNose/common/web"
)

func main() {
	cfg := config.Load()
	utils.Infof("DogNose starting (port=%s filter=%q)", cfg.Port, cfg.Filter)

	app := web.NewApp(cfg)
	app.Run()
}
