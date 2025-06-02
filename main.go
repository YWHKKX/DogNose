package main

import (
	"github.com/GolangProject/DogNose/common/utils"
	"github.com/GolangProject/DogNose/common/web"
)

func main() {
	utils.Debug("Starting packet capture...")

	app := web.NewApp()
	app.Run()
}
