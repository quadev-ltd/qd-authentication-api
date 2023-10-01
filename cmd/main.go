package main

import (
	"log"
	"qd_authentication_api/cmd/application"
	"qd_authentication_api/internal/config"
)

func main() {
	// grpclog.SetLogger(log.New(os.Stdout, "grpc: ", log.LstdFlags))
	log.Println("Starting authentication service...")

	var config config.Config
	config.Load("./internal/config")
	application := application.NewApplication(&config)
	application.StartServers()

	defer application.Close()
}
