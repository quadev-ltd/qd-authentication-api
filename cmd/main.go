package main

import (
	"os"

	"google.golang.org/grpc/grpclog"

	"qd-authentication-api/internal/application"
	"qd-authentication-api/internal/config"
)

func main() {

	var configurations config.Config
	configLocation := "./internal/config"
	configurations.Load(configLocation)

	if configurations.Verbose {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stdout))
	}

	application := application.NewApplication(&configurations)
	if application == nil {
		return
	}

	application.StartServer()
	defer application.Close()
}
