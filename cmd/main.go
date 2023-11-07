package main

import (
	"os"
	"qd_authentication_api/internal/application"
	"qd_authentication_api/internal/config"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/grpclog"
)

func main() {

	var configurations config.Config
	configLocation := "./internal/config"
	configurations.Load(configLocation)

	if configurations.Verbose {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stdout))
	}

	log.Info().Msg("Starting authentication service..")
	application := application.NewApplication(&configurations)
	application.StartServer()

	defer application.Close()
}
