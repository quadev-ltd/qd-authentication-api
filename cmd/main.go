package main

import (
	"os"
	"qd_authentication_api/cmd/application"
	"qd_authentication_api/internal/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/grpclog"
)

func setUpLogs(configurations *config.Config) {

	if configurations.Verbose == true {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stdout))
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		if configurations.Environment == config.ProductionEnvironment {
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func main() {

	var config config.Config
	configLocation := "./internal/config"
	config.Load(configLocation)

	setUpLogs(&config)

	log.Info().Msg("Starting authentication service...")
	application := application.NewApplication(&config)
	application.StartServers()

	defer application.Close()
}
