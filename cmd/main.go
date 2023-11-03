package main

import (
	"os"
	"qd_authentication_api/cmd/application"
	"qd_authentication_api/internal/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/grpclog"
)

func main() {
	verbose := os.Getenv(config.VervoseKey)
	environment := os.Getenv(config.AppEnvironmentKey)
	if verbose == "true" {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stdout))
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		if environment == config.ProductionEnvironment {
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Info().Msg("Starting authentication service...")

	var config config.Config
	confiLocation := "./internal/config"
	config.Load(confiLocation)
	application := application.NewApplication(&config)
	application.StartServers()

	defer application.Close()
}
