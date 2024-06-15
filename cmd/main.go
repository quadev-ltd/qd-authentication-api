package main

import (
	"log"
	"os"

	commontConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"google.golang.org/grpc/grpclog"

	"qd-authentication-api/internal/application"
	"qd-authentication-api/internal/config"
)

func main() {

	var configurations config.Config
	configLocation := "./internal/config"
	err := configurations.Load(configLocation)
	if err != nil {
		log.Fatalln("Failed loading the configurations", err)
	}

	var centralConfig commontConfig.Config
	centralConfig.Load(
		configurations.Environment,
		configurations.AWS.Key,
		configurations.AWS.Secret,
	)

	if configurations.Verbose {
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stdout))
	}

	application := application.NewApplication(&configurations, &centralConfig, nil)
	if application == nil {
		log.Fatalln("Failed to create application")
		return
	}

	application.StartServer()
	defer application.Close()
}
