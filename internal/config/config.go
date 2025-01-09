package config

import (
	"fmt"

	commonAWS "github.com/quadev-ltd/qd-common/pkg/aws"
	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"
)

type db struct {
	URI string
}

type firebase struct {
	ConfigPath string `mapstructure:"config_path"`
}

// Config is the configuration of the application
type Config struct {
	Verbose           bool
	Environment       string
	AuthenticationKey string   `mapstructure:"authentication_key"`
	AuthenticationDB  db       `mapstructure:"authentication_db"`
	Firebase          firebase `mapstructure:"firebase"`
	AWS               commonAWS.Config
}

// Load loads the configuration from the given path yml file
func (config *Config) Load(path string) error {
	env := commonConfig.GetEnvironment()
	config.Environment = env
	config.Verbose = commonConfig.GetVerbose()

	log.Info().Msgf("Loading configuration for environment: %s", env)
	vip, err := commonConfig.SetupConfig(path, env)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}
	if err := vip.Unmarshal(&config); err != nil {
		return fmt.Errorf("Error unmarshaling configuration: %v", err)
	}

	return nil
}
