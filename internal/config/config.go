package config

import (
	"fmt"
	"os"
	"strings"

	commonAWS "github.com/quadev-ltd/qd-common/pkg/aws"
	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type db struct {
	URI string
}

// Config is the configuration of the application
type Config struct {
	Verbose           bool
	Environment       string
	App               string
	AuthenticationKey string `mapstructure:"authentication_key"`
	AuthenticationDB  db     `mapstructure:"authentication_db"`
	AWS               commonAWS.Config
}

// Load loads the configuration from the given path yml file
func (config *Config) Load(path string) error {
	env := os.Getenv(commonConfig.AppEnvironmentKey)
	if env == "" {
		env = commonConfig.LocalEnvironment
	}
	config.Environment = env

	// Set the file name of the configurations file (if any)
	viper.SetConfigName(fmt.Sprintf("config.%s", env))
	viper.SetConfigType("yml")
	viper.AddConfigPath(path)

	// Bind environment variables (if any, they take priority)
	prefix := fmt.Sprintf("%s_ENV", strings.ToUpper(env))
	viper.AutomaticEnv()
	viper.SetEnvPrefix(prefix)                             // replace YOUR_PREFIX with your actual prefix
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Replace dots with underscores in env var names

	// Read the configuration file
	err := viper.ReadInConfig()
	if err != nil {
		log.Err(fmt.Errorf("Error loading configuration file: %v", err))
	}

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("Error unmarshaling configuration: %v", err)
	}

	if os.Getenv(commonConfig.VerboseKey) == "true" {
		config.Verbose = true
	} else {
		config.Verbose = false
	}
	return nil
}
