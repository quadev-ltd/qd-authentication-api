package config

import (
	"fmt"
	"os"
	"strings"

	pkgConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type address struct {
	Host string
	Port string
}

type smtp struct {
	Host     string
	Port     string
	Username string
	Password string
}

type db struct {
	URI string
}

// Config is the configuration of the application
type Config struct {
	Verbose                   bool
	Environment               string
	App                       string
	AuthenticationKey         string `mapstructure:"authentication_key"`
	EmailVerificationEndpoint string `mapstructure:"email_verification_endpoint"`
	GRPC                      address
	AuthenticationDB          db `mapstructure:"authentication_db"`
	Email                     address
}

// Load loads the configuration from the given path yml file
func (config *Config) Load(path string) error {
	env := os.Getenv(pkgConfig.AppEnvironmentKey)
	if env == "" {
		env = pkgConfig.LocalEnvironment
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

	if os.Getenv(pkgConfig.VerboseKey) == "true" {
		config.Verbose = true
	} else {
		config.Verbose = false
	}
	return nil
}
