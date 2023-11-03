package config

import (
	"fmt"
	"os"

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
	DB                        db
	SMTP                      smtp
}

// Load loads the configuration from the given path yml file
func (config *Config) Load(path string) error {
	env := os.Getenv(AppEnvironmentKey)
	if env == "" {
		env = DevelopmentEnvironment
	}
	viper.SetConfigName(fmt.Sprintf("config.%s", env))
	viper.SetConfigType("yml")
	viper.AddConfigPath(path)

	// Read the configuration file
	err := viper.ReadInConfig()
	if err != nil {
		log.Err(fmt.Errorf("Error loading configuration file: %v", err))
	}

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("Error unmarshaling configuration: %v", err)
	}
	if os.Getenv(VerboseKey) == "true" {
		config.Verbose = true
	} else {
		config.Verbose = false
	}
	if os.Getenv(AppEnvironmentKey) != "" {
		config.Environment = os.Getenv(AppEnvironmentKey)
	}

	return nil
}
