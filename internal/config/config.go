package config

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type Address struct {
	Host string
	Port string
}

type SMTP struct {
	Host     string
	Port     string
	Username string
	Password string
}

type DB struct {
	URI string
}

type Config struct {
	Verbose                   bool
	Environment               string
	App                       string
	AuthenticationKey         string `mapstructure:"authentication_key"`
	EmailVerificationEndpoint string `mapstructure:"email_verification_endpoint"`
	GRPC                      Address
	REST                      Address
	DB                        DB
	SMTP                      SMTP
}

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
