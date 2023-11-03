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

type Application struct {
	Name     string
	Protocol string
}

type Authentication struct {
	Key string
}

type DB struct {
	URI string
}

type Config struct {
	App            Application
	REST           Address
	GRPC           Address
	DB             DB
	SMTP           SMTP
	Authentication Authentication
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

	return nil
}
