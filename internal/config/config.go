package config

import (
	"fmt"
	"log"
	"os"

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

func (config *Config) Load() error {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "dev"
	}
	viper.SetConfigName(fmt.Sprintf("config.%s", env))
	viper.SetConfigType("yml")
	viper.AddConfigPath("./internal/config")

	// Read the configuration file
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error loading configuration file: %v", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("Error unmarshaling configuration: %v", err)
	}

	return nil
}
