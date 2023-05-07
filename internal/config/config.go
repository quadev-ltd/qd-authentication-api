package config

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	MongoURI string
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

	config.MongoURI = viper.GetString("mongo.uri")

	return nil
}
