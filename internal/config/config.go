package config

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"
)

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

type Application struct {
	BaseUrl string
	Name    string
}

type Config struct {
	App      Application
	MongoURI string
	SMTP     SMTPConfig
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

	config.App.Name = viper.GetString("app.name")
	config.App.BaseUrl = viper.GetString("app.base_url")
	config.MongoURI = viper.GetString("mongo.uri")
	config.SMTP.Host = viper.GetString("smtp.host")
	config.SMTP.Port = viper.GetString("smtp.port")
	config.SMTP.Username = viper.GetString("smtp.username")
	config.SMTP.Password = viper.GetString("smtp.password")

	return nil
}
