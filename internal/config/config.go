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

type Config struct {
	App            Application
	REST           Address
	GRPC           Address
	MongoURI       string
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

	config.App.Name = viper.GetString("app.name")
	config.App.Protocol = viper.GetString("app.protocol")
	config.REST.Host = viper.GetString("http.host")
	config.REST.Port = viper.GetString("http.port")
	config.GRPC.Host = viper.GetString("grpc.host")
	config.GRPC.Port = viper.GetString("grpc.port")
	config.MongoURI = viper.GetString("mongo.uri")
	config.SMTP.Host = viper.GetString("smtp.host")
	config.SMTP.Port = viper.GetString("smtp.port")
	config.SMTP.Username = viper.GetString("smtp.username")
	config.SMTP.Password = viper.GetString("smtp.password")
	config.Authentication.Key = viper.GetString("authentication.key")

	return nil
}
