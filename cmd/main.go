package main

import (
	"context"
	"log"
	"net/http"

	"qd_authentication_api/internal/config"
	mongoRepository "qd_authentication_api/internal/repository/mongo"
	"qd_authentication_api/internal/router"
	"qd_authentication_api/internal/service"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	var config config.Config
	config.Load()

	client, error := mongo.Connect(context.Background(), options.Client().ApplyURI(config.MongoURI))
	if error != nil {
		log.Fatal(error)
	}
	defer client.Disconnect(context.Background())

	userRepo := mongoRepository.NewMongoUserRepository(client)
	emailServiceConfig := service.EmailServiceConfig{
		AppName:  config.App.Name,
		BaseUrl:  config.App.BaseUrl,
		From:     config.SMTP.Username,
		Password: config.SMTP.Password,
		Host:     config.SMTP.Host,
		Port:     config.SMTP.Port,
	}
	emailService := service.NewEmailService(emailServiceConfig, &service.SmtpService{})
	authService := service.NewAuthService(emailService, userRepo)
	router := router.SetupRoutes(authService)

	// Start the HTTP server
	server := &http.Server{
		Handler:      router,
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Starting the server on :8080...")
	log.Fatal(server.ListenAndServe())
}
