package main

import (
	"log"
	"net/http"

	"qd_authentication_api/internal/config"
	"qd_authentication_api/internal/router"
	"time"
)

func main() {
	var config config.Config
	config.Load()

	router := router.SetupRoutes(config.MongoURI)

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
