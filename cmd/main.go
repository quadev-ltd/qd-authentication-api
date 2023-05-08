package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"qd_authentication_api/internal/config"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	var config config.Config
	config.Load()

	// Create a MongoDB client and collection
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.MongoURI))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Print out database and collection information
	// dbInfo, err := client.ListDatabaseNames(context.Background(), nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("Connected to MongoDB. Databases: %v\n", dbInfo)

	// Start the HTTP server
	server := &http.Server{
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Starting the server on :8080...")
	log.Fatal(server.ListenAndServe())
}
