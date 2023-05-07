package main

import (
	"context"
	"fmt"
	"log"

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
		fmt.Printf("Error connecting to the Cluster: %v", err)
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Check if the connection is still alive
	err = client.Ping(context.Background(), nil)
	if err != nil {
		fmt.Printf("Error Pinging Cluster: %v", err)
		log.Fatal(err)
	}

	// Print out database and collection information
	dbInfo, err := client.ListDatabaseNames(context.Background(), nil)
	if err != nil {
		fmt.Printf("Error getting the list of DBs available: %v", err)
		log.Fatal(err)
	}
	fmt.Printf("Connected to MongoDB. Databases: %v\n", dbInfo)
}
