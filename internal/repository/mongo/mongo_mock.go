package mongo

import (
	"context"

	"github.com/benweissmann/memongo"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func SetupMockMongoServer() (*memongo.Server, *mongo.Client, error) {
	// Start mongo server
	mongoServer, err := memongo.StartWithOptions(
		&memongo.Options{
			LogLevel:     4,
			MongoVersion: "4.0.5",
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// Create a new mongo client
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoServer.URI()))
	if err != nil {
		mongoServer.Stop()
		return nil, nil, err
	}

	// Connect the mongo client
	if err := client.Connect(context.Background()); err != nil {
		client.Disconnect(context.Background())
		mongoServer.Stop()
		return nil, nil, err
	}

	return mongoServer, client, nil
}
