package mock

import (
	"context"
	"runtime"

	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SetupMockMongoServer sets up a mock mongo server
func SetupMockMongoServer() (*memongo.Server, *mongo.Client, error) {
	memongoOptions := &memongo.Options{
		LogLevel:     4,
		MongoVersion: "4.0.5",
	}
	if runtime.GOARCH == "arm64" {
		if runtime.GOOS == "darwin" {
			// Only set the custom url as workaround for arm64 macs
			memongoOptions.DownloadURL = "https://fastdl.mongodb.org/osx/mongodb-macos-x86_64-5.0.0.tgz"
		}
	}
	mongoServer, err := memongo.StartWithOptions(memongoOptions)
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
