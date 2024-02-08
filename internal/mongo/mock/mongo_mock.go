package mock

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/tryvium-travels/memongo"
	"github.com/tryvium-travels/memongo/memongolog"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// SetUpMongoServer sets up a mock mongo server
func SetUpMongoServer(test *testing.T) *memongo.Server {
	memongoOptions := &memongo.Options{
		LogLevel:     memongolog.LogLevelSilent,
		MongoVersion: "4.4.28",
	}
	mongoBinPath := os.Getenv("MONGODB_BIN")
	mongoVersion := os.Getenv("MONGO_DB_VERSION")
	if mongoVersion != "" {
		memongoOptions.MongoVersion = mongoVersion
		test.Logf("Using MongoDB version: %s", mongoVersion)
	}
	if mongoBinPath != "" {
		memongoOptions.MongodBin = fmt.Sprintf("%s/mongod", mongoBinPath)
		test.Logf("Using existing MongoDB binary at: %s", mongoBinPath)
	} else if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" {
		// Only set the custom url as workaround for arm64 macs
		memongoOptions.DownloadURL = "https://fastdl.mongodb.org/osx/mongodb-macos-x86_64-4.2.25.tgz"
		test.Logf("Using download url: %s", memongoOptions.DownloadURL)
	}
	mongoServer, err := memongo.StartWithOptions(memongoOptions)
	if err != nil {
		test.Fatalf("Failed to start mock mongo server: %v", err)
	}
	return mongoServer
}

// SetupMockMongoServerAndClient sets up a mock mongo server
func SetupMockMongoServerAndClient(test *testing.T) (*memongo.Server, *mongo.Client, error) {
	mongoServer := SetUpMongoServer(test)

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
