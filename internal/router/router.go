package router

import (
	"context"
	"log"
	"qd_authentication_api/internal/handlers"
	mongoRepository "qd_authentication_api/internal/repository/mongo"
	"qd_authentication_api/internal/service"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func SetupRoutes(mongoURI string) *mux.Router {
	client, error := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURI))
	if error != nil {
		log.Fatal(error)
	}
	defer client.Disconnect(context.Background())

	userRepo := mongoRepository.NewMongoUserRepository(client)
	authService := service.NewAuthService(userRepo)

	router := mux.NewRouter()

	router.HandleFunc("/register", handlers.RegisterHandler(authService)).Methods("POST")

	return router
}
