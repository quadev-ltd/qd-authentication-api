package router

import (
	"qd_authentication_api/internal/handlers"
	"qd_authentication_api/internal/service"

	"github.com/gorilla/mux"
)

func SetupRoutes(authenticationService *service.AuthenticationService) *mux.Router {

	router := mux.NewRouter()

	router.HandleFunc("/register", handlers.RegisterHandler(authenticationService)).Methods("POST")

	router.HandleFunc("/verify/{verification_token}", handlers.EmailVerificationHandler(authenticationService)).Methods("GET")

	router.HandleFunc("/authenticate", handlers.AuthenticateHandler(authenticationService)).Methods("POST")

	return router
}
