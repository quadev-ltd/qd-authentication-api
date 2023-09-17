package handlers

import (
	"fmt"
	"net/http"
	"qd_authentication_api/internal/service"

	"github.com/gorilla/mux"
)

func EmailVerificationHandler(authenticationService service.AuthenticationServicer) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		verificationToken := params["verification_token"]
		resultError := authenticationService.Verify(verificationToken)
		if resultError != nil {
			http.Error(writer, fmt.Sprintf("Email verification error: %s", resultError.Error()), http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}
}
