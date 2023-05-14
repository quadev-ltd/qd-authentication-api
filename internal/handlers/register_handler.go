package handlers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/pb"
	"qd_authentication_api/internal/service"
	"time"

	"github.com/go-playground/validator/v10"
	"google.golang.org/protobuf/proto"
)

func RegisterHandler(authService service.AuthServicer) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		var userPb pb.RegisterRequest

		bodyBytes, error := ioutil.ReadAll(request.Body)
		if error != nil {
			http.Error(writer, fmt.Sprintf("Error trying to read request body: %s", error.Error()), http.StatusBadRequest)
			return
		}

		error = proto.Unmarshal(bodyBytes, &userPb)
		if error != nil {
			http.Error(writer, fmt.Sprintf("Error trying to unmarshal the body: %s", error.Error()), http.StatusBadRequest)
			return
		}

		// Convert google.protobuf.Timestamp to time.Time
		dateOfBirth := time.Unix(userPb.DateOfBirth.GetSeconds(), int64(userPb.DateOfBirth.GetNanos()))
		error = authService.Register(userPb.Email, userPb.Password, userPb.FirstName, userPb.LastName, &dateOfBirth)
		if error != nil {
			_, isValidationError := error.(validator.ValidationErrors)
			if isValidationError {
				http.Error(writer, fmt.Sprintf("Register error: %s", error.Error()), http.StatusBadRequest)
				return
			}
			if _, isEmailInUseError := error.(*model.EmailInUseError); isEmailInUseError {
				http.Error(writer, fmt.Sprintf("Register error: %s", error.Error()), http.StatusBadRequest)
				return
			}
			http.Error(writer, fmt.Sprintf("Register error: %s", error.Error()), http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}
}
