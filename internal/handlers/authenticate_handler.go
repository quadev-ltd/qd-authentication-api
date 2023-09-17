package handlers

import (
	// TODO delete io/ioutil dependency
	"io/ioutil"
	"net/http"
	"qd_authentication_api/internal/model"
	"qd_authentication_api/internal/pb"
	"qd_authentication_api/internal/service"

	// TODO delete github.com/golang/protobuf/proto dependency
	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/protobuf/proto"
)

func AuthenticateHandler(authenticationService service.AuthenticationServicer) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var userPb pb.AuthenticateRequest

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if err := proto.Unmarshal(body, &userPb); err != nil {
			http.Error(writer, "Invalid request payload", http.StatusBadRequest)
			return
		}

		authTokens, err := authenticationService.Authenticate(userPb.Email, userPb.Password)
		if err != nil {
			handleAuthenticationError(writer, err)
			return
		}

		authenticateResponse := *convertAuthTokensToResponse(authTokens)

		authTokensProto, err := proto.Marshal(&authenticateResponse)
		if err != nil {
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}

		writer.Header().Set("Content-Type", "application/protobuf")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(authTokensProto)
	}
}

func handleAuthenticationError(writer http.ResponseWriter, err error) {
	var statusCode int
	var errorMessage string

	switch err.(type) {
	case *model.WrongEmailOrPassword:
		statusCode = http.StatusUnauthorized
		errorMessage = "Invalid email or password"
	default:
		statusCode = http.StatusInternalServerError
		errorMessage = "Internal server error"
	}

	http.Error(writer, errorMessage, statusCode)
}

func convertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb.AuthenticateResponse {
	return &pb.AuthenticateResponse{
		AuthToken: authTokens.AuthToken,
		AuthTokenExpiry: &timestamp.Timestamp{
			Seconds: authTokens.AuthTokenExpiry.Unix(),
			Nanos:   int32(authTokens.AuthTokenExpiry.Nanosecond()),
		},
		RefreshToken: authTokens.RefreshToken,
		RefreshTokenExpiry: &timestamp.Timestamp{
			Seconds: authTokens.RefreshTokenExpiry.Unix(),
			Nanos:   int32(authTokens.RefreshTokenExpiry.Nanosecond()),
		},
		UserEmail: authTokens.UserEmail,
	}
}
