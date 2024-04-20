package dto

import (
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"

	"qd-authentication-api/internal/model"
)

// ConvertAuthTokensToResponse converts auth tokens to a response
func ConvertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb_authentication.AuthenticateResponse {
	return &pb_authentication.AuthenticateResponse{
		AuthToken:    authTokens.AuthToken,
		RefreshToken: authTokens.RefreshToken,
	}
}
