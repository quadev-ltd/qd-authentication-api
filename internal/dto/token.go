package dto

import (
	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/util"
)

// ConvertAuthTokensToResponse converts auth tokens to a response
func ConvertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb_authentication.AuthenticateResponse {
	return &pb_authentication.AuthenticateResponse{
		AuthToken:          authTokens.AuthToken,
		AuthTokenExpiry:    util.ConvertToTimestamp(authTokens.AuthTokenExpiry),
		RefreshToken:       authTokens.RefreshToken,
		RefreshTokenExpiry: util.ConvertToTimestamp(authTokens.RefreshTokenExpiry),
		UserEmail:          authTokens.UserEmail,
		UserID:             authTokens.UserID,
	}
}
