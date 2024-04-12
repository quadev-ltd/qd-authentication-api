package dto

import (
	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/util"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
)

// ConvertAuthTokensToResponse converts auth tokens to a response
func ConvertAuthTokensToResponse(authTokens *model.AuthTokensResponse) *pb_authentication.AuthenticateResponse {
	return &pb_authentication.AuthenticateResponse{
		AuthToken:          authTokens.AuthToken,
		AuthTokenExpiry:    util.ConvertToTimestamp(authTokens.AuthTokenExpiry),
		RefreshToken:       authTokens.RefreshToken,
		RefreshTokenExpiry: util.ConvertToTimestamp(authTokens.RefreshTokenExpiry),
		UserEmail:          authTokens.UserEmail,
		UserId:             authTokens.UserID,
	}
}
