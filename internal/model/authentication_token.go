package model

import "time"

// AuthTokensResponse is the response object for the auth tokens endpoint
type AuthTokensResponse struct {
	AuthToken          string    `json:"auth_token"`
	AuthTokenExpiry    time.Time `json:"auth_token_expiry"`
	RefreshToken       string    `json:"refresh_token"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
	UserEmail          string    `json:"user_email"`
}
