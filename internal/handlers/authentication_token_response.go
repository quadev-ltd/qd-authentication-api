package handlers

import "time"

type AuthTokensResponse struct {
	AuthToken          string    `json:"auth_token"`
	AuthTokenExpiry    time.Time `json:"auth_token_expiry"`
	RefreshToken       string    `json:"refresh_token"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
	UserEmail          string    `json:"user_email"`
}
