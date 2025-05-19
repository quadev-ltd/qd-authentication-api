package model

import "time"

// AuthTokensResponse is the response object for the auth tokens endpoint
type AuthTokensResponse struct {
	AuthToken          string    `json:"authToken"`
	AuthTokenExpiry    time.Time `json:"authTokenExpiry"`
	RefreshToken       string    `json:"refreshToken"`
	RefreshTokenExpiry time.Time `json:"refreshTokenExpiry"`
	UserEmail          string    `json:"userEmail"`
	UserID             string    `json:"userID"`
	FirebaseToken      string    `json:"firebaseToken"`
}
