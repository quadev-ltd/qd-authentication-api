package service

import (
	"time"
)

// TODO: Analyse best expiry times for tokens
// Expiry times for tokens
const (
	AuthenticationTokenExpiry = 2 * time.Hour      // Authentication token expiry set to 2 hours
	RefreshTokenExpiry        = 7 * 24 * time.Hour // Refresh token expiry set to 7 days
	VerificationTokenExpiry   = 24 * time.Hour     // Verification token expiry set to 24 hours
	PasswordResetTokenExpiry  = 20 * time.Minute
	RefreshTokenRenewalWindow = 12 * time.Hour // Refresh token renewal set to 7 days
)
