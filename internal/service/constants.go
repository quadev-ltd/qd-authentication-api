package service

import (
	"time"
)

// TODO: Analyse best expiry times for tokens
// Expiry times for tokens
const (
	AuthenticationTokenDuration = 30 * time.Minute   // Authentication token expiry set to 2 hours
	RefreshTokenDuration        = 7 * 24 * time.Hour // Refresh token expiry set to 7 days
	VerificationTokenExpiry     = 5 * time.Minute    // Verification token expiry set to 24 hours
	PasswordResetTokenExpiry    = 5 * time.Minute
	RefreshTokenRenewalWindow   = 12 * time.Hour // Refresh token renewal set to 7 days
)
