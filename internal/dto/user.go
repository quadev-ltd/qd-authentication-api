package dto

import (
	"time"

	"qd-authentication-api/internal/model"
	"qd-authentication-api/internal/util"

	"github.com/quadev-ltd/qd-common/pb/gen/go/pb_authentication"
)

// GetAccountStatusDescription returns the description of the account status
func GetAccountStatusDescription(accountStatus model.AccountStatus) string {
	switch accountStatus {
	case model.AccountStatusUnverified:
		return "AccountStatusUnverified"
	case model.AccountStatusVerified:
		return "AccountStatusVerified"
	default:
		return "Unknown"
	}
}

// ConvertUserToUserDTO converts a user to a user DTO
func ConvertUserToUserDTO(user *model.User) *pb_authentication.User {
	return &pb_authentication.User{
		UserID:           user.ID.Hex(),
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		AccountStatus:    GetAccountStatusDescription(user.AccountStatus),
		RegistrationDate: util.ConvertToTimestamp(user.RegistrationDate),
		DateOfBirth:      util.ConvertToTimestamp(user.DateOfBirth),
	}
}

// ProfileDetails is a DTO for user profile details
type ProfileDetails struct {
	ID          string
	FirstName   string
	LastName    string
	DateOfBirth *time.Time
}
