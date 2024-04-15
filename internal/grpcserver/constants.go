package grpcserver

// GRPC Method keys
const (
	GetPublicKeyMethod             = "GetPublicKey"
	RegisterMethod                 = "Register"
	VerifyEmailMethod              = "VerifyEmail"
	AuthenticateMethod             = "Authenticate"
	ForgotPasswordMethod           = "ForgotPassword"
	ResetPasswordMethod            = "ResetPassword"
	VerifyResetPasswordTokenMethod = "VerifyResetPasswordToken"
	RefreshTokenMethod             = "RefreshToken"
	ResendEmailVerificationMethod  = "ResendEmailVerification"
	GetUserProfileMethod           = "GetUserProfile"
	UpdateUserProfileMethod        = "UpdateUserProfile"
)

// PublicMethods are GRPC public method routes
var PublicMethods = map[string]string{
	GetPublicKeyMethod:             "/pb_authentication.AuthenticationService/GetPublicKey",
	RegisterMethod:                 "/pb_authentication.AuthenticationService/Register",
	VerifyEmailMethod:              "/pb_authentication.AuthenticationService/VerifyEmail",
	ResendEmailVerificationMethod:  "/pb_authentication.AuthenticationService/ResendEmailVerification",
	AuthenticateMethod:             "/pb_authentication.AuthenticationService/Authenticate",
	ForgotPasswordMethod:           "/pb_authentication.AuthenticationService/ForgotPassword",
	ResetPasswordMethod:            "/pb_authentication.AuthenticationService/ResetPassword",
	VerifyResetPasswordTokenMethod: "/pb_authentication.AuthenticationService/VerifyResetPasswordToken",
}

// PublicMethodsArray is an array of GRPC public method routes
func PublicMethodsArray() []string {
	var arr []string
	for _, v := range PublicMethods {
		arr = append(arr, v)
	}
	return arr
}

// AuthenticatedMethods are GRPC authenticated method routes
var AuthenticatedMethods = map[string]string{
	RefreshTokenMethod:      "/pb_authentication.AuthenticationService/RefreshToken",
	GetUserProfileMethod:    "/pb_authentication.AuthenticationService/GetUserProfile",
	UpdateUserProfileMethod: "/pb_authentication.AuthenticationService/UpdateUserProfile",
}
