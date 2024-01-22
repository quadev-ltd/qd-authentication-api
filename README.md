# QuaDev Authentication Service
A GRPC API and a private and public key JWT-based authentication microservice, utilizing Atlas Mongo. This is hosted on AWS ECS and secured within a AWS VPC. The gateway of this VPC is protected by JWT-based authentication.

# Set up
Set up host redirections in `/etc/hosts` file:
```
127.0.0.1    	qd.authentication.api
```
Add corresponding certificates in `/certs` folder in the root  
run `go run cmd/maing.go` to start the service.

## Tests
Gomock is used to create mocks for service unit testing, and Testify is used s assertion library and to provide a better layout and organization of test results. Mocks can easily be updated when services are changed.
For example:
```mockgen -source=email_service.go -destination=mock/email_service_mock.go -package=mock EmailService```

## Endpoint testing
End to end testing. The test suite `cmd/application/application_test.go` provides a set of end to end test to verify that the primary journeys are working correctly.
Mongo DB and SMTP server are mocked using `github.com/tryvium-travels/memongo` and `github.com/mhale/smtpd`.

## GRPC
Run `buf generate` in `/pb/` to generate the protobuf files and GRPC and GRPC Gateway implementations 
Run `buf generate --path ./google/api` if path need to be declared for imports.
Flags `-v --debug` will provide more details on the execution.
GRPC_Gateway docs:
https://medium.com/swlh/rest-over-grpc-with-grpc-gateway-for-go-9584bfcbb835

## Git Hooks
To activate commit hooks use the following command:
```git config core.hooksPath githooks/```
And make `githooks/pre-commit` executable.
To avoid running hooks do `git commit --no-verify`


##  TODOs
<!-- TODOs -->
<!--
    STUDY CONNECTION TO EMAIL SERVICE THROUGH TLS
    Add JWT at registration response
    Add unit tests
        JWTAuthenticator
        authentication_service_test.go
        GetPublicKey journey
        GenerateKeyFiles
    Test expiration dates in tokens
    Add token refresh endpooint
    Add forgot password
    Add change password
    Add reset password
    Add logout
    Add routines
    Add 2 Factor Authentication

    Refresh Token: This endpoint allows users to refresh their authentication token using a valid refresh token. It helps maintain the user's session without requiring them to log in again.

Logout: This endpoint logs the user out by invalidating their refresh token. It's useful when a user wants to sign out or when you need to manage active sessions.

Change Password: Users should be able to change their account password. This endpoint typically requires the user to provide their current password and a new password.

Forgot Password: In case a user forgets their password, this endpoint allows them to request a password reset email with a link to reset their password.

Reset Password: When a user receives a password reset email, this endpoint lets them set a new password after verifying their identity with a reset token.

Two-Factor Authentication (2FA): If your application supports 2FA, you'll need endpoints for enabling, disabling, and verifying 2FA setups.
 -->
