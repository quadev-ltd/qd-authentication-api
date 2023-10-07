# QuaDev Authentication Service
A GRPC API and a JWT-based authentication microservice, utilizing Atlas Mongo. This is hosted on AWS ECS and secured within a AWS VPC. The gateway of this VPC is protected by JWT-based authentication.

## Tests
Gomock is used to create mocks for service unit testing. Mocks can easily be updated when services are changed.
For example:
```mockgen -source=email_service.go -destination=mock/email_service_mock.go -package=mock EmailService```

## Endpoint testing
To test the requests we use curl reuests. In the folder `/Users/GFC01/Documents/qd-authentication-api/internal/pb/endpoint_test` the binary data for the request body is creted and then it is used for the curl request as in the following:
```
curl -X POST -H "Content-Type: application/protobuf" --data-binary @test.bin http://localhost:8080/register
```

## GRPC
Run `buf generate` in `/pb/` to generate the protobuf files and GRPC and GRPC Gateway implementations 
Run `buf generate --path ./google/api` if path need to be declared for imports.
Flags `-v --debug` will provide more details on the execution.
GRPC_Gateway docs:
https://medium.com/swlh/rest-over-grpc-with-grpc-gateway-for-go-9584bfcbb835
<!-- TODOs -->
<!--
    Add JWT at registration response
    Add unit tests
        JWTAuthenticator
        authentication_service_test.go
    Test expiration dates in tokens
    Errors and logs
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
