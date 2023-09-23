# QuaDev Authentication Service

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
    DONE: Remove handlers and create unit tests for GRPC server 
    DONE: service
    Errors and logs
    Email verification token expiry and announce if token already Email verified message and unit test
    Implement RegistrationResponse
    Add routines
 -->
