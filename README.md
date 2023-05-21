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