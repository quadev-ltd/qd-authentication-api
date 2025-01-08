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

## Hooks: Linting and formatting
To enable linting and formatting on each commit we use the following dependencies:
```
golang.org/x/tools/cmd/goimports@latest
golang.org/x/lint/golint@latest
```
To activate commit hooks use the following command:
```git config core.hooksPath githooks/```
And make `githooks/pre-commit` executable.
To avoid running hooks do `git commit --no-verify`

## GRPC
To generate the grpc code:
- Follow the steps in https://buf.build/docs/installation to install buf.
- Install protoc dependencies in your local:
```bash
GO111MODULE=off go get google.golang.org/grpc/cmd/protoc-gen-go-grpc
GO111MODULE=off go get google.golang.org/protobuf/cmd/protoc-gen-go
```
- In the root of the repository, run `git submodule update --init --recursive`.
- Then, in `/pb/`, run `buf generate` to generate the protobuf files.  
> note: Flags `-v --debug` will provide more details on the execution.



<!-- TODOs -->
<!--
    Refactor register (devide into parts)
    Change name of EmailVerification variable
    Add routines
    Add 2 Factor Authentication


Logout: This endpoint logs the user out by invalidating their refresh token. It's useful when a user wants to sign out or when you need to manage active sessions.

 -->
