package grpcserver

import (
	"context"
	"fmt"

	"github.com/quadev-ltd/qd-common/pkg/grpcserver"
	"github.com/quadev-ltd/qd-common/pkg/log"
	commonTLS "github.com/quadev-ltd/qd-common/pkg/tls"
	"google.golang.org/grpc"

	"qd-authentication-api/internal/service"
	"qd-authentication-api/pb/gen/go/pb_authentication"
)

// Factoryer is the interfact for creating a gRPC server
type Factoryer interface {
	Create(
		grpcServerAddress string,
		authenticationService service.UserServicer,
		tokenService service.TokenServicer,
		passwordService service.PasswordServicer,
		logFactory log.Factoryer,
		tlsEnabled bool,
	) (grpcserver.GRPCServicer, error)
}

// Factory is the implementation of the gRPC server factory
type Factory struct{}

var _ Factoryer = &Factory{}

// Create creates a gRPC server
func (grpcServerFactory *Factory) Create(
	grpcServerAddress string,
	authenticationService service.UserServicer,
	tokenService service.TokenServicer,
	passwordService service.PasswordServicer,
	logFactory log.Factoryer,
	tlsEnabled bool,
) (grpcserver.GRPCServicer, error) {
	// TODO: Set domain info in the config file
	const certFilePath = "certs/qd.authentication.api.crt"
	const keyFilePath = "certs/qd.authentication.api.key"

	grpcListener, err := commonTLS.CreateTLSListener(grpcServerAddress, certFilePath, keyFilePath, tlsEnabled)
	if err != nil {
		return nil, fmt.Errorf("Failed to listen: %v", err)
	}

	// Create a gRPC server with a registered authentication service
	authenticationServiceGRPCServer := NewAuthenticationServiceServer(
		authenticationService,
		tokenService,
		passwordService,
	)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(
			chainUnaryInterceptors(
				log.CreateLoggerInterceptor(logFactory),
				AuthInterceptor(tokenService),
			),
		),
	)
	pb_authentication.RegisterAuthenticationServiceServer(grpcServer, authenticationServiceGRPCServer)
	return grpcserver.NewGRPCService(grpcServer, grpcListener), nil
}

// chainUnaryInterceptors chains multiple unary interceptors into one.
func chainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		// Build the interceptor chain
		chain := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chain
			chain = func(currentCtx context.Context, currentReq interface{}) (interface{}, error) {
				return interceptor(currentCtx, currentReq, info, next)
			}
		}

		// Execute the chain
		return chain(ctx, req)
	}
}
