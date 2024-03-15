package grpcserver

import (
	"context"
	"strings"

	commonJWT "github.com/quadev-ltd/qd-common/pkg/jwt"
	commonToken "github.com/quadev-ltd/qd-common/pkg/token"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	servicePkg "qd-authentication-api/internal/service"
)

// Attach claims to context
func NewContextWithClaims(ctx context.Context, claims *commonJWT.TokenClaims) context.Context {
	return context.WithValue(ctx, commonJWT.ClaimsContextKey, claims)
}

// AuthInterceptor is a middleware for authentication and authorization
func AuthInterceptor(tokenService servicePkg.TokenServicer) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication for public methods
		publicMethods := PublicMethodsArray()
		for _, publicMethod := range publicMethods {
			if info.FullMethod == publicMethod {
				return handler(ctx, req)
			}
		}

		claims, err := validateToken(ctx, tokenService)
		if err != nil {
			return nil, err
		}
		if info.FullMethod == AuthenticatedMethods[RefreshTokenMethod] &&
			claims.Type != commonToken.RefreshTokenType {
			return nil, status.Errorf(codes.Unauthenticated, "Not a refresh token")
		}

		// Attach claims to context
		ctxWithClaims := NewContextWithClaims(ctx, claims)

		// Continue with the handler if token is valid
		return handler(ctxWithClaims, req)
	}
}

func validateToken(ctx context.Context, tokenService servicePkg.TokenServicer) (*commonJWT.TokenClaims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "Metadata not found in request")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "Authorization token not provided")
	}

	token := values[0]
	token = strings.TrimPrefix(token, "Bearer ")

	// Call your existing token verification logic here
	claims, err := tokenService.VerifyJWTToken(ctx, token)
	if err != nil {
		if _, ok := err.(*servicePkg.Error); ok {
			return nil, status.Errorf(codes.Unauthenticated, err.Error())
		}
		return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired token")
	}

	return claims, nil
}
