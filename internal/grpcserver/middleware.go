package grpcserver

import (
	"context"
	"qd_authentication_api/internal/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type loggerKey string

// LoggerKey is the key for the logger in the context
const LoggerKey loggerKey = "logger"

func loggerInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	logger, err := log.NewLogger(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Internal server error. Dubious request")
	}
	newCtx := context.WithValue(ctx, LoggerKey, logger)
	return handler(newCtx, req)
}
