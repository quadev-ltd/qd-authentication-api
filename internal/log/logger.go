package log

import (
	"context"
	"errors"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
)

type Loggerer interface {
	Error(err error, message string)
	Info(message string)
	Warn(message string)
}

type Logger struct {
	logger zerolog.Logger
}

const CorrelationIdKey = "correlation_id"

func NewLogger(ctx context.Context) (Loggerer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Error().Msg("Metadata not found in context")
		return nil, errors.New("Metadata not found in context")
	}
	correlationId, exists := md[CorrelationIdKey]
	if !exists || len(correlationId) != 1 {
		log.Error().Msg("Correlation ID not found in metadata")
		return nil, errors.New("Correlation ID not found in metadata")
	}
	logger := zerolog.New(os.Stdout).With().Str(CorrelationIdKey, correlationId[0]).Logger()

	return &Logger{
		logger: logger,
	}, nil
}

func (logger *Logger) Error(err error, message string) {
	log.Error().Err(err).Msg(message)
}

func (logger *Logger) Info(message string) {
	log.Info().Msg(message)
}

func (logger *Logger) Warn(message string) {
	log.Warn().Msg(message)
}
