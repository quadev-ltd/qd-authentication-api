package log

import (
	"context"
	"errors"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/metadata"
)

// Loggerer is the interface of the logger
type Loggerer interface {
	Error(err error, message string)
	Info(message string)
	Warn(message string)
}

// Logger is the logger of the application
type Logger struct {
	logger zerolog.Logger
}

// CorrelationIDKey is the key of the correlation ID in the metadata
const CorrelationIDKey = "correlation_id"

// NewLogger creates a new logger from the context
func NewLogger(ctx context.Context) (Loggerer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Error().Msg("Metadata not found in context")
		return nil, errors.New("Metadata not found in context")
	}
	correlationID, exists := md[CorrelationIDKey]
	if !exists || len(correlationID) != 1 {
		log.Error().Msg("Correlation ID not found in metadata")
		return nil, errors.New("Correlation ID not found in metadata")
	}
	logger := zerolog.New(os.Stdout).With().Str(CorrelationIDKey, correlationID[0]).Logger()

	return &Logger{
		logger: logger,
	}, nil
}

// Error logs an error
func (logger *Logger) Error(err error, message string) {
	log.Error().Err(err).Msg(message)
}

// Info logs an info
func (logger *Logger) Info(message string) {
	log.Info().Msg(message)
}

// Warn logs a warning
func (logger *Logger) Warn(message string) {
	log.Warn().Msg(message)
}
