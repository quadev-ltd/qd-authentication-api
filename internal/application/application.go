package application

import (
	"fmt"

	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/quadev-ltd/qd-common/pkg/grpcserver"
	"github.com/quadev-ltd/qd-common/pkg/log"

	"qd-authentication-api/internal/config"
	"qd-authentication-api/internal/firebase"
	grpcFactory "qd-authentication-api/internal/grpcserver"
	"qd-authentication-api/internal/service"
)

// Applicationer provides the main functions to start the application
type Applicationer interface {
	StartServer()
	Close()
	GetGRPCServerAddress() string
}

// Application is the main application
type Application struct {
	grpcServiceServer grpcserver.GRPCServicer
	grpcServerAddress string
	service           service.Managerer
	logger            log.Loggerer
}

// NewApplication creates a new application
func NewApplication(
	config *config.Config,
	centralConfig *commonConfig.Config,
	firebaseService firebase.AuthServicer,
) Applicationer {
	logFactory := log.NewLogFactory(config.Environment)
	logger := logFactory.NewLogger()
	if centralConfig.TLSEnabled {
		logger.Info("TLS is enabled")
	} else {
		logger.Info("TLS is disabled")
	}

	serviceManager, err := (&service.Factory{}).CreateServiceManager(config, centralConfig, firebaseService)
	if err != nil {
		logger.Error(err, "Failed to create authentication service")
		return nil
	}

	grpcServerAddress := fmt.Sprintf(
		"%s:%s",
		centralConfig.AuthenticationService.Host,
		centralConfig.AuthenticationService.Port,
	)
	grpcServiceServer, err := (&grpcFactory.Factory{}).Create(
		grpcFactory.Config{
			GRPCServerAddress: grpcServerAddress,
			TLSEnabled:        centralConfig.TLSEnabled,
		},
		serviceManager,
		logFactory,
	)

	if err != nil {
		logger.Error(err, "Failed to create GRPC Service Server")
		return nil
	}

	return New(grpcServiceServer, grpcServerAddress, serviceManager, logger)
}

// New creates a new application with raw parameters
func New(grpcServiceServer grpcserver.GRPCServicer, grpcServerAddress string, service service.Managerer, logger log.Loggerer) Applicationer {
	return &Application{
		grpcServiceServer: grpcServiceServer,
		grpcServerAddress: grpcServerAddress,
		service:           service,
		logger:            logger,
	}
}

// StartServer starts the gRPC server
func (application *Application) StartServer() {
	application.logger.Info(fmt.Sprintf("Starting gRPC server on %s:...", application.grpcServerAddress))
	err := application.grpcServiceServer.Serve()
	if err != nil {
		application.logger.Error(err, "Failed to serve grpc server")
	}
}

// Close closes the gRPC server and services used by the application
func (application *Application) Close() {
	switch {
	case application.service == nil:
		application.logger.Error(nil, "Service is not created")
		return
	case application.grpcServiceServer == nil:
		application.logger.Error(nil, "gRPC server is not created")
		return
	}
	application.service.Close()
	application.grpcServiceServer.Close()
	application.logger.Info("Application closed")
}

// GetGRPCServerAddress returns the gRPC server address
func (application *Application) GetGRPCServerAddress() string {
	return application.grpcServerAddress
}
