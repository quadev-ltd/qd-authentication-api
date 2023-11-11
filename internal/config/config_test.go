package config

import (
	"os"
	"testing"

	pkgConfig "github.com/gustavo-m-franco/qd-common/pkg/config"
	"github.com/stretchr/testify/assert"
)

const (
	MockConfigPath = "./"
)

func TestLoad(t *testing.T) {
	// Setup
	cfg := &Config{}
	os.Setenv(pkgConfig.AppEnvironmentKey, "test")
	os.Setenv(pkgConfig.VerboseKey, "false")

	defer os.Unsetenv(pkgConfig.AppEnvironmentKey)
	defer os.Unsetenv(pkgConfig.VerboseKey)

	err := cfg.Load(MockConfigPath)
	assert.NoError(t, err, "expected no error from Load")

	// Assertions
	assert.Equal(t, "QuaDevAuthenticationTest", cfg.App)
	assert.Equal(t, "test_key", cfg.AuthenticationKey)
	assert.Equal(t, "http://localhost:2222/", cfg.EmailVerificationEndpoint)
	assert.Equal(t, "localhost", cfg.GRPC.Host)
	assert.Equal(t, "mongodb+srv://password:user@cluster.test.mongodb.net/test", cfg.DB.URI)
	assert.Equal(t, "3333", cfg.GRPC.Port)
	assert.Equal(t, "localhost", cfg.Email.Host)
	assert.Equal(t, "1111", cfg.Email.Port)

	assert.False(t, cfg.Verbose)
	assert.Equal(t, "test", cfg.Environment)
}
