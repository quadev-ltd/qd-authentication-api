package config

import (
	"os"
	"testing"

	"github.com/quadev-ltd/qd-common/pkg/config"
	pkgConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/stretchr/testify/assert"
)

const (
	MockConfigPath = "./"
)

func TestLoad(t *testing.T) {
	t.Run("Load_Should_Show_File_Values_If_No_Env_Vars", func(t *testing.T) {
		// Setup
		cfg := &Config{}
		os.Setenv(pkgConfig.AppEnvironmentKey, "test")
		os.Setenv(pkgConfig.VerboseKey, "false")

		defer os.Unsetenv(pkgConfig.AppEnvironmentKey)
		defer os.Unsetenv(pkgConfig.VerboseKey)

		err := cfg.Load(MockConfigPath)
		assert.NoError(t, err, "expected no error from Load")

		// Assertions
		assert.Equal(t, "test_key", cfg.AuthenticationKey)
		assert.Equal(t, "mongodb+srv://password:user@cluster.test.mongodb.net/test", cfg.AuthenticationDB.URI)
		assert.Equal(t, "key", cfg.AWS.Key)
		assert.Equal(t, "secret", cfg.AWS.Secret)
		assert.Equal(t, "internal/firebase/firebase-service-account-dev.json", cfg.Firebase.ConfigPath)

		assert.False(t, cfg.Verbose)
		assert.Equal(t, "test", cfg.Environment)
	})

	t.Run("Load_Should_Show_Env_Vars_Values", func(t *testing.T) {
		// Setup
		cfg := &Config{}
		os.Setenv(config.AppEnvironmentKey, "test")
		os.Setenv(config.VerboseKey, "false")
		os.Setenv("TEST_ENV_AUTHENTICATION_KEY", "test_key_env")
		os.Setenv("TEST_ENV_AUTHENTICATION_DB_URI", "mongodb://pwd:user@cluster.net/test_env")
		os.Setenv("TEST_ENV_AWS_KEY", "aws_key_env")
		os.Setenv("TEST_ENV_AWS_SECRET", "aws_secret_env")
		os.Setenv("TEST_ENV_FIREBASE_CONFIG_PATH", "firebase_config_path")

		defer os.Unsetenv(config.AppEnvironmentKey)
		defer os.Unsetenv(config.VerboseKey)
		defer os.Unsetenv("TEST_ENV_AUTHENTICATION_KEY")
		defer os.Unsetenv("TEST_ENV_AUTHENTICATION_DB_URI")
		defer os.Unsetenv("TEST_ENV_AWS_KEY")
		defer os.Unsetenv("TEST_ENV_AWS_SECRET")
		defer os.Unsetenv("TEST_ENV_FIREBASE_CONFIG_PATH")

		err := cfg.Load(MockConfigPath)
		assert.NoError(t, err, "expected no error from Load")

		// Assertions
		assert.Equal(t, "test_key_env", cfg.AuthenticationKey)
		assert.Equal(t, "mongodb://pwd:user@cluster.net/test_env", cfg.AuthenticationDB.URI)
		assert.Equal(t, "aws_key_env", cfg.AWS.Key)
		assert.Equal(t, "aws_secret_env", cfg.AWS.Secret)
		assert.Equal(t, "firebase_config_path", cfg.Firebase.ConfigPath)

		assert.False(t, cfg.Verbose)
		assert.Equal(t, "test", cfg.Environment)
	})
}
