package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/appconfigdata"
	commonAWS "github.com/quadev-ltd/qd-common/pkg/aws"
	commonConfig "github.com/quadev-ltd/qd-common/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type address struct {
	Host string
	Port string
}

type smtp struct {
	Host     string
	Port     string
	Username string
	Password string
}

type db struct {
	URI string
}

// Config is the configuration of the application
type Config struct {
	Verbose           bool
	Environment       string
	App               string
	AuthenticationKey string `mapstructure:"authentication_key"`
	AuthenticationDB  db     `mapstructure:"authentication_db"`
	AWS               commonAWS.AWSConfig
}

// Load loads the configuration from the given path yml file
func (config *Config) Load(path string) error {
	env := os.Getenv(commonConfig.AppEnvironmentKey)
	if env == "" {
		env = commonConfig.LocalEnvironment
	}
	config.Environment = env

	// Set the file name of the configurations file (if any)
	viper.SetConfigName(fmt.Sprintf("config.%s", env))
	viper.SetConfigType("yml")
	viper.AddConfigPath(path)

	// Bind environment variables (if any, they take priority)
	prefix := fmt.Sprintf("%s_ENV", strings.ToUpper(env))
	viper.AutomaticEnv()
	viper.SetEnvPrefix(prefix)                             // replace YOUR_PREFIX with your actual prefix
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // Replace dots with underscores in env var names

	// Read the configuration file
	err := viper.ReadInConfig()
	if err != nil {
		log.Err(fmt.Errorf("Error loading configuration file: %v", err))
	}

	generalConfigData := config.Test()
	configReader := bytes.NewReader(generalConfigData)
	// Merge the AWS AppConfig data into your local configuration
	if err := viper.MergeConfig(configReader); err != nil {
		fmt.Println("Error merging AWS AppConfig data:", err)
	}

	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("Error unmarshaling configuration: %v", err)
	}

	if os.Getenv(commonConfig.VerboseKey) == "true" {
		config.Verbose = true
	} else {
		config.Verbose = false
	}

	return nil
}

func (config *Config) Test() []byte {
	sess, _ := session.NewSession(
		&aws.Config{
			Region: aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials(
				"AKIARWDSJ2CMK4KP3ASZ",
				"uhkUFmC8GhY8Y+pjRFTnYHLp/bItt44toRKiL3ul",
				"",
			),
		},
	)

	svc := appconfigdata.New(sess)

	startSessionOutput, _ := svc.StartConfigurationSession(
		&appconfigdata.StartConfigurationSessionInput{
			ApplicationIdentifier:          aws.String("222hh4s"),
			EnvironmentIdentifier:          aws.String("i0lf5xh"),
			ConfigurationProfileIdentifier: aws.String("mfgfaot"),
		},
	)

	latestConfigOutput, err := svc.GetLatestConfiguration(&appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: startSessionOutput.InitialConfigurationToken,
	})

	if err != nil {
		fmt.Println("Error fetching configuration:", err)
		return nil
	}

	// Process configuration data (e.g., set environment variables)
	configData := latestConfigOutput.Configuration
	return configData
}
