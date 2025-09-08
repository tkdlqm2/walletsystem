package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/viper"
)

// 기존 config.go 파일에 추가
type DepositProcessingConfig struct {
	BatchSize          int           `yaml:"batch_size" env:"DEPOSIT_BATCH_SIZE" envDefault:"100"`
	ProcessingInterval time.Duration `yaml:"processing_interval" env:"DEPOSIT_PROCESSING_INTERVAL" envDefault:"10s"`
	MaxRetries         int           `yaml:"max_retries" env:"DEPOSIT_MAX_RETRIES" envDefault:"3"`
	Timeout            time.Duration `yaml:"timeout" env:"DEPOSIT_TIMEOUT" envDefault:"5m"`
	EnableScheduler    bool          `yaml:"enable_scheduler" env:"DEPOSIT_ENABLE_SCHEDULER" envDefault:"true"`
}

// Config holds all configuration for our application
type Config struct {
	Server            ServerConfig
	Database          DatabaseConfig
	Blockchain        BlockchainConfig
	Notification      NotificationConfig
	Logging           LoggingConfig
	Crypto            CryptoConfig
	AWS               AWSConfig
	DepositProcessing DepositProcessingConfig `yaml:"deposit_processing"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port string
	Host string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

// BlockchainConfig holds blockchain configuration
type BlockchainConfig struct {
	Ethereum EthereumConfig
	Tron     TronConfig
}

// EthereumConfig holds Ethereum specific configuration
type EthereumConfig struct {
	RpcURL string
}

// TronConfig holds TRON specific configuration
type TronConfig struct {
	RpcURL         string
	UsdtAddress    string
	SendToken      string
	TrongridAPIKey string
}

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	Telegram TelegramConfig
}

// TelegramConfig holds Telegram specific configuration
type TelegramConfig struct {
	BotToken string
	ChatID   string
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string
	Format string
	Dir    string
}

// CryptoConfig holds crypto configuration
type CryptoConfig struct {
	Passphrase string
	Seed       string
	Salt       string
}

// AWSConfig holds AWS configuration
type AWSConfig struct {
	SecretID string
	KeyAlias string
}

// LoadConfig loads configuration from YAML file or environment variables
func LoadConfig() *Config {
	// Try to load from YAML file first
	if config, err := LoadConfigFromYAML(); err == nil {
		return config
	}

	// Fallback to environment variables
	return LoadConfigFromEnv()
}

// LoadConfigFromYAML loads configuration from YAML file
func LoadConfigFromYAML() (*Config, error) {
	viper.SetConfigName("config.dev")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("../configs")
	viper.AddConfigPath("../../configs")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Override with environment variables if they exist
	overrideWithEnvVars(&config)

	return &config, nil
}

// overrideWithEnvVars overrides config values with environment variables if they exist
func overrideWithEnvVars(config *Config) {
	// Database overrides
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		config.Database.Password = password
	}
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() *Config {
	return &Config{
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT", "8080"),
			Host: getEnv("SERVER_HOST", "localhost"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_URL", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", "password"),
			Database: getEnv("DB_DATABASE", "account_manage"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Blockchain: BlockchainConfig{
			Ethereum: EthereumConfig{
				RpcURL: getEnv("ETHEREUM_RPC_URL", ""),
			},
			Tron: TronConfig{
				RpcURL:         getEnv("TRON_RPC_URL", ""),
				UsdtAddress:    getEnv("TRON_USDT_ADDR", ""),
				SendToken:      getEnv("SEND_TOKEN", ""),
				TrongridAPIKey: getEnv("TRONGRID_API_KEY", ""),
			},
		},
		Notification: NotificationConfig{
			Telegram: TelegramConfig{
				BotToken: getEnv("TELEGRAM_BOT_TOKEN", ""),
				ChatID:   getEnv("TELEGRAM_BOT_MESSAGE_GROUP", ""),
			},
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "text"),
			Dir:    getEnv("LOG_DIR", "./logs"),
		},
		Crypto: CryptoConfig{
			Passphrase: getEnv("CRYPTO_PASSPHRASE", ""),
			Seed:       getEnv("SEED", ""),
			Salt:       getEnv("SALT", ""),
		},
		AWS: AWSConfig{
			SecretID: getEnv("SECRETID", ""),
			KeyAlias: getEnv("KEYALIAS", ""),
		},
	}
}

// getEnv gets an environment variable with a fallback value
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvAsInt gets an environment variable as integer with a fallback value
func getEnvAsInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}
