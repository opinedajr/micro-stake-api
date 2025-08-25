package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Server   ServerConfig
	App      AppConfig
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
}

type JWTConfig struct {
	Secret                string
	ExpirationHours       int
	RefreshExpirationDays int
}

type ServerConfig struct {
	Host string
	Port string
}

type AppConfig struct {
	Environment string
	RateLimit   RateLimitConfig
}

type RateLimitConfig struct {
	Requests      int
	WindowMinutes int
}

func Load() (*Config, error) {
	// Carregar variáveis de ambiente do arquivo .env se existir
	if err := godotenv.Load(); err != nil {
		// Não é um erro fatal se o arquivo .env não existir
	}

	config := &Config{
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "micro_stake_user"),
			Password: getEnv("DB_PASSWORD", "micro_stake_password"),
			Name:     getEnv("DB_NAME", "micro_stake_db"),
			SSLMode:  getEnv("DB_SSL_MODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnv("REDIS_PORT", "6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
		},
		JWT: JWTConfig{
			Secret:                getEnv("JWT_SECRET", "your-super-secret-jwt-key-here"),
			ExpirationHours:       getEnvAsInt("JWT_EXPIRATION_HOURS", 24),
			RefreshExpirationDays: getEnvAsInt("JWT_REFRESH_EXPIRATION_DAYS", 15),
		},
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
			Port: getEnv("SERVER_PORT", "8080"),
		},
		App: AppConfig{
			Environment: getEnv("ENV", "development"),
			RateLimit: RateLimitConfig{
				Requests:      getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
				WindowMinutes: getEnvAsInt("RATE_LIMIT_WINDOW_MINUTES", 1),
			},
		},
	}

	return config, nil
}

func (c *Config) GetDSN() string {
	return "host=" + c.Database.Host +
		" user=" + c.Database.User +
		" password=" + c.Database.Password +
		" dbname=" + c.Database.Name +
		" port=" + c.Database.Port +
		" sslmode=" + c.Database.SSLMode +
		" TimeZone=UTC"
}

func (c *Config) GetRedisAddr() string {
	return c.Redis.Host + ":" + c.Redis.Port
}

func (c *Config) GetServerAddr() string {
	return c.Server.Host + ":" + c.Server.Port
}

func (c *Config) GetJWTExpiration() time.Duration {
	return time.Duration(c.JWT.ExpirationHours) * time.Hour
}

func (c *Config) GetJWTRefreshExpiration() time.Duration {
	return time.Duration(c.JWT.RefreshExpirationDays) * 24 * time.Hour
}

func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
