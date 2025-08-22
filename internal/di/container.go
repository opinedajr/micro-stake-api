package di

import (
	"gorm.io/gorm"

	"micro-stake/internal/auth"
	"micro-stake/internal/config"
	"micro-stake/internal/user/postgres"
	"micro-stake/pkg/logger"
)

// Container é o container de injeção de dependências da aplicação
type Container struct {
	config      *config.Config
	db          *gorm.DB
	logger      logger.Logger
	authService auth.AuthService
	authHandler *auth.AuthHandler
}

// NewContainer cria uma nova instância do container
func NewContainer(cfg *config.Config, db *gorm.DB, logger logger.Logger) *Container {
	return &Container{
		config: cfg,
		db:     db,
		logger: logger,
	}
}

// GetConfig retorna a configuração da aplicação
func (c *Container) GetConfig() *config.Config {
	return c.config
}

// GetDB retorna a instância do banco de dados
func (c *Container) GetDB() *gorm.DB {
	return c.db
}

// GetLogger retorna a instância do logger
func (c *Container) GetLogger() logger.Logger {
	return c.logger
}

// Métodos para obter instâncias dos serviços - serão implementados nas próximas fases
func (c *Container) GetAuthService() auth.AuthService {
	if c.authService == nil {
		repo := postgres.NewUserRepository(c.GetDB())
		c.authService = auth.NewAuthService(repo, c.GetConfig().JWT)
	}
	return c.authService
}

func (c *Container) GetAuthHandler() *auth.AuthHandler {
	if c.authHandler == nil {
		c.authHandler = auth.NewAuthHandler(c.GetAuthService())
	}
	return c.authHandler
}
