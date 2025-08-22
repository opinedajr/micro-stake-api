package database

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"micro-stake/internal/config"
)

type Connection struct {
	DB *gorm.DB
}

func NewConnection(cfg *config.Config) (*Connection, error) {
	// Configurar logger do GORM baseado no ambiente
	var gormLogger logger.Interface
	if cfg.IsProduction() {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Configuração do GORM
	gormConfig := &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	// Conectar ao banco de dados
	db, err := gorm.Open(postgres.Open(cfg.GetDSN()), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configurar pool de conexões
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configurações do pool de conexões
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Testar conexão
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Database connection established successfully")

	return &Connection{DB: db}, nil
}

func (c *Connection) Close() error {
	sqlDB, err := c.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	return sqlDB.Close()
}

func (c *Connection) GetDB() *gorm.DB {
	return c.DB
}

// Método para executar migrações
func (c *Connection) AutoMigrate(models ...interface{}) error {
	return c.DB.AutoMigrate(models...)
}

// Método para verificar saúde da conexão
func (c *Connection) HealthCheck() error {
	sqlDB, err := c.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	return sqlDB.Ping()
}
