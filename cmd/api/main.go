package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"micro-stake/internal/config"
	"micro-stake/internal/di"
	"micro-stake/internal/shared/database"
	"micro-stake/pkg/logger"
)

func main() {
	// Carregar configurações
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Inicializar logger
	logLevel := logger.LevelInfo
	if !cfg.IsProduction() {
		logLevel = logger.LevelDebug
	}

	appLogger := logger.New("micro-stake-api", "1.0.0", logLevel)
	appLogger.Info("Starting Micro Stake API",
		logger.String("environment", cfg.App.Environment),
		logger.String("version", "1.0.0"),
	)

	// Conectar ao banco de dados
	dbConn, err := database.NewConnection(cfg)
	if err != nil {
		appLogger.Error("Failed to connect to database", err)
		os.Exit(1)
	}
	defer func() {
		if err := dbConn.Close(); err != nil {
			appLogger.Error("Failed to close database connection", err)
		}
	}()

	// Executar migrações (será implementado quando criarmos os models)
	// if err := runMigrations(dbConn); err != nil {
	//     appLogger.Error("Failed to run migrations", err)
	//     os.Exit(1)
	// }

	// Inicializar container de dependências
	container := di.NewContainer(cfg, dbConn.GetDB(), appLogger)

	// Configurar rotas
	router := setupRoutes(container)

	// Configurar servidor HTTP
	server := &http.Server{
		Addr:         cfg.GetServerAddr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Canal para capturar sinais de sistema
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Iniciar servidor em goroutine
	go func() {
		appLogger.Info("Server starting",
			logger.String("address", cfg.GetServerAddr()),
			logger.String("environment", cfg.App.Environment),
		)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Failed to start server", err)
			os.Exit(1)
		}
	}()

	// Aguardar sinal de encerramento
	<-quit
	appLogger.Info("Server shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		appLogger.Error("Server forced to shutdown", err)
		os.Exit(1)
	}

	appLogger.Info("Server stopped gracefully")
}

func setupRoutes(container *di.Container) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"micro-stake-api","version":"1.0.0","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
	})

	// Root endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Micro Stake API - Hot Reload Confirmed! 🔥","version":"1.0.0","environment":"development"}`))
	})

	// Auth endpoints
	authHandler := container.GetAuthHandler()
	mux.HandleFunc("/api/v1/auth/signup", authHandler.SignUp)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)

	return mux
}
