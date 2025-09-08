package http

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acecasino/account_manage/internal/config"
	"github.com/acecasino/account_manage/internal/presentation/http/middleware"
	"github.com/acecasino/account_manage/internal/presentation/http/routes"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
	"gorm.io/gorm"
)

// Server represents the HTTP server
type Server struct {
	config *config.Config
	server *echo.Echo
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config) *Server {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	return &Server{
		config: cfg,
		server: e,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Create database connection
	var db *gorm.DB
	db, err := config.NewDatabase(s.config.Database)
	if err != nil {
		logger.GetLogger().Fatal("Failed to connect to database: %v", err)
		return err
	}

	// Setup routes
	routes.SetupRoutes(s.server, s.config, db)

	// Start server
	port := s.config.Server.Port
	if port == "" {
		port = "8080"
	}

	logger.GetLogger().Infof("Starting server on port %s", port)

	// Graceful shutdown
	go func() {
		if err := s.server.Start(":" + port); err != nil && err != http.ErrServerClosed {
			logger.GetLogger().Fatal("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.GetLogger().Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		logger.GetLogger().Fatal("Server forced to shutdown: %v", err)
	}

	logger.GetLogger().Info("Server exited")
	return nil
}
