package routes

import (
	"github.com/acecasino/account_manage/internal/config"
	"github.com/acecasino/account_manage/internal/presentation/http/handlers"
	"github.com/labstack/echo"
	"gorm.io/gorm"
)

// SetupRoutes sets up all routes for the application
func SetupRoutes(e *echo.Echo, cfg *config.Config, db *gorm.DB) {
	// API routes
	api := e.Group("/api/v1")

	// Health check
	e.GET("/health", handlers.HeartBeat)

	// Address management
	api.GET("/ether-address", handlers.EtherAddress(db))
	api.GET("/tron-address", handlers.TronAddress(db))
	api.GET("/address", handlers.GetAllAddress(db))

	// Balance and transactions
	api.GET("/balance", handlers.Balance(db))
	api.POST("/collect", handlers.Collect(db))
	api.POST("/send", handlers.Send(db))

	// Withdrawal
	api.POST("/withdraw", handlers.DoWithdraw(db))
	api.POST("/manual-request", handlers.ManualRequest(db))

	// Encryption/Decryption
	api.GET("/encrypt-all-private-keys", handlers.EncryptAllPrivateKeys(db))
	api.GET("/encrypt-private-key-by-email", handlers.EncryptPrivateKeyByEmail(db))
	api.GET("/decrypt-private-key-by-email", handlers.DecryptPrivateKeyByEmail(db))
}
