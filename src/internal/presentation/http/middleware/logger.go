package middleware

import (
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/labstack/echo"
)

// Logger returns a logger middleware
func Logger() echo.MiddlewareFunc {
	return logger.LoggingMiddleware
}
