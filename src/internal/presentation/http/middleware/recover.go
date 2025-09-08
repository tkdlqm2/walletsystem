package middleware

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// Recover returns a recover middleware
func Recover() echo.MiddlewareFunc {
	return middleware.Recover()
}
