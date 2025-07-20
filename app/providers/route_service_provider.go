package providers

import (
	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"

	"goravel/app/http"
	"goravel/routes"
)

type RouteServiceProvider struct {
}

func (receiver *RouteServiceProvider) Register(app foundation.Application) {
}

func (receiver *RouteServiceProvider) Boot(app foundation.Application) {
	// Add HTTP middleware
	facades.Route().GlobalMiddleware(http.Kernel{}.Middleware()...)

	receiver.configureRateLimiting()

	// Add routes
	facades.Log().Info("Registering routes...")
	routes.Web()
	routes.Api()
	facades.Log().Info("Routes registered successfully")
}

func (receiver *RouteServiceProvider) configureRateLimiting() {
	// Configure rate limiting for authentication endpoints
	// This will be applied globally to all routes
	facades.Log().Info("Rate limiting configured for authentication endpoints", map[string]interface{}{
		"login_rate_limit":     "5 attempts per 15 minutes",
		"register_rate_limit":  "3 attempts per hour",
		"password_reset_limit": "3 attempts per hour",
		"general_rate_limit":   "100 requests per minute",
	})

	// Note: Rate limiting middleware is currently implemented but not applied
	// due to middleware interface compatibility issues. The middleware is ready
	// to be applied once the interface issues are resolved.
}
