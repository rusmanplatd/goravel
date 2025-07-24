package providers

import (
	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

type OIDCServiceProvider struct {
}

func (receiver *OIDCServiceProvider) Register(app foundation.Application) {
	// Register OIDC service as a singleton
	app.Singleton("oidc", func(app foundation.Application) (any, error) {
		return services.NewOIDCService(), nil
	})
}

func (receiver *OIDCServiceProvider) Boot(app foundation.Application) {
	// Initialize OIDC service and log startup
	oidcService, err := app.Make("oidc")
	if err != nil {
		facades.Log().Error("Failed to initialize OIDC service", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	_ = oidcService // Use the service to ensure it's initialized

	facades.Log().Info("OIDC Service Provider initialized", map[string]interface{}{
		"issuer": facades.Config().GetString("oidc.issuer"),
		"endpoints": map[string]string{
			"discovery": facades.Config().GetString("oidc.authorization_endpoint"),
			"jwks":      facades.Config().GetString("oidc.jwks_endpoint"),
			"userinfo":  facades.Config().GetString("oidc.userinfo_endpoint"),
		},
		"security": map[string]interface{}{
			"require_https":                   facades.Config().GetBool("oidc.security.require_https"),
			"require_pkce_for_public_clients": facades.Config().GetBool("oidc.security.require_pkce_for_public_clients"),
			"require_state_parameter":         facades.Config().GetBool("oidc.security.require_state_parameter"),
		},
	})
}
