package providers

import (
	"context"
	"fmt"

	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

type VaultServiceProvider struct {
	vaultService *services.VaultService
}

// Register registers the Vault service
func (v *VaultServiceProvider) Register(app foundation.Application) {
	// Register Vault service as singleton
	app.Singleton("vault", func(app foundation.Application) (any, error) {
		// Check if Vault is enabled
		if !facades.Config().GetBool("vault.dev.enabled", false) &&
			facades.Config().Env("APP_ENV", "local") == "local" {
			facades.Log().Info("Vault service disabled in local environment", nil)
			return nil, nil
		}

		// Initialize Vault service
		vaultService, err := services.NewVaultService()
		if err != nil {
			facades.Log().Error("Failed to initialize Vault service", map[string]interface{}{
				"error": err.Error(),
			})

			// In development, continue without Vault if fallback is enabled
			if facades.Config().GetBool("vault.dev.fallback_to_env", false) {
				facades.Log().Warning("Continuing without Vault service (fallback enabled)", nil)
				return nil, nil
			}

			return nil, err
		}

		// Store reference for cleanup
		v.vaultService = vaultService

		facades.Log().Info("Vault service registered successfully", nil)
		return vaultService, nil
	})

	// Register helper functions
	app.Bind("vault.get", func(app foundation.Application) (any, error) {
		return func(path string) (*services.SecretData, error) {
			if vaultService, err := app.MakeWith("vault", nil); err == nil && vaultService != nil {
				if vs, ok := vaultService.(*services.VaultService); ok {
					return vs.GetSecret(path)
				}
			}
			return nil, fmt.Errorf("vault service not available")
		}, nil
	})

	app.Bind("vault.get_value", func(app foundation.Application) (any, error) {
		return func(path, key string) (string, error) {
			if vaultService, err := app.MakeWith("vault", nil); err == nil && vaultService != nil {
				if vs, ok := vaultService.(*services.VaultService); ok {
					return vs.GetSecretValue(path, key)
				}
			}
			return "", fmt.Errorf("vault service not available")
		}, nil
	})

	app.Bind("vault.put", func(app foundation.Application) (any, error) {
		return func(path string, data map[string]interface{}) error {
			if vaultService, err := app.MakeWith("vault", nil); err == nil && vaultService != nil {
				if vs, ok := vaultService.(*services.VaultService); ok {
					return vs.PutSecret(path, data)
				}
			}
			return fmt.Errorf("vault service not available")
		}, nil
	})
}

// Boot boots the Vault service
func (v *VaultServiceProvider) Boot(app foundation.Application) {
	// Vault service is initialized during registration
	// Additional boot logic can be added here if needed

	facades.Log().Info("Vault service provider booted", nil)
}

// Stop gracefully shuts down the Vault service
func (v *VaultServiceProvider) Stop(ctx context.Context) error {
	if v.vaultService != nil {
		facades.Log().Info("Shutting down Vault service", nil)
		return v.vaultService.Close()
	}
	return nil
}
