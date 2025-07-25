package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"

	"goravel/app/http/controllers/web"
	"goravel/app/http/middleware"
)

// Web routes
func Web() {
	// Get web controller instances
	authController := web.NewAuthController()
	tenantController := web.NewTenantController()
	roleController := web.NewRoleController()
	permissionController := web.NewPermissionController()
	oauthController := web.NewOAuthController()
	oauthClientController := web.NewOAuthClientController()
	mfaController := web.NewMfaController()
	webauthnController := web.NewWebAuthnController()
	securityController := web.NewSecurityController()
	accountSwitcherController := web.NewAccountSwitcherController()

	// Authentication routes
	facades.Route().Group(func(router route.Router) {
		// Guest routes (no authentication required)
		router.Get("/login", func(ctx http.Context) http.Response {
			// Handle intended URL for all login methods
			intendedURL := ctx.Request().Query("redirect")
			if intendedURL != "" {
				// Basic validation to prevent open redirect attacks
				if intendedURL[0] == '/' {
					ctx.Request().Session().Put("intended_url", intendedURL)
				}
			}
			return authController.ShowLogin(ctx)
		})
		router.Post("/login", authController.Login)
		router.Get("/register", authController.ShowRegister)
		router.Post("/register", authController.Register)
		router.Get("/forgot-password", authController.ShowForgotPassword)
		router.Post("/forgot-password", authController.ForgotPassword)
		router.Get("/reset-password", authController.ShowResetPassword)
		router.Post("/reset-password", authController.ResetPassword)

		// MFA verification during login (guest route)
		router.Get("/auth/mfa/verify", mfaController.ShowVerify)
		router.Post("/auth/mfa/verify", mfaController.Verify)

		// WebAuthn authentication for login (guest routes)
		router.Post("/auth/webauthn/begin-authentication", webauthnController.BeginAuthentication)
		router.Post("/auth/webauthn/finish-authentication", webauthnController.FinishAuthentication)

		// Account addition (guest route for adding accounts to existing session)
		router.Get("/auth/add-account", accountSwitcherController.AddAccountPrompt)

		// Protected routes (authentication required)
		router.Group(func(router route.Router) {
			// Apply web auth middleware
			router.Middleware(middleware.WebAuth())

			// Dashboard
			router.Get("/dashboard", authController.ShowDashboard)
			router.Post("/logout", authController.Logout)

			// Tenant management
			router.Get("/tenants", tenantController.Index)
			router.Get("/tenants/create", tenantController.Create)
			router.Post("/tenants", tenantController.Store)
			router.Get("/tenants/{id}", tenantController.Show)
			router.Get("/tenants/{id}/edit", tenantController.Edit)
			router.Put("/tenants/{id}", tenantController.Update)
			router.Delete("/tenants/{id}", tenantController.Delete)

			// Role management (within tenant context)
			router.Get("/roles", roleController.Index)
			router.Get("/roles/create", roleController.Create)
			router.Post("/roles", roleController.Store)
			router.Get("/roles/{id}", roleController.Show)
			router.Get("/roles/{id}/edit", roleController.Edit)
			router.Put("/roles/{id}", roleController.Update)
			router.Delete("/roles/{id}", roleController.Delete)

			// Permission management (within tenant context)
			router.Get("/permissions", permissionController.Index)
			router.Get("/permissions/create", permissionController.Create)
			router.Post("/permissions", permissionController.Store)
			router.Get("/permissions/{id}/edit", permissionController.Edit)
			router.Put("/permissions/{id}", permissionController.Update)
			router.Delete("/permissions/{id}", permissionController.Destroy)

			// OAuth Client management (requires authentication)
			router.Get("/oauth/clients", oauthClientController.Index)
			router.Post("/oauth/clients", oauthClientController.Store)
			router.Get("/oauth/clients/{id}", oauthClientController.Show)
			router.Get("/oauth/clients/{id}/edit", oauthClientController.Edit)
			router.Put("/oauth/clients/{id}", oauthClientController.Update)
			router.Delete("/oauth/clients/{id}", oauthClientController.Delete)

			// Security Settings
			router.Get("/security", securityController.Index)
			router.Get("/security/change-password", securityController.ShowChangePassword)
			router.Post("/security/change-password", securityController.ChangePassword)
			router.Get("/security/sessions", securityController.ShowSessions)
			router.Post("/security/sessions/{id}/revoke", securityController.RevokeSession)
			router.Get("/security/audit-log", securityController.ShowAuditLog)

			// MFA Management
			router.Get("/security/mfa/setup", mfaController.ShowSetup)
			router.Get("/security/mfa/manage", mfaController.ShowManage)
			router.Post("/security/mfa/enable", mfaController.Enable)
			router.Post("/security/mfa/disable", mfaController.Disable)

			// WebAuthn Management
			router.Get("/security/webauthn/setup", webauthnController.ShowSetup)
			router.Get("/security/webauthn/manage", webauthnController.ShowManage)
			router.Post("/security/webauthn/begin-registration", webauthnController.BeginRegistration)
			router.Post("/security/webauthn/finish-registration", webauthnController.FinishRegistration)
			router.Get("/security/webauthn/credentials", webauthnController.ShowCredentials)
			router.Put("/security/webauthn/credentials/{id}/name", webauthnController.UpdateCredentialName)
			router.Get("/security/webauthn/credentials/{id}/delete", webauthnController.DeleteCredential)

			// Multi-Account Management
			router.Get("/auth/accounts", accountSwitcherController.ShowAccountSwitcher)
			router.Get("/auth/accounts/api", accountSwitcherController.GetAccounts)
			router.Post("/auth/switch-account", accountSwitcherController.SwitchAccount)
			router.Post("/auth/remove-account", accountSwitcherController.RemoveAccount)

			// Enhanced Multi-Account API endpoints
			router.Get("/auth/accounts/statistics", accountSwitcherController.GetSessionStatistics)
			router.Post("/auth/accounts/refresh", accountSwitcherController.RefreshAccount)
			router.Post("/auth/accounts/extend-session", accountSwitcherController.ExtendSession)
			router.Post("/auth/accounts/validate", accountSwitcherController.ValidateAccount)
		})
	})

	// OAuth2 Authorization routes (separate from API)
	facades.Route().Group(func(router route.Router) {
		// Apply web auth middleware for OAuth authorization
		router.Middleware(middleware.WebAuth())

		// OAuth authorization endpoint (requires authentication)
		router.Get("/oauth/authorize", oauthController.ShowAuthorize)
		router.Post("/oauth/authorize", oauthController.HandleAuthorize)
	})

	// OAuth Security Center routes (protected)
	oauthSecurityController := web.NewOAuthSecurityController()
	facades.Route().Group(func(router route.Router) {
		router.Middleware(middleware.WebAuth())

		// Security center main page
		router.Get("/oauth/security", oauthSecurityController.Index)

		// Consent and token management
		router.Post("/oauth/security/revoke-consent/{client_id}", oauthSecurityController.RevokeConsent)
		router.Post("/oauth/security/revoke-token/{token_id}", oauthSecurityController.RevokeToken)

		// Detailed views
		router.Get("/oauth/security/history", oauthSecurityController.ConsentHistory)
		router.Get("/oauth/security/apps/{client_id}", oauthSecurityController.AppDetails)
	})

	// App Passwords routes (protected)
	appPasswordController := web.NewAppPasswordController()
	facades.Route().Group(func(router route.Router) {
		router.Middleware(middleware.WebAuth())

		// App passwords management
		router.Get("/oauth/app-passwords", appPasswordController.Index)
		router.Get("/oauth/app-passwords/create", appPasswordController.Create)
		router.Post("/oauth/app-passwords", appPasswordController.Store)
		router.Post("/oauth/app-passwords/{id}/revoke", appPasswordController.Revoke)
		router.Delete("/oauth/app-passwords/{id}", appPasswordController.Delete)
	})

	// OAuth2 Playground routes (public for development)
	oauthPlaygroundController := web.NewOAuthPlaygroundController()
	facades.Route().Group(func(router route.Router) {
		// OAuth2 Playground
		router.Get("/oauth/playground", oauthPlaygroundController.Index)
		router.Post("/oauth/playground/build-url", oauthPlaygroundController.BuildAuthorizationURL)
		router.Post("/oauth/playground/exchange-code", oauthPlaygroundController.ExchangeCode)
		router.Post("/oauth/playground/test-endpoint", oauthPlaygroundController.TestEndpoint)
		router.Get("/oauth/playground/callback", oauthPlaygroundController.Callback)
	})

	// Google OAuth routes (public)
	googleOAuthController := web.NewGoogleOAuthController()
	facades.Route().Get("/auth/google", googleOAuthController.Redirect)
	facades.Route().Get("/auth/google/callback", googleOAuthController.Callback)

	// Protected Google OAuth routes
	facades.Route().Group(func(router route.Router) {
		router.Middleware(middleware.WebAuth())
		router.Post("/auth/google/unlink", googleOAuthController.Unlink)
	})

	// Default route
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Redirect(302, "/dashboard")
	})
}
