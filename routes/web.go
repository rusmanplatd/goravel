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

		// Protected routes (authentication required) - Apply middleware individually
		// Dashboard
		facades.Route().Middleware(middleware.WebAuth()).Get("/dashboard", authController.ShowDashboard)
		facades.Route().Middleware(middleware.WebAuth()).Post("/logout", authController.Logout)

		// Tenant management
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants", tenantController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants/create", tenantController.Create)
		facades.Route().Middleware(middleware.WebAuth()).Post("/tenants", tenantController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants/{id}", tenantController.Show)
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants/{id}/edit", tenantController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/tenants/{id}", tenantController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/tenants/{id}", tenantController.Delete)

		// Role management (within tenant context)
		facades.Route().Middleware(middleware.WebAuth()).Get("/roles", roleController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/roles/create", roleController.Create)
		facades.Route().Middleware(middleware.WebAuth()).Post("/roles", roleController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Get("/roles/{id}", roleController.Show)
		facades.Route().Middleware(middleware.WebAuth()).Get("/roles/{id}/edit", roleController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/roles/{id}", roleController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/roles/{id}", roleController.Delete)

		// Permission management (within tenant context)
		facades.Route().Middleware(middleware.WebAuth()).Get("/permissions", permissionController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/permissions/create", permissionController.Create)
		facades.Route().Middleware(middleware.WebAuth()).Post("/permissions", permissionController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Get("/permissions/{id}/edit", permissionController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/permissions/{id}", permissionController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/permissions/{id}", permissionController.Destroy)

		// OAuth Client management (requires authentication)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients", oauthClientController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/clients", oauthClientController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients/{id}", oauthClientController.Show)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients/{id}/edit", oauthClientController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/oauth/clients/{id}", oauthClientController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/oauth/clients/{id}", oauthClientController.Delete)

		// Security Settings
		facades.Route().Middleware(middleware.WebAuth()).Get("/security", securityController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/change-password", securityController.ShowChangePassword)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/change-password", securityController.ChangePassword)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/sessions", securityController.ShowSessions)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/sessions/{id}/revoke", securityController.RevokeSession)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/audit-log", securityController.ShowAuditLog)

		// MFA Management
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/mfa/setup", mfaController.ShowSetup)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/mfa/manage", mfaController.ShowManage)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/mfa/enable", mfaController.Enable)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/mfa/disable", mfaController.Disable)

		// WebAuthn Management
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/webauthn/setup", webauthnController.ShowSetup)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/webauthn/manage", webauthnController.ShowManage)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/webauthn/begin-registration", webauthnController.BeginRegistration)
		facades.Route().Middleware(middleware.WebAuth()).Post("/security/webauthn/finish-registration", webauthnController.FinishRegistration)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/webauthn/credentials", webauthnController.ShowCredentials)
		facades.Route().Middleware(middleware.WebAuth()).Put("/security/webauthn/credentials/{id}/name", webauthnController.UpdateCredentialName)
		facades.Route().Middleware(middleware.WebAuth()).Get("/security/webauthn/credentials/{id}/delete", webauthnController.DeleteCredential)

		// Multi-Account Management
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts", accountSwitcherController.ShowAccountSwitcher)
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts/api", accountSwitcherController.GetAccounts)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/switch-account", accountSwitcherController.SwitchAccount)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/remove-account", accountSwitcherController.RemoveAccount)

		// Enhanced Multi-Account API endpoints
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts/statistics", accountSwitcherController.GetSessionStatistics)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/refresh", accountSwitcherController.RefreshAccount)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/extend-session", accountSwitcherController.ExtendSession)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/validate", accountSwitcherController.ValidateAccount)
	})

	// OAuth2 Authorization routes (separate from API)
	facades.Route().Group(func(router route.Router) {
		// OAuth authorization endpoint (requires authentication)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/authorize", oauthController.ShowAuthorize)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/authorize", oauthController.HandleAuthorize)
	})

	// OAuth Security Center routes (protected)
	oauthSecurityController := web.NewOAuthSecurityController()
	facades.Route().Group(func(router route.Router) {
		// Security center main page
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/security", oauthSecurityController.Index)

		// Consent and token management
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/security/revoke-consent/{client_id}", oauthSecurityController.RevokeConsent)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/security/revoke-token/{token_id}", oauthSecurityController.RevokeToken)

		// Detailed views
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/security/history", oauthSecurityController.ConsentHistory)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/security/apps/{client_id}", oauthSecurityController.AppDetails)
	})

	// App Passwords routes (protected)
	appPasswordController := web.NewAppPasswordController()
	facades.Route().Group(func(router route.Router) {
		// App passwords management
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/app-passwords", appPasswordController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/app-passwords/create", appPasswordController.Create)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/app-passwords", appPasswordController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/app-passwords/{id}/revoke", appPasswordController.Revoke)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/oauth/app-passwords/{id}", appPasswordController.Delete)
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
	facades.Route().Middleware(middleware.WebAuth()).Post("/auth/google/unlink", googleOAuthController.Unlink)

	// Default route
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Redirect(302, "/dashboard")
	})
}
