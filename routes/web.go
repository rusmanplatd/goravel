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
	organizationController := web.NewOrganizationController()
	notificationController := web.NewNotificationController()
	oauthController := web.NewOAuthController()
	oauthClientController := web.NewOAuthClientController()
	mfaController := web.NewMfaController()
	webauthnController := web.NewWebAuthnController()
	securityController := web.NewSecurityController()
	driveController := web.NewDriveController()
	accountSwitcherController := web.NewAccountSwitcherController()
	profileController := web.NewProfileController()

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

		// Tenant switching
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants/user/list", tenantController.GetUserTenants)
		facades.Route().Middleware(middleware.WebAuth()).Post("/tenants/switch", tenantController.SwitchTenant)
		facades.Route().Middleware(middleware.WebAuth()).Get("/tenants/current", tenantController.GetCurrentTenant)

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

		// Organization management
		facades.Route().Middleware(middleware.WebAuth()).Get("/organizations", organizationController.Index)

		// Notification management
		facades.Route().Middleware(middleware.WebAuth()).Get("/notifications", notificationController.Index)

		// Profile management
		facades.Route().Middleware(middleware.WebAuth()).Get("/profile", profileController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Get("/profile/edit", profileController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/profile", profileController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Get("/profile/settings", profileController.Settings)
		facades.Route().Middleware(middleware.WebAuth()).Put("/profile/settings", profileController.UpdateSettings)

		// Placeholder routes for other navbar links
		facades.Route().Middleware(middleware.WebAuth()).Get("/milestones", func(ctx http.Context) http.Response {
			return ctx.Response().View().Make("coming-soon.tmpl", map[string]interface{}{
				"title":   "Milestones",
				"user":    ctx.Value("user"),
				"feature": "Milestones",
			})
		})
		facades.Route().Middleware(middleware.WebAuth()).Get("/task-boards", func(ctx http.Context) http.Response {
			return ctx.Response().View().Make("coming-soon.tmpl", map[string]interface{}{
				"title":   "Task Boards",
				"user":    ctx.Value("user"),
				"feature": "Task Boards",
			})
		})

		// OAuth Client management (requires authentication)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients", oauthClientController.Index)
		facades.Route().Middleware(middleware.WebAuth()).Post("/oauth/clients", oauthClientController.Store)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients/{id}", oauthClientController.Show)
		facades.Route().Middleware(middleware.WebAuth()).Get("/oauth/clients/{id}/edit", oauthClientController.Edit)
		facades.Route().Middleware(middleware.WebAuth()).Put("/oauth/clients/{id}", oauthClientController.Update)
		facades.Route().Middleware(middleware.WebAuth()).Delete("/oauth/clients/{id}", oauthClientController.Delete)

		// Meeting web routes
		meetingWebController := &web.MeetingController{}
		facades.Route().Get("/meetings/{id}/join", meetingWebController.PreJoin)
		facades.Route().Post("/meetings/{id}/join", meetingWebController.Join)
		facades.Route().Get("/meetings/{id}/room", meetingWebController.Room)

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
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/quick-switch", accountSwitcherController.QuickSwitch)
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts/suggestions", accountSwitcherController.GetAccountSuggestions)
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts/grouped", accountSwitcherController.GetAccountsByOrganization)
		facades.Route().Middleware(middleware.WebAuth()).Get("/auth/accounts/security-insights", accountSwitcherController.GetSecurityInsights)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/update-activity", accountSwitcherController.UpdateAccountActivity)

		// Bulk operations
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/bulk-refresh", accountSwitcherController.BulkRefreshAccounts)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/bulk-extend-sessions", accountSwitcherController.BulkExtendSessions)
		facades.Route().Middleware(middleware.WebAuth()).Post("/auth/accounts/bulk-remove", accountSwitcherController.BulkRemoveAccounts)
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

	// Generic OAuth IdP routes (public)
	oauthIdpController := web.NewOAuthIdpController()
	facades.Route().Get("/auth/oauth/{provider}", oauthIdpController.Redirect)
	facades.Route().Get("/auth/oauth/{provider}/callback", oauthIdpController.Callback)
	facades.Route().Get("/api/oauth/providers", oauthIdpController.GetProviders)

	// Protected OAuth IdP routes
	facades.Route().Middleware(middleware.WebAuth()).Group(func(router route.Router) {
		router.Post("/auth/oauth/{provider}/unlink", oauthIdpController.Unlink)
		router.Get("/api/oauth/identities", oauthIdpController.GetUserIdentities)
	})

	// OAuth Provider Management routes (protected - admin only)
	oauthProviderController := web.NewOAuthProviderController()
	facades.Route().Middleware(middleware.WebAuth()).Group(func(router route.Router) {
		router.Get("/oauth/providers", oauthProviderController.Index)
		router.Get("/oauth/providers/create", oauthProviderController.Create)
		router.Post("/oauth/providers", oauthProviderController.Store)
		router.Get("/oauth/providers/{id}/edit", oauthProviderController.Edit)
		router.Put("/oauth/providers/{id}", oauthProviderController.Update)
		router.Delete("/oauth/providers/{id}", oauthProviderController.Delete)
		router.Post("/oauth/providers/{id}/toggle", oauthProviderController.Toggle)

		// Template routes
		router.Get("/oauth/providers/templates", oauthProviderController.Templates)
		router.Get("/oauth/providers/templates/{template}", oauthProviderController.GetTemplate)
		router.Post("/oauth/providers/from-template", oauthProviderController.CreateFromTemplate)
	})

	// OAuth Security Dashboard routes (protected) - TODO: Implement dashboard controller
	// oauthSecurityDashboardController := web.NewOAuthSecurityDashboardController()
	// facades.Route().Middleware(middleware.WebAuth()).Group(func(router route.Router) {
	//	router.Get("/oauth/security/dashboard", oauthSecurityDashboardController.Dashboard)
	//	router.Get("/oauth/security/devices", oauthSecurityDashboardController.DeviceManagement)
	//	router.Post("/oauth/security/devices/{fingerprint}/revoke", oauthSecurityDashboardController.RevokeDevice)
	//	router.Get("/oauth/security/events", oauthSecurityDashboardController.SecurityEvents)
	//	router.Get("/oauth/security/analytics", oauthSecurityDashboardController.Analytics)
	// })

	// Legacy Google OAuth routes (public) - for backward compatibility
	googleOAuthController := web.NewGoogleOAuthController()
	facades.Route().Get("/auth/google", googleOAuthController.Redirect)
	facades.Route().Get("/auth/google/callback", googleOAuthController.Callback)

	// Protected Google OAuth routes - for backward compatibility
	facades.Route().Middleware(middleware.WebAuth()).Post("/auth/google/unlink", googleOAuthController.Unlink)

	// Drive routes
	facades.Route().Middleware(middleware.WebAuth()).Get("/drive", driveController.Index)

	// Default route
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Redirect(302, "/dashboard")
	})
}
