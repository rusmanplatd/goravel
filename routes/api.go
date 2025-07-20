package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	v1 "goravel/app/http/controllers/api/v1"
)

func Api() {
	// Initialize controllers
	authController := v1.NewAuthController()
	oauthController := v1.NewOAuthController()
	userController := v1.NewUserController()
	tenantController := v1.NewTenantController()
	roleController := v1.NewRoleController()
	permissionController := v1.NewPermissionController()
	activityLogController := v1.NewActivityLogController()
	countryController := v1.NewCountryController()
	provinceController := v1.NewProvinceController()
	cityController := v1.NewCityController()
	districtController := v1.NewDistrictController()
	chatController := v1.NewChatController()
	calendarEventController := v1.NewCalendarEventController()

	// Public authentication routes
	facades.Route().Post("/api/v1/auth/login", authController.Login)
	facades.Route().Post("/api/v1/auth/register", authController.Register)
	facades.Route().Post("/api/v1/auth/forgot-password", authController.ForgotPassword)
	facades.Route().Post("/api/v1/auth/reset-password", authController.ResetPassword)

	// WebAuthn public routes (for authentication)
	facades.Route().Post("/api/v1/auth/webauthn/authenticate", authController.WebauthnAuthenticate)

	// Protected routes (require authentication) - temporarily without middleware for testing
	// Authentication management (requires auth)
	facades.Route().Post("/api/v1/auth/refresh", authController.RefreshToken)
	facades.Route().Post("/api/v1/auth/logout", authController.Logout)
	facades.Route().Get("/api/v1/auth/profile", authController.GetProfile)
	facades.Route().Post("/api/v1/auth/change-password", authController.ChangePassword)

	// MFA routes
	facades.Route().Get("/api/v1/auth/mfa/setup", authController.GenerateMfaSetup)
	facades.Route().Post("/api/v1/auth/mfa/enable", authController.EnableMfa)
	facades.Route().Post("/api/v1/auth/mfa/disable", authController.DisableMfa)
	facades.Route().Post("/api/v1/auth/mfa/verify", authController.VerifyMfa)

	// WebAuthn protected routes
	facades.Route().Post("/api/v1/auth/webauthn/register", authController.WebauthnRegister)
	facades.Route().Get("/api/v1/auth/webauthn/begin-registration", authController.BeginWebauthnRegistration)
	facades.Route().Get("/api/v1/auth/webauthn/begin-authentication", authController.BeginWebauthnAuthentication)
	facades.Route().Get("/api/v1/auth/webauthn/credentials", authController.GetWebauthnCredentials)
	facades.Route().Delete("/api/v1/auth/webauthn/credentials/{id}", authController.DeleteWebauthnCredential)

	// OAuth2 routes (public)
	facades.Route().Post("/api/v1/oauth/token", oauthController.Token)
	facades.Route().Post("/api/v1/oauth/authorize", oauthController.Authorize)
	facades.Route().Post("/api/v1/oauth/introspect", oauthController.IntrospectToken)
	facades.Route().Post("/api/v1/oauth/revoke", oauthController.RevokeToken)
	facades.Route().Post("/api/v1/oauth/device", oauthController.DeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/device/token", oauthController.DeviceToken)
	facades.Route().Post("/api/v1/oauth/device/complete", oauthController.CompleteDeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/token/exchange", oauthController.TokenExchange)

	// Test OAuth endpoint
	facades.Route().Get("/api/v1/oauth/test", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"message": "OAuth controller is working",
			"status":  "success",
		})
	})

	// OAuth2 routes (protected) - temporarily without middleware for testing
	facades.Route().Post("/api/v1/oauth/clients", oauthController.CreateClient)
	facades.Route().Get("/api/v1/oauth/clients", oauthController.GetClients)
	facades.Route().Get("/api/v1/oauth/clients/{id}", oauthController.GetClient)
	facades.Route().Put("/api/v1/oauth/clients/{id}", oauthController.UpdateClient)
	facades.Route().Delete("/api/v1/oauth/clients/{id}", oauthController.DeleteClient)
	facades.Route().Post("/api/v1/oauth/personal-access-tokens", oauthController.CreatePersonalAccessToken)
	facades.Route().Get("/api/v1/oauth/personal-access-tokens", oauthController.GetPersonalAccessTokens)
	facades.Route().Delete("/api/v1/oauth/personal-access-tokens/{id}", oauthController.RevokePersonalAccessToken)

	// User management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/users", userController.Index)
	facades.Route().Post("/api/v1/users", userController.Store)
	facades.Route().Get("/api/v1/users/{id}", userController.Show)
	facades.Route().Put("/api/v1/users/{id}", userController.Update)
	facades.Route().Delete("/api/v1/users/{id}", userController.Delete)
	facades.Route().Get("/api/v1/users/{id}/tenants", userController.Tenants)
	facades.Route().Get("/api/v1/users/{id}/roles", userController.Roles)
	facades.Route().Post("/api/v1/users/{id}/roles", userController.AssignRole)
	facades.Route().Delete("/api/v1/users/{id}/roles/{role_id}", userController.RevokeRole)

	// Tenant management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/tenants", tenantController.Index)
	facades.Route().Post("/api/v1/tenants", tenantController.Store)
	facades.Route().Get("/api/v1/tenants/{id}", tenantController.Show)
	facades.Route().Put("/api/v1/tenants/{id}", tenantController.Update)
	facades.Route().Delete("/api/v1/tenants/{id}", tenantController.Delete)
	facades.Route().Get("/api/v1/tenants/{id}/users", tenantController.Users)
	facades.Route().Post("/api/v1/tenants/{id}/users", tenantController.AddUser)
	facades.Route().Delete("/api/v1/tenants/{id}/users/{user_id}", tenantController.RemoveUser)

	// Role management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/roles", roleController.Index)
	facades.Route().Post("/api/v1/roles", roleController.Store)
	facades.Route().Get("/api/v1/roles/{id}", roleController.Show)
	facades.Route().Put("/api/v1/roles/{id}", roleController.Update)
	facades.Route().Delete("/api/v1/roles/{id}", roleController.Delete)
	facades.Route().Get("/api/v1/roles/{id}/permissions", roleController.Permissions)
	facades.Route().Post("/api/v1/roles/{id}/permissions", roleController.AssignPermission)
	facades.Route().Delete("/api/v1/roles/{id}/permissions/{permission_id}", roleController.RevokePermission)

	// Permission management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/permissions", permissionController.Index)
	facades.Route().Post("/api/v1/permissions", permissionController.Store)
	facades.Route().Get("/api/v1/permissions/{id}", permissionController.Show)
	facades.Route().Put("/api/v1/permissions/{id}", permissionController.Update)
	facades.Route().Delete("/api/v1/permissions/{id}", permissionController.Delete)

	// Activity log routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/activity-logs", activityLogController.Index)
	facades.Route().Post("/api/v1/activity-logs", activityLogController.Store)
	facades.Route().Get("/api/v1/activity-logs/{id}", activityLogController.Show)
	facades.Route().Get("/api/v1/activity-logs/subject", activityLogController.GetActivitiesForSubject)
	facades.Route().Get("/api/v1/activity-logs/causer", activityLogController.GetActivitiesForCauser)
	facades.Route().Get("/api/v1/activity-logs/log-name", activityLogController.GetActivitiesByLogName)
	facades.Route().Get("/api/v1/activity-logs/date-range", activityLogController.GetActivitiesInDateRange)

	// Country management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/countries", countryController.Index)
	facades.Route().Post("/api/v1/countries", countryController.Store)
	facades.Route().Get("/api/v1/countries/{id}", countryController.Show)
	facades.Route().Put("/api/v1/countries/{id}", countryController.Update)
	facades.Route().Delete("/api/v1/countries/{id}", countryController.Delete)
	facades.Route().Post("/api/v1/countries/bulk-delete", countryController.BulkDelete)
	facades.Route().Patch("/api/v1/countries/{id}/toggle-active", countryController.ToggleActive)
	facades.Route().Get("/api/v1/countries/{id}/provinces", countryController.Provinces)

	// Province management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/provinces", provinceController.Index)
	facades.Route().Post("/api/v1/provinces", provinceController.Store)
	facades.Route().Get("/api/v1/provinces/{id}", provinceController.Show)
	facades.Route().Put("/api/v1/provinces/{id}", provinceController.Update)
	facades.Route().Delete("/api/v1/provinces/{id}", provinceController.Delete)
	facades.Route().Get("/api/v1/provinces/{id}/cities", provinceController.Cities)

	// City management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/cities", cityController.Index)
	facades.Route().Post("/api/v1/cities", cityController.Store)
	facades.Route().Get("/api/v1/cities/{id}", cityController.Show)
	facades.Route().Put("/api/v1/cities/{id}", cityController.Update)
	facades.Route().Delete("/api/v1/cities/{id}", cityController.Delete)
	facades.Route().Get("/api/v1/cities/{id}/districts", cityController.Districts)

	// District management routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/districts", districtController.Index)
	facades.Route().Post("/api/v1/districts", districtController.Store)
	facades.Route().Get("/api/v1/districts/{id}", districtController.Show)
	facades.Route().Put("/api/v1/districts/{id}", districtController.Update)
	facades.Route().Delete("/api/v1/districts/{id}", districtController.Delete)

	// Chat system routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/chat/rooms", chatController.GetChatRooms)
	facades.Route().Post("/api/v1/chat/rooms", chatController.CreateChatRoom)
	facades.Route().Get("/api/v1/chat/rooms/{id}", chatController.GetChatRoom)
	facades.Route().Put("/api/v1/chat/rooms/{id}", chatController.UpdateChatRoom)
	facades.Route().Delete("/api/v1/chat/rooms/{id}", chatController.DeleteChatRoom)
	facades.Route().Get("/api/v1/chat/rooms/{id}/messages", chatController.GetMessages)
	facades.Route().Post("/api/v1/chat/rooms/{id}/messages", chatController.SendMessage)
	facades.Route().Post("/api/v1/chat/rooms/{id}/read", chatController.MarkRoomAsRead)
	facades.Route().Get("/api/v1/chat/rooms/{id}/members", chatController.GetRoomMembers)
	facades.Route().Post("/api/v1/chat/rooms/{id}/members", chatController.AddMember)
	facades.Route().Delete("/api/v1/chat/rooms/{id}/members/{user_id}", chatController.RemoveMember)
	facades.Route().Post("/api/v1/chat/rooms/{id}/rotate-key", chatController.RotateRoomKey)
	facades.Route().Get("/api/v1/chat/keys", chatController.GetUserKeys)
	facades.Route().Post("/api/v1/chat/keys", chatController.GenerateKeyPair)

	// Message reactions routes
	facades.Route().Post("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.AddMessageReaction)
	facades.Route().Delete("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.RemoveMessageReaction)
	facades.Route().Get("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.GetMessageReactions)
	facades.Route().Get("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions/summary", chatController.GetReactionSummary)

	// Message editing and deletion routes
	facades.Route().Put("/api/v1/chat/rooms/{id}/messages/{message_id}", chatController.EditMessage)
	facades.Route().Delete("/api/v1/chat/rooms/{id}/messages/{message_id}", chatController.DeleteMessage)

	// Thread management routes
	facades.Route().Post("/api/v1/chat/rooms/{id}/messages/{message_id}/threads", chatController.CreateThread)
	facades.Route().Get("/api/v1/chat/threads/{thread_id}", chatController.GetThread)
	facades.Route().Get("/api/v1/chat/rooms/{id}/threads", chatController.GetRoomThreads)
	facades.Route().Post("/api/v1/chat/threads/{thread_id}/resolve", chatController.ResolveThread)

	// Notification settings routes
	facades.Route().Get("/api/v1/chat/rooms/{id}/notifications", chatController.GetNotificationSettings)
	facades.Route().Put("/api/v1/chat/rooms/{id}/notifications", chatController.UpdateNotificationSettings)
	facades.Route().Get("/api/v1/chat/notifications/global", chatController.GetGlobalNotificationSettings)
	facades.Route().Put("/api/v1/chat/notifications/global", chatController.UpdateGlobalNotificationSettings)

	// Calendar events routes (protected) - temporarily without middleware for testing
	facades.Route().Get("/api/v1/calendar-events", calendarEventController.Index)
	facades.Route().Post("/api/v1/calendar-events", calendarEventController.Store)
	facades.Route().Get("/api/v1/calendar-events/{id}", calendarEventController.Show)
	facades.Route().Put("/api/v1/calendar-events/{id}", calendarEventController.Update)
	facades.Route().Delete("/api/v1/calendar-events/{id}", calendarEventController.Delete)
	facades.Route().Get("/api/v1/calendar-events/{id}/participants", calendarEventController.GetParticipants)
	facades.Route().Post("/api/v1/calendar-events/{id}/participants", calendarEventController.AddParticipant)
	facades.Route().Put("/api/v1/calendar-events/{id}/participants/{user_id}/response", calendarEventController.UpdateParticipantResponse)
	facades.Route().Delete("/api/v1/calendar-events/{id}/participants/{user_id}", calendarEventController.RemoveParticipant)
	facades.Route().Get("/api/v1/calendar-events/my", calendarEventController.GetMyEvents)

	// Calendar event reminders routes
	facades.Route().Post("/api/v1/calendar-events/{id}/reminders", calendarEventController.CreateReminder)
	facades.Route().Get("/api/v1/calendar-events/{id}/reminders", calendarEventController.GetReminders)

	// Meeting management routes
	facades.Route().Put("/api/v1/calendar-events/{id}/meeting/status", calendarEventController.UpdateMeetingStatus)

	// Calendar utility routes
	facades.Route().Post("/api/v1/calendar-events/check-conflicts", calendarEventController.CheckConflicts)
	facades.Route().Post("/api/v1/calendar-events/export", calendarEventController.ExportCalendar)

	// API Documentation (public)
	facades.Route().Get("/api/docs", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"message":      "API Documentation",
			"openapi":      "/api/docs/openapi.yaml",
			"openapi_json": "/api/docs/openapi.json",
			"ui":           "/api/openapi.html",
		})
	})

	// Serve OpenAPI 3.0 UI
	facades.Route().Get("/api/openapi.html", func(ctx http.Context) http.Response {
		return ctx.Response().File("public/openapi.html")
	})

	// Serve OpenAPI 3.0 YAML
	facades.Route().Get("/api/docs/openapi.yaml", func(ctx http.Context) http.Response {
		return ctx.Response().File("docs/openapi.yaml")
	})

	// Serve OpenAPI 3.0 JSON
	facades.Route().Get("/api/docs/openapi.json", func(ctx http.Context) http.Response {
		return ctx.Response().File("docs/openapi.json")
	})
}
