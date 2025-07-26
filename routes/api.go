package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	v1 "goravel/app/http/controllers/api/v1"
	"goravel/app/http/middleware"
)

func Api() {
	// Initialize controllers
	authController := v1.NewAuthController()
	oauthController := v1.NewOAuthController()
	userController := v1.NewUserController()
	tenantController := v1.NewTenantController()
	organizationController := v1.NewOrganizationController()
	departmentController := v1.NewDepartmentController()
	teamController := v1.NewTeamController()
	projectController := v1.NewProjectController()
	roleController := v1.NewRoleController()
	permissionController := v1.NewPermissionController()
	activityLogController := v1.NewActivityLogController()
	countryController := v1.NewCountryController()
	provinceController := v1.NewProvinceController()
	cityController := v1.NewCityController()
	districtController := v1.NewDistrictController()
	chatController := v1.NewChatController()
	calendarEventController := v1.NewCalendarEventController()
	notificationController := v1.NewNotificationController()

	// Public authentication routes with rate limiting
	facades.Route().Middleware(middleware.AuthRateLimit()).Post("/api/v1/auth/login", authController.Login)
	facades.Route().Middleware(middleware.AuthRateLimit()).Post("/api/v1/auth/register", authController.Register)
	facades.Route().Middleware(middleware.AuthRateLimit()).Post("/api/v1/auth/forgot-password", authController.ForgotPassword)
	facades.Route().Middleware(middleware.AuthRateLimit()).Post("/api/v1/auth/reset-password", authController.ResetPassword)

	// WebAuthn public routes (for authentication) with rate limiting
	facades.Route().Middleware(middleware.WebAuthnRateLimit()).Post("/api/v1/auth/webauthn/authenticate", authController.WebauthnAuthenticate)

	// Protected routes (require authentication)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/refresh", authController.RefreshToken)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/logout", authController.Logout)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/auth/profile", authController.GetProfile)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/change-password", authController.ChangePassword)

	// MFA routes (require authentication)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/auth/mfa/setup", authController.GenerateMfaSetup)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/mfa/enable", authController.EnableMfa)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/mfa/disable", authController.DisableMfa)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/mfa/verify", authController.VerifyMfa)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/mfa/backup-codes/regenerate", authController.GenerateNewBackupCodes)

	// WebAuthn protected routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/auth/webauthn/register", authController.WebauthnRegister)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/auth/webauthn/begin-registration", authController.BeginWebauthnRegistration)
	facades.Route().Get("/api/v1/auth/webauthn/begin-authentication", authController.BeginWebauthnAuthentication)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/auth/webauthn/credentials", authController.GetWebauthnCredentials)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/auth/webauthn/credentials/{id}", authController.DeleteWebauthnCredential)

	// OAuth2 routes (public)
	facades.Route().Post("/api/v1/oauth/token", oauthController.Token)
	facades.Route().Post("/api/v1/oauth/authorize", oauthController.Authorize)
	facades.Route().Post("/api/v1/oauth/introspect", oauthController.IntrospectToken)
	facades.Route().Post("/api/v1/oauth/revoke", oauthController.RevokeToken)
	facades.Route().Post("/api/v1/oauth/device", oauthController.DeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/device/token", oauthController.DeviceToken)
	facades.Route().Post("/api/v1/oauth/device/complete", oauthController.CompleteDeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/token/exchange", oauthController.TokenExchange)

	// OAuth2 Discovery and OpenID Connect endpoints
	facades.Route().Get("/.well-known/oauth-authorization-server", oauthController.Discovery)
	facades.Route().Get("/api/v1/oauth/userinfo", oauthController.UserInfo)
	facades.Route().Get("/api/v1/oauth/jwks", oauthController.JWKS)

	// Enhanced OAuth2 endpoints
	facades.Route().Post("/api/v1/oauth/jwt-token", oauthController.CreateJWTToken)
	facades.Route().Post("/api/v1/oauth/security-report", oauthController.SecurityReport)

	// Test OAuth endpoint
	facades.Route().Get("/api/v1/oauth/test", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"message": "OAuth controller is working",
			"status":  "success",
		})
	})

	// OAuth2 routes (protected)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/oauth/clients", oauthController.CreateClient)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/clients", oauthController.GetClients)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/clients/{id}", oauthController.GetClient)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/oauth/clients/{id}", oauthController.UpdateClient)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/oauth/clients/{id}", oauthController.DeleteClient)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/oauth/personal-access-tokens", oauthController.CreatePersonalAccessToken)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/personal-access-tokens", oauthController.GetPersonalAccessTokens)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/oauth/personal-access-tokens/{id}", oauthController.RevokePersonalAccessToken)

	// User management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/users", userController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/users", userController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/users/{id}", userController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/users/{id}", userController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/users/{id}", userController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/users/{id}/tenants", userController.Tenants)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/users/{id}/roles", userController.Roles)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/users/{id}/roles", userController.AssignRole)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/users/{id}/roles/{role_id}", userController.RevokeRole)

	// Tenant management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/tenants", tenantController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/tenants", tenantController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/tenants/{id}", tenantController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/tenants/{id}", tenantController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/tenants/{id}", tenantController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/tenants/{id}/users", tenantController.Users)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/tenants/{id}/users", tenantController.AddUser)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/tenants/{id}/users/{user_id}", tenantController.RemoveUser)

	// Organization management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations", organizationController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations", organizationController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}", organizationController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}", organizationController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}", organizationController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/users", organizationController.Users)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/users", organizationController.AddUser)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/users/{user_id}", organizationController.RemoveUser)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/hierarchy", organizationController.Hierarchy)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/stats", organizationController.Stats)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/verify", organizationController.Verify)

	// Department management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/departments", departmentController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/departments", departmentController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/departments/{department_id}", departmentController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/departments/{department_id}", departmentController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/departments/{department_id}", departmentController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/departments/{department_id}/users", departmentController.Users)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/departments/{department_id}/users", departmentController.AddUser)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/departments/{department_id}/users/{user_id}", departmentController.RemoveUser)

	// Team management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/teams", teamController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/teams", teamController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/teams/{team_id}", teamController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/teams/{team_id}", teamController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/teams/{team_id}", teamController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/teams/{team_id}/users", teamController.Users)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/teams/{team_id}/users", teamController.AddUser)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/teams/{team_id}/users/{user_id}", teamController.RemoveUser)

	// Project management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects", projectController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects", projectController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}", projectController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/projects/{project_id}", projectController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}", projectController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/users", projectController.Users)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/users", projectController.AddUser)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}/users/{user_id}", projectController.RemoveUser)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/teams", projectController.Teams)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/teams", projectController.AddTeam)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}/teams/{team_id}", projectController.RemoveTeam)

	// Task management routes (protected)
	taskController := v1.NewTaskController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/tasks", taskController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/tasks", taskController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/tasks/{task_id}", taskController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/projects/{project_id}/tasks/{task_id}", taskController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}/tasks/{task_id}", taskController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/task-labels", taskController.Labels)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/task-labels", taskController.CreateLabel)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/milestones", taskController.Milestones)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/milestones", taskController.CreateMilestone)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/task-boards", taskController.Boards)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/task-boards", taskController.CreateBoard)

	// Role management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/roles", roleController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/roles", roleController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/roles/{id}", roleController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/roles/{id}", roleController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/roles/{id}", roleController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/roles/{id}/permissions", roleController.Permissions)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/roles/{id}/permissions", roleController.AssignPermission)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/roles/{id}/permissions/{permission_id}", roleController.RevokePermission)

	// Permission management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/permissions", permissionController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/permissions", permissionController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/permissions/{id}", permissionController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/permissions/{id}", permissionController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/permissions/{id}", permissionController.Delete)

	// Activity log routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs", activityLogController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/activity-logs", activityLogController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs/{id}", activityLogController.Show)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs/subject", activityLogController.GetActivitiesForSubject)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs/causer", activityLogController.GetActivitiesForCauser)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs/log-name", activityLogController.GetActivitiesByLogName)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/activity-logs/date-range", activityLogController.GetActivitiesInDateRange)

	// Country management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/countries", countryController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/countries", countryController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/countries/{id}", countryController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/countries/{id}", countryController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/countries/{id}", countryController.Delete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/countries/bulk-delete", countryController.BulkDelete)
	facades.Route().Middleware(middleware.Auth()).Patch("/api/v1/countries/{id}/toggle-active", countryController.ToggleActive)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/countries/{id}/provinces", countryController.Provinces)

	// Province management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/provinces", provinceController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/provinces", provinceController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/provinces/{id}", provinceController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/provinces/{id}", provinceController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/provinces/{id}", provinceController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/provinces/{id}/cities", provinceController.Cities)

	// City management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/cities", cityController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/cities", cityController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/cities/{id}", cityController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/cities/{id}", cityController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/cities/{id}", cityController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/cities/{id}/districts", cityController.Districts)

	// District management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/districts", districtController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/districts", districtController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/districts/{id}", districtController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/districts/{id}", districtController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/districts/{id}", districtController.Delete)

	// Chat system routes (protected)
	// Chat routes with E2EE rate limiting
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms", chatController.GetChatRooms)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/rooms", chatController.CreateChatRoom)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}", chatController.GetChatRoom)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/chat/rooms/{id}", chatController.UpdateChatRoom)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/chat/rooms/{id}", chatController.DeleteChatRoom)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/messages", chatController.GetMessages)
	facades.Route().Middleware(middleware.Auth(), middleware.E2EERateLimit()).Post("/api/v1/chat/rooms/{id}/messages", chatController.SendMessage)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/rooms/{id}/read", chatController.MarkRoomAsRead)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/members", chatController.GetRoomMembers)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/rooms/{id}/members", chatController.AddMember)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/chat/rooms/{id}/members/{user_id}", chatController.RemoveMember)
	facades.Route().Middleware(middleware.Auth(), middleware.E2EERateLimit()).Post("/api/v1/chat/rooms/{id}/rotate-key", chatController.RotateRoomKey)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/keys", chatController.GetUserKeys)
	facades.Route().Middleware(middleware.Auth(), middleware.E2EERateLimit()).Post("/api/v1/chat/keys", chatController.GenerateKeyPair)

	// Message reactions routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.AddMessageReaction)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.RemoveMessageReaction)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions", chatController.GetMessageReactions)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/messages/{message_id}/reactions/summary", chatController.GetReactionSummary)

	// Message editing and deletion routes
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/chat/rooms/{id}/messages/{message_id}", chatController.EditMessage)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/chat/rooms/{id}/messages/{message_id}", chatController.DeleteMessage)

	// Thread management routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/rooms/{id}/messages/{message_id}/threads", chatController.CreateThread)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/threads/{thread_id}", chatController.GetThread)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/threads", chatController.GetRoomThreads)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/chat/threads/{thread_id}/resolve", chatController.ResolveThread)

	// Notification settings routes
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/rooms/{id}/notifications", chatController.GetNotificationSettings)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/chat/rooms/{id}/notifications", chatController.UpdateNotificationSettings)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/chat/notifications/global", chatController.GetGlobalNotificationSettings)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/chat/notifications/global", chatController.UpdateGlobalNotificationSettings)

	// Notification routes (protected)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/notifications/welcome/{user_id}", notificationController.SendWelcomeNotification)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/notifications/password-reset", notificationController.SendPasswordResetNotification)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/notifications/{user_id}", notificationController.GetUserNotifications)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/notifications/{notification_id}/read", notificationController.MarkNotificationAsRead)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/notifications/read-all/{user_id}", notificationController.MarkAllNotificationsAsRead)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/notifications/{notification_id}", notificationController.DeleteNotification)

	// Calendar events routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events", calendarEventController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events", calendarEventController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/{id}", calendarEventController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/calendar-events/{id}", calendarEventController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/calendar-events/{id}", calendarEventController.Delete)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/{id}/participants", calendarEventController.GetParticipants)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/{id}/participants", calendarEventController.AddParticipant)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/calendar-events/{id}/participants/{user_id}/response", calendarEventController.UpdateParticipantResponse)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/calendar-events/{id}/participants/{user_id}", calendarEventController.RemoveParticipant)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/my", calendarEventController.GetMyEvents)

	// Calendar event reminders routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/{id}/reminders", calendarEventController.CreateReminder)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/{id}/reminders", calendarEventController.GetReminders)

	// Meeting management routes
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/calendar-events/{id}/meeting/status", calendarEventController.UpdateMeetingStatus)

	// Calendar utility routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/check-conflicts", calendarEventController.CheckConflicts)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/export", calendarEventController.ExportCalendar)

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

	// WebSocket routes
	websocketController := v1.NewWebSocketController()

	// WebSocket connection endpoint (with middleware chain)
	facades.Route().Middleware(
		middleware.WebSocketCORS(),
		middleware.WebSocketAuth(),
		middleware.WebSocketSecurity(),
		middleware.WebSocketRateLimit(),
	).Get("/api/v1/ws", websocketController.Connect)

	// WebSocket management endpoints (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/websocket/stats", websocketController.GetConnectionStats)
	facades.Route().Get("/api/v1/websocket/health", websocketController.HealthCheck)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/websocket/test", websocketController.SendTestNotification)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/websocket/broadcast", websocketController.BroadcastMessage)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/websocket/connections/{connection_id}", websocketController.CloseConnection)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/websocket/users/{user_id}/connections", websocketController.CloseUserConnections)

	// Chat WebSocket routes (real-time chat functionality)
	// Chat room WebSocket connection for real-time messaging
	facades.Route().Middleware(
		middleware.WebSocketCORS(),
		middleware.WebSocketAuth(),
		middleware.WebSocketSecurity(),
		middleware.WebSocketRateLimit(),
	).Get("/api/v1/ws/chat/rooms/{room_id}", websocketController.ConnectToChatRoom)

	// Chat typing indicator WebSocket endpoint
	facades.Route().Middleware(
		middleware.WebSocketCORS(),
		middleware.WebSocketAuth(),
		middleware.WebSocketSecurity(),
		middleware.WebSocketRateLimit(),
	).Get("/api/v1/ws/chat/typing/{room_id}", websocketController.ConnectToTypingIndicator)

	// Chat user presence WebSocket endpoint
	facades.Route().Middleware(
		middleware.WebSocketCORS(),
		middleware.WebSocketAuth(),
		middleware.WebSocketSecurity(),
		middleware.WebSocketRateLimit(),
	).Get("/api/v1/ws/chat/presence", websocketController.ConnectToUserPresence)

	// Chat WebSocket management endpoints (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/websocket/chat/rooms/{room_id}/connections", websocketController.GetChatRoomConnections)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/websocket/chat/rooms/{room_id}/broadcast", websocketController.BroadcastToChatRoom)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/websocket/chat/rooms/{room_id}/connections", websocketController.CloseChatRoomConnections)
}
