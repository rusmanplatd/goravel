package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"

	v1 "goravel/app/http/controllers/api/v1"
	"goravel/app/http/middleware"
)

func Api() {
	// Initialize controllers
	authController, err := v1.NewAuthController()
	if err != nil {
		facades.Log().Error("Failed to create API auth controller", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
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
	driveController := v1.NewDriveController()
	jobLevelController := v1.NewJobLevelController()
	jobPositionController := v1.NewJobPositionController()

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
	facades.Route().Post("/api/v1/oauth/par", oauthController.PushedAuthorizationRequest) // PAR endpoint
	facades.Route().Post("/api/v1/oauth/device", oauthController.DeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/device/token", oauthController.DeviceToken)
	facades.Route().Post("/api/v1/oauth/device/complete", oauthController.CompleteDeviceAuthorization)
	facades.Route().Post("/api/v1/oauth/token/exchange", oauthController.TokenExchange)

	// OAuth2 Discovery and OpenID Connect endpoints
	facades.Route().Get("/.well-known/oauth-authorization-server", oauthController.Discovery)
	facades.Route().Get("/.well-known/openid_configuration", oauthController.Discovery) // OIDC discovery alias
	facades.Route().Get("/api/v1/oauth/userinfo", oauthController.UserInfo)
	facades.Route().Get("/api/v1/oauth/jwks", oauthController.JWKS)

	// Google-like additional endpoints
	facades.Route().Get("/api/v1/oauth/tokeninfo", oauthController.TokenInfo)
	facades.Route().Post("/api/v1/oauth/logout", oauthController.Logout)
	facades.Route().Get("/oauth/check_session", oauthController.CheckSession)

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

	// OAuth2 Consent Management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/consent/prepare", oauthController.PrepareConsent)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/oauth/consent/process", oauthController.ProcessConsent)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/consents", oauthController.GetUserConsents)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/oauth/consents/{client_id}", oauthController.RevokeConsent)

	// OAuth2 Analytics routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/oauth/analytics", oauthController.GetAnalytics)

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

	// Job Level management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/job-levels", jobLevelController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/job-levels", jobLevelController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/job-levels/{id}", jobLevelController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/job-levels/{id}", jobLevelController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/job-levels/{id}", jobLevelController.Destroy)

	// Job Position management routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/job-positions", jobPositionController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/job-positions", jobPositionController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/job-positions/{id}", jobPositionController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/job-positions/{id}", jobPositionController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/job-positions/{id}", jobPositionController.Destroy)

	// User job management routes (protected)
	userJobManagementController := v1.NewUserJobManagementController()
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/users/{user_id}/job-assignment", userJobManagementController.AssignUserToPosition)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/users/{user_id}/career-progression", userJobManagementController.GetUserCareerProgression)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/users/{user_id}/promote", userJobManagementController.PromoteUser)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/job-analytics", userJobManagementController.GetJobAnalytics)

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

	// Project views routes (protected)
	projectViewController := v1.NewProjectViewController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/views", projectViewController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/views", projectViewController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/views/{view_id}", projectViewController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/projects/{project_id}/views/{view_id}", projectViewController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}/views/{view_id}", projectViewController.Delete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/views/{view_id}/set-default", projectViewController.SetDefault)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/views/{view_id}/duplicate", projectViewController.Duplicate)

	// Project custom fields routes (protected)
	customFieldController := v1.NewProjectCustomFieldController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/custom-fields", customFieldController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/custom-fields", customFieldController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/custom-fields/{field_id}", customFieldController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/organizations/{id}/projects/{project_id}/custom-fields/{field_id}", customFieldController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/organizations/{id}/projects/{project_id}/custom-fields/{field_id}", customFieldController.Delete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/custom-fields/reorder", customFieldController.Reorder)

	// Task custom field values routes (protected)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/tasks/{task_id}/fields", customFieldController.GetTaskFieldValues)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/tasks/{task_id}/fields/{field_id}", customFieldController.SetTaskFieldValue)

	// Project templates routes (protected)
	templateController := v1.NewProjectTemplateController()
	facades.Route().Get("/api/v1/templates", templateController.Index)
	facades.Route().Get("/api/v1/templates/featured", templateController.Featured)
	facades.Route().Get("/api/v1/templates/category/{category}", templateController.Category)
	facades.Route().Get("/api/v1/templates/{id}", templateController.Show)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/templates", templateController.Store)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/templates/{id}", templateController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/templates/{id}", templateController.Delete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/templates/{id}/use", templateController.UseTemplate)

	// Project insights routes (protected)
	insightController := v1.NewProjectInsightController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/insights", insightController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/organizations/{id}/projects/{project_id}/insights/generate", insightController.Generate)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/insights/summary", insightController.Summary)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/insights/velocity", insightController.Velocity)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/insights/burndown", insightController.Burndown)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/organizations/{id}/projects/{project_id}/insights/distribution", insightController.TaskDistribution)

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

	// Meeting API routes
	meetingController := v1.NewMeetingController()

	// Meeting management
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/start", meetingController.StartMeeting)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/end", meetingController.EndMeeting)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{id}/status", meetingController.GetMeetingStatus)

	// Participant management
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/join", meetingController.JoinMeeting)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/leave", meetingController.LeaveMeeting)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{id}/participants", meetingController.GetParticipants)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/meetings/{id}/participants/status", meetingController.UpdateParticipantStatus)

	// Meeting chat
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/chat", meetingController.SendChatMessage)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{id}/chat", meetingController.GetChatHistory)

	// LiveKit integration
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/token", meetingController.GenerateLiveKitToken)

	// Breakout rooms
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/breakout-rooms", meetingController.CreateBreakoutRooms)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{id}/breakout-rooms/assign", meetingController.AssignToBreakoutRoom)

	// Meeting WebSocket for real-time features
	meetingWSController := v1.NewMeetingWebSocketController()
	facades.Route().Get("/api/v1/meetings/{id}/ws", meetingWSController.ConnectToMeeting)

	// Meeting analytics routes
	meetingAnalyticsController := v1.NewMeetingAnalyticsController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/analytics/stats", meetingAnalyticsController.GetMeetingStats)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/analytics/participation", meetingAnalyticsController.GetParticipationReport)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/analytics/engagement", meetingAnalyticsController.GetEngagementMetrics)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/analytics/attendance", meetingAnalyticsController.GetAttendanceReport)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/analytics/organizational", meetingAnalyticsController.GetOrganizationalAnalytics)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/analytics/export", meetingAnalyticsController.ExportMeetingReport)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/analytics/realtime", meetingAnalyticsController.GetRealTimeMetrics)

	// Meeting security routes
	meetingSecurityController := v1.NewMeetingSecurityController()
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/policy", meetingSecurityController.ApplySecurityPolicy)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/validate-access", meetingSecurityController.ValidateAccess)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/security/waiting-room", meetingSecurityController.GetWaitingRoomParticipants)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/waiting-room/approve", meetingSecurityController.ApproveWaitingRoomParticipant)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/waiting-room/deny", meetingSecurityController.DenyWaitingRoomParticipant)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/remove-participant", meetingSecurityController.RemoveParticipant)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/mute-participant", meetingSecurityController.MuteParticipant)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/disable-camera", meetingSecurityController.DisableParticipantCamera)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/meetings/{meeting_id}/security/lock", meetingSecurityController.LockMeeting)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/security/events", meetingSecurityController.GetSecurityEvents)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/meetings/{meeting_id}/security/monitor", meetingSecurityController.MonitorMeetingSecurity)

	// Calendar utility routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/check-conflicts", calendarEventController.CheckConflicts)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/export", calendarEventController.ExportCalendar)

	// Calendar bulk operations
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/bulk-update", calendarEventController.BulkUpdate)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/bulk-delete", calendarEventController.BulkDelete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/bulk-reschedule", calendarEventController.BulkReschedule)

	// Calendar view and availability routes
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/view", calendarEventController.GetCalendarView)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-events/availability", calendarEventController.GetAvailability)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-events/suggestions", calendarEventController.GetEventSuggestions)

	// Event Templates API routes
	eventTemplateController := v1.NewEventTemplateController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/event-templates", eventTemplateController.Index)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/event-templates", eventTemplateController.Store)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/event-templates/{id}", eventTemplateController.Show)
	facades.Route().Middleware(middleware.Auth()).Put("/api/v1/event-templates/{id}", eventTemplateController.Update)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/event-templates/{id}", eventTemplateController.Delete)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/event-templates/{id}/create-event", eventTemplateController.CreateEventFromTemplate)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/event-templates/{id}/usage", eventTemplateController.GetTemplateUsage)

	// Calendar Analytics API routes
	calendarAnalyticsController := v1.NewCalendarAnalyticsController()
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-analytics/users/{user_id}", calendarAnalyticsController.GetUserAnalytics)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-analytics/tenants/{tenant_id}", calendarAnalyticsController.GetTenantAnalytics)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-analytics/reports", calendarAnalyticsController.GenerateReport)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-analytics/meeting-effectiveness", calendarAnalyticsController.GetMeetingEffectivenessReport)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-analytics/productivity-insights", calendarAnalyticsController.GetProductivityInsights)

	// Calendar Sharing API routes
	calendarSharingController := v1.NewCalendarSharingController()
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-sharing/share/{shared_with_id}", calendarSharingController.ShareCalendar)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-sharing/accept/{share_id}", calendarSharingController.AcceptCalendarShare)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-sharing/shared-calendars", calendarSharingController.GetSharedCalendars)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/calendar-sharing/revoke/{share_id}", calendarSharingController.RevokeCalendarShare)

	// Calendar Delegation API routes
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-delegation/create/{delegate_id}", calendarSharingController.CreateDelegation)
	facades.Route().Middleware(middleware.Auth()).Post("/api/v1/calendar-delegation/accept/{delegation_id}", calendarSharingController.AcceptDelegation)
	facades.Route().Middleware(middleware.Auth()).Delete("/api/v1/calendar-delegation/revoke/{delegation_id}", calendarSharingController.RevokeDelegation)
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-delegation/activities", calendarSharingController.GetDelegationActivities)

	// Calendar Permissions API routes
	facades.Route().Middleware(middleware.Auth()).Get("/api/v1/calendar-permissions/check", calendarSharingController.CheckPermission)

	// API Documentation (public)
	facades.Route().Get("/api/docs", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"message":      "API Documentation",
			"openapi":      "/api/docs/openapi.yaml",
			"openapi_json": "/api/docs/openapi.json",
			"ui":           "/api/docs/openapi.html",
		})
	})

	// Serve OpenAPI 3.0 UI
	facades.Route().Get("/api/docs/openapi.html", func(ctx http.Context) http.Response {
		return ctx.Response().File("public/docs/openapi.html")
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

	// Resource Indicators endpoints (RFC 8707)
	facades.Route().Get("/api/v1/oauth/resources", oauthController.GetResourceServers)
	facades.Route().Post("/api/v1/oauth/resources", oauthController.RegisterResourceServer)
	facades.Route().Post("/api/v1/oauth/authorize/resources", oauthController.ProcessResourceAuthorization)

	// Token Binding endpoints (RFC 8473)
	facades.Route().Post("/api/v1/oauth/token-binding/validate", oauthController.ValidateTokenBinding)
	facades.Route().Get("/api/v1/oauth/token-binding/info", oauthController.GetTokenBindingInfo)

	// Drive API routes (Google Drive-like functionality)
	facades.Route().Middleware(middleware.Auth()).Group(func(r route.Router) {
		// File operations
		r.Post("/api/v1/drive/files", driveController.UploadFile)
		r.Get("/api/v1/drive/files", driveController.GetFiles)
		r.Get("/api/v1/drive/files/{id}/download", driveController.DownloadFile)
		r.Get("/api/v1/drive/files/{id}/preview", driveController.GetFilePreview)
		r.Get("/api/v1/drive/files/{id}/thumbnail", driveController.GetFileThumbnail)
		r.Post("/api/v1/drive/files/{id}/share", driveController.ShareFile)
		r.Post("/api/v1/drive/files/{id}/move", driveController.MoveFile)
		r.Post("/api/v1/drive/files/{id}/trash", driveController.TrashFile)
		r.Post("/api/v1/drive/files/{id}/restore", driveController.RestoreFile)
		r.Post("/api/v1/drive/files/{id}/star", driveController.ToggleFileStar)
		r.Post("/api/v1/drive/files/{id}/versions", driveController.CreateFileVersion)
		r.Post("/api/v1/drive/files/{id}/comments", driveController.AddFileComment)
		r.Get("/api/v1/drive/files/{id}/comments", driveController.GetFileComments)
		r.Get("/api/v1/drive/files/{id}/activity", driveController.GetFileActivity)

		// Comment operations
		r.Put("/api/v1/drive/comments/{id}", driveController.UpdateFileComment)
		r.Delete("/api/v1/drive/comments/{id}", driveController.DeleteFileComment)

		// Search and filtering
		r.Get("/api/v1/drive/search", driveController.SearchFiles)
		r.Get("/api/v1/drive/recent", driveController.GetRecentFiles)
		r.Get("/api/v1/drive/starred", driveController.GetStarredFiles)
		r.Get("/api/v1/drive/types/{type}", driveController.GetFilesByType)

		// Bulk operations
		r.Post("/api/v1/drive/bulk", driveController.BulkOperation)

		// Folder operations
		r.Post("/api/v1/drive/folders", driveController.CreateFolder)
		r.Get("/api/v1/drive/folders", driveController.GetFolders)
		r.Get("/api/v1/drive/folders/{id}/contents", driveController.GetFolderContents)
		r.Post("/api/v1/drive/folders/{id}/share", driveController.ShareFolder)
		r.Post("/api/v1/drive/folders/{id}/trash", driveController.MoveFolderToTrash)
		r.Post("/api/v1/drive/folders/{id}/restore", driveController.RestoreFolderFromTrash)

		// Shared and trash
		r.Get("/api/v1/drive/shared/folders", driveController.GetSharedFolders)
		r.Get("/api/v1/drive/trash", driveController.GetTrashedItems)

		// Storage management
		r.Get("/api/v1/drive/quota", driveController.GetStorageQuota)
		r.Get("/api/v1/drive/analytics", driveController.GetStorageAnalytics)
		r.Post("/api/v1/drive/cleanup", driveController.CleanupTrash)

		// Tagging system
		r.Post("/api/v1/drive/files/{id}/tags", driveController.TagFile)
		r.Delete("/api/v1/drive/files/{id}/tags", driveController.RemoveTagsFromFile)
		r.Get("/api/v1/drive/tags", driveController.GetAllUserTags)
		r.Get("/api/v1/drive/tags/stats", driveController.GetTagUsageStats)
		r.Get("/api/v1/drive/tags/files", driveController.GetFilesByTags)
		r.Get("/api/v1/drive/tags/suggest", driveController.SuggestTags)
		r.Get("/api/v1/drive/organize/tags", driveController.OrganizeFilesByTags)

		// Duplicate detection and management
		r.Get("/api/v1/drive/duplicates", driveController.FindDuplicateFiles)
		r.Get("/api/v1/drive/duplicates/stats", driveController.GetDuplicateStats)
		r.Post("/api/v1/drive/duplicates/resolve", driveController.ResolveDuplicates)
		r.Get("/api/v1/drive/similar", driveController.FindSimilarFiles)
		r.Get("/api/v1/drive/duplicates/suggestions", driveController.GetDuplicateManagementSuggestions)

		// AI-powered insights and recommendations
		r.Get("/api/v1/drive/insights/activity", driveController.GetUserActivityInsights)
		r.Get("/api/v1/drive/insights/workspace", driveController.GetWorkspaceInsights)
		r.Get("/api/v1/drive/recommendations", driveController.GetSmartRecommendations)
		r.Get("/api/v1/drive/frequent", driveController.GetFrequentlyAccessedFiles)
		r.Get("/api/v1/drive/recommended", driveController.GetRecommendedFiles)
	})

	// Public file download (for shared files)
	facades.Route().Get("/api/v1/drive/public/files/{id}/download", driveController.DownloadFile)

	// Vault monitoring and management routes
	vaultController := v1.NewVaultController()
	facades.Route().Prefix("api/v1/vault").Group(func(router route.Router) {
		router.Get("/health", vaultController.Health)
		router.Get("/metrics", vaultController.Metrics)
		router.Get("/status", vaultController.Status)
		router.Post("/cache/clear", vaultController.ClearCache)
		router.Post("/token/renew", vaultController.RenewToken)

		// Key versioning routes
		router.Post("/keys/{user_id}/versions", vaultController.CreateKeyVersion)
		router.Get("/keys/{user_id}/versions", vaultController.ListKeyVersions)
		router.Post("/keys/{user_id}/rollback", vaultController.RollbackKey)
		router.Delete("/keys/{user_id}/versions/{version}", vaultController.DeleteKeyVersion)
		router.Get("/keys/{user_id}/history", vaultController.GetKeyHistory)
	})
}
