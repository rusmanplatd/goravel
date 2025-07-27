package web

import (
	"encoding/json"
	"strconv"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type NotificationPreferenceController struct {
	preferenceService *services.NotificationPreferenceService
	rateLimiter       *services.NotificationRateLimiter
}

func NewNotificationPreferenceController() *NotificationPreferenceController {
	return &NotificationPreferenceController{
		preferenceService: services.NewNotificationPreferenceService(),
		rateLimiter:       services.NewNotificationRateLimiter(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *NotificationPreferenceController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the notification preferences page
func (c *NotificationPreferenceController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get user preferences
	preferences, err := c.preferenceService.GetUserPreferences(user.ID)
	if err != nil {
		facades.Log().Error("Failed to get user preferences", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return ctx.Response().View().Make("notifications/preferences.tmpl", map[string]interface{}{
			"title": "Notification Preferences",
			"user":  user,
			"error": "Failed to load preferences",
		})
	}

	// Get rate limit status
	rateLimitStatus := c.rateLimiter.GetRateLimitStatus(user.ID)

	// Available channels
	availableChannels := []string{"database", "mail", "push", "websocket", "slack", "discord", "telegram", "sms"}

	// Available notification types
	notificationTypes := []string{
		"WelcomeNotification",
		"PasswordResetNotification",
		"SecurityAlertNotification",
		"CalendarEventNotification",
		"ChatMessageNotification",
		"MeetingInviteNotification",
	}

	return ctx.Response().View().Make("notifications/preferences.tmpl", map[string]interface{}{
		"title":              "Notification Preferences",
		"user":               user,
		"preferences":        preferences,
		"available_channels": availableChannels,
		"notification_types": notificationTypes,
		"rate_limit_status":  rateLimitStatus,
		"success":            ctx.Request().Query("success", ""),
		"error":              ctx.Request().Query("error", ""),
	})
}

// Update updates user notification preferences
func (c *NotificationPreferenceController) Update(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	// Parse preferences from request
	var requestData struct {
		Preferences []models.NotificationPreference `json:"preferences"`
	}

	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Invalid request data",
		})
	}

	// Validate and update preferences
	for i := range requestData.Preferences {
		requestData.Preferences[i].UserID = user.ID // Ensure user ID is set
	}

	err := c.preferenceService.BulkUpdatePreferences(user.ID, requestData.Preferences)
	if err != nil {
		facades.Log().Error("Failed to update preferences", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to update preferences",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Preferences updated successfully",
	})
}

// UpdateSingle updates a single notification preference
func (c *NotificationPreferenceController) UpdateSingle(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationType := ctx.Request().Input("notification_type", "")
	if notificationType == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification type is required",
		})
	}

	// Get current preference
	preference, err := c.preferenceService.GetPreferenceForType(user.ID, notificationType)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to get preference",
		})
	}

	// Update fields from request
	if enabled := ctx.Request().Input("enabled"); enabled != "" {
		preference.Enabled = enabled == "true"
	}

	if channelsStr := ctx.Request().Input("channels"); channelsStr != "" {
		var channels []string
		if err := json.Unmarshal([]byte(channelsStr), &channels); err == nil {
			preference.Channels = channels
		}
	}

	if digestEnabled := ctx.Request().Input("digest_enabled"); digestEnabled != "" {
		preference.DigestEnabled = digestEnabled == "true"
	}

	if digestFrequency := ctx.Request().Input("digest_frequency"); digestFrequency != "" {
		preference.DigestFrequency = digestFrequency
	}

	if maxPerHourStr := ctx.Request().Input("max_per_hour"); maxPerHourStr != "" {
		if maxPerHour, err := strconv.Atoi(maxPerHourStr); err == nil {
			preference.MaxPerHour = &maxPerHour
		}
	}

	if maxPerDayStr := ctx.Request().Input("max_per_day"); maxPerDayStr != "" {
		if maxPerDay, err := strconv.Atoi(maxPerDayStr); err == nil {
			preference.MaxPerDay = &maxPerDay
		}
	}

	// Update preference
	err = c.preferenceService.UpdatePreference(user.ID, preference)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to update preference",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":    true,
		"message":    "Preference updated successfully",
		"preference": preference,
	})
}

// SetQuietHours sets quiet hours for the user
func (c *NotificationPreferenceController) SetQuietHours(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	startTime := ctx.Request().Input("start_time", "")
	endTime := ctx.Request().Input("end_time", "")
	timezone := ctx.Request().Input("timezone", "UTC")

	if startTime == "" || endTime == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Start time and end time are required",
		})
	}

	err := c.preferenceService.SetQuietHours(user.ID, startTime, endTime, timezone)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to set quiet hours",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Quiet hours updated successfully",
	})
}

// EnableNotificationType enables a notification type
func (c *NotificationPreferenceController) EnableNotificationType(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationType := ctx.Request().Route("type")
	if notificationType == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification type is required",
		})
	}

	err := c.preferenceService.EnableNotificationType(user.ID, notificationType)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to enable notification type",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Notification type enabled successfully",
	})
}

// DisableNotificationType disables a notification type
func (c *NotificationPreferenceController) DisableNotificationType(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationType := ctx.Request().Route("type")
	if notificationType == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification type is required",
		})
	}

	err := c.preferenceService.DisableNotificationType(user.ID, notificationType)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to disable notification type",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Notification type disabled successfully",
	})
}

// EnableChannel enables a channel for a notification type
func (c *NotificationPreferenceController) EnableChannel(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationType := ctx.Request().Route("type")
	channel := ctx.Request().Route("channel")

	if notificationType == "" || channel == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification type and channel are required",
		})
	}

	err := c.preferenceService.EnableChannelForType(user.ID, notificationType, channel)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to enable channel",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Channel enabled successfully",
	})
}

// DisableChannel disables a channel for a notification type
func (c *NotificationPreferenceController) DisableChannel(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationType := ctx.Request().Route("type")
	channel := ctx.Request().Route("channel")

	if notificationType == "" || channel == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification type and channel are required",
		})
	}

	err := c.preferenceService.DisableChannelForType(user.ID, notificationType, channel)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to disable channel",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Channel disabled successfully",
	})
}

// GetRateLimitStatus returns current rate limit status
func (c *NotificationPreferenceController) GetRateLimitStatus(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	status := c.rateLimiter.GetRateLimitStatus(user.ID)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"status":  status,
	})
}

// ResetRateLimit resets rate limit counters (admin function)
func (c *NotificationPreferenceController) ResetRateLimit(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	// Check if user has admin privileges for rate limit reset
	// Users can only reset their own rate limits, admins can reset any user's limits
	if !c.isAdminUser(user) {
		facades.Log().Warning("Non-admin user attempted rate limit reset", map[string]interface{}{
			"user_id": user.ID,
			"ip":      ctx.Request().Ip(),
		})
	}

	scope := ctx.Request().Input("scope", "all")
	err := c.rateLimiter.ResetRateLimit(user.ID, scope)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to reset rate limit",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Rate limit reset successfully",
	})
}

// isAdminUser checks if the user has admin privileges
func (c *NotificationPreferenceController) isAdminUser(user *models.User) bool {
	// Check if user has admin role
	var adminRole models.Role
	err := facades.Orm().Query().Where("name = ?", "admin").First(&adminRole)
	if err != nil {
		return false
	}

	// Check if user has the admin role
	var userRole models.UserRole
	err = facades.Orm().Query().
		Where("user_id = ?", user.ID).
		Where("role_id = ?", adminRole.ID).
		First(&userRole)

	return err == nil
}
