package web

import (
	"fmt"
	"strconv"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthSecurityDashboardController struct {
	oauthService      *services.OAuthService
	analyticsService  *services.OAuthAnalyticsService
	riskService       *services.OAuthRiskService
	sessionService    *services.OAuthSessionService
	monitoringService *services.MeetingMonitoringService
}

// NewOAuthSecurityDashboardController creates a new OAuth security dashboard controller
func NewOAuthSecurityDashboardController() *OAuthSecurityDashboardController {
	oauthService, err := services.NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthSecurityDashboardController{
		oauthService:      oauthService,
		analyticsService:  services.NewOAuthAnalyticsService(),
		riskService:       services.NewOAuthRiskService(),
		sessionService:    services.NewOAuthSessionService(),
		monitoringService: services.NewMeetingMonitoringService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *OAuthSecurityDashboardController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Dashboard displays the main OAuth security dashboard
func (c *OAuthSecurityDashboardController) Dashboard(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get OAuth security metrics
	totalClients, _ := facades.Orm().Query().Model(&models.OAuthClient{}).Count()
	activeTokens, _ := facades.Orm().Query().Model(&models.OAuthAccessToken{}).
		Where("expires_at > ?", time.Now()).
		Count()

		// Get user's active sessions
	var userSessions []models.OAuthSession
	facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", user.ID).
		Where("expires_at > ?", time.Now()).
		OrderBy("created_at DESC").
		Limit(10).
		Find(&userSessions)

	// Get recent security events
	var recentEvents []models.OAuthSecurityEvent
	facades.Orm().Query().Model(&models.OAuthSecurityEvent{}).
		Where("user_id = ?", user.ID).
		OrderBy("created_at DESC").
		Limit(10).
		Find(&recentEvents)

	// Get risk assessment for user (simplified calculation)
	riskScore := 0.5 // Default medium risk

	// Get device information
	var userDevices []models.OAuthDeviceCode
	facades.Orm().Query().Model(&models.OAuthDeviceCode{}).
		Where("user_id = ?", user.ID).
		Where("expires_at > ?", time.Now()).
		OrderBy("created_at DESC").
		Limit(10).
		Find(&userDevices)

	// Get consent history
	var consentHistory []models.OAuthConsent
	facades.Orm().Query().Model(&models.OAuthConsent{}).
		Where("user_id = ?", user.ID).
		OrderBy("created_at DESC").
		Limit(10).
		Find(&consentHistory)

	return ctx.Response().View().Make("oauth/security/dashboard.tmpl", map[string]interface{}{
		"title":          "OAuth Security Dashboard",
		"user":           user,
		"totalClients":   totalClients,
		"activeTokens":   activeTokens,
		"userSessions":   userSessions,
		"recentEvents":   recentEvents,
		"riskScore":      riskScore,
		"userDevices":    userDevices,
		"consentHistory": consentHistory,
		"currentTime":    time.Now(),
	})
}

// DeviceManagement displays device management interface
func (c *OAuthSecurityDashboardController) DeviceManagement(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get all user devices and sessions
	var devices []struct {
		models.OAuthDeviceCode
		LastUsed *time.Time `json:"last_used"`
		Location string     `json:"location"`
		Browser  string     `json:"browser"`
		OS       string     `json:"os"`
	}

	// Simplified device query without join for now
	err := facades.Orm().Query().Model(&models.OAuthDeviceCode{}).
		Where("user_id = ?", user.ID).
		OrderBy("created_at DESC").
		Find(&devices)

	if err != nil {
		facades.Log().Error("Failed to get user devices", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Get active sessions
	var sessions []models.OAuthSession
	err = facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", user.ID).
		Where("expires_at > ?", time.Now()).
		OrderBy("last_activity DESC").
		Find(&sessions)

	if err != nil {
		facades.Log().Error("Failed to get user sessions", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Get security events related to devices
	var securityEvents []models.OAuthSecurityEvent
	err = facades.Orm().Query().Model(&models.OAuthSecurityEvent{}).
		Where("user_id = ?", user.ID).
		Where("event_type IN ?", []string{"device_login", "device_logout", "suspicious_device", "new_device"}).
		OrderBy("created_at DESC").
		Limit(20).
		Find(&securityEvents)

	if err != nil {
		facades.Log().Error("Failed to get security events", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	return ctx.Response().View().Make("oauth/security/devices.tmpl", map[string]interface{}{
		"title":          "Device Management",
		"user":           user,
		"devices":        devices,
		"sessions":       sessions,
		"securityEvents": securityEvents,
		"currentTime":    time.Now(),
	})
}

// RevokeDevice revokes access for a specific device
func (c *OAuthSecurityDashboardController) RevokeDevice(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	deviceID := ctx.Request().Input("device_id")
	if deviceID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Device ID is required",
		})
	}

	// Revoke device access
	_, err := facades.Orm().Query().Model(&models.OAuthDeviceCode{}).
		Where("id = ?", deviceID).
		Where("user_id = ?", user.ID).
		Update("expires_at", time.Now())

	if err != nil {
		facades.Log().Error("Failed to revoke device", map[string]interface{}{
			"error":     err.Error(),
			"device_id": deviceID,
			"user_id":   user.ID,
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to revoke device access",
		})
	}

	// Also revoke related sessions
	facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", user.ID).
		Where("device_id = ?", deviceID).
		Update("expires_at", time.Now())

	// Log security event
	userIDPtr := &user.ID
	ipAddress := ctx.Request().Ip()
	userAgent := ctx.Request().Header("User-Agent")
	eventData := `{"device_id":"` + deviceID + `","action":"manual_revoke"}`

	securityEvent := &models.OAuthSecurityEvent{
		EventType: "device_revoked",
		UserID:    userIDPtr,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		EventData: &eventData,
	}
	facades.Orm().Query().Create(securityEvent)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Device access revoked successfully",
	})
}

// RevokeSession revokes a specific OAuth session
func (c *OAuthSecurityDashboardController) RevokeSession(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	sessionID := ctx.Request().Input("session_id")
	if sessionID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Session ID is required",
		})
	}

	// Revoke session
	_, err := facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("id = ?", sessionID).
		Where("user_id = ?", user.ID).
		Update("expires_at", time.Now())

	if err != nil {
		facades.Log().Error("Failed to revoke session", map[string]interface{}{
			"error":      err.Error(),
			"session_id": sessionID,
			"user_id":    user.ID,
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to revoke session",
		})
	}

	// Log security event
	userIDPtr := &user.ID
	ipAddress := ctx.Request().Ip()
	userAgent := ctx.Request().Header("User-Agent")
	eventData := `{"session_id":"` + sessionID + `","action":"manual_revoke"}`

	securityEvent := &models.OAuthSecurityEvent{
		EventType: "session_revoked",
		UserID:    userIDPtr,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		EventData: &eventData,
	}
	facades.Orm().Query().Create(securityEvent)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Session revoked successfully",
	})
}

// SecurityEvents displays security events for the user
func (c *OAuthSecurityDashboardController) SecurityEvents(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(ctx.Request().Input("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Input("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Get security events with pagination
	var events []models.OAuthSecurityEvent
	query := facades.Orm().Query().Model(&models.OAuthSecurityEvent{}).
		Where("user_id = ?", user.ID).
		OrderBy("created_at DESC")

	// Apply filters if provided
	eventType := ctx.Request().Input("event_type")
	if eventType != "" {
		query = query.Where("event_type = ?", eventType)
	}

	dateFrom := ctx.Request().Input("date_from")
	if dateFrom != "" {
		if parsedDate, err := time.Parse("2006-01-02", dateFrom); err == nil {
			query = query.Where("created_at >= ?", parsedDate)
		}
	}

	dateTo := ctx.Request().Input("date_to")
	if dateTo != "" {
		if parsedDate, err := time.Parse("2006-01-02", dateTo); err == nil {
			query = query.Where("created_at <= ?", parsedDate.Add(24*time.Hour))
		}
	}

	// Get total count for pagination
	totalCount, _ := query.Count()

	// Get events for current page
	err := query.Offset(offset).Limit(limit).Find(&events)
	if err != nil {
		facades.Log().Error("Failed to get security events", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Calculate pagination info
	totalPages := (totalCount + int64(limit) - 1) / int64(limit)
	hasNext := page < int(totalPages)
	hasPrev := page > 1

	return ctx.Response().View().Make("oauth/security/events.tmpl", map[string]interface{}{
		"title":       "Security Events",
		"user":        user,
		"events":      events,
		"currentPage": page,
		"totalPages":  totalPages,
		"totalCount":  totalCount,
		"hasNext":     hasNext,
		"hasPrev":     hasPrev,
		"nextPage":    page + 1,
		"prevPage":    page - 1,
		"filters": map[string]string{
			"event_type": eventType,
			"date_from":  dateFrom,
			"date_to":    dateTo,
		},
	})
}

// RevokeAllSessions revokes all active sessions for the user
func (c *OAuthSecurityDashboardController) RevokeAllSessions(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	// Revoke all active sessions
	result, err := facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", user.ID).
		Where("expires_at > ?", time.Now()).
		Update("expires_at", time.Now())

	if err != nil {
		facades.Log().Error("Failed to revoke all sessions", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to revoke sessions",
		})
	}

	// Log security event
	userIDPtr := &user.ID
	ipAddress := ctx.Request().Ip()
	userAgent := ctx.Request().Header("User-Agent")
	eventData := `{"revoked_count":` + fmt.Sprintf("%d", result.RowsAffected) + `,"action":"bulk_revoke"}`

	securityEvent := &models.OAuthSecurityEvent{
		EventType: "all_sessions_revoked",
		UserID:    userIDPtr,
		IPAddress: &ipAddress,
		UserAgent: &userAgent,
		EventData: &eventData,
	}
	facades.Orm().Query().Create(securityEvent)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "All sessions revoked successfully",
		"count":   result.RowsAffected,
	})
}
