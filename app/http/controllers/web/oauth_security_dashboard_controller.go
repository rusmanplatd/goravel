package web

import (
	"fmt"
	"strconv"
	"strings"
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

	// Get risk assessment for user with proper calculation
	riskScore := c.calculateUserRiskScore(user.ID)

	// Get device information with optimized query and proper joins
	devices := c.getUserDevicesWithDetails(user.ID)

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
		"userDevices":    devices,
		"consentHistory": consentHistory,
		"currentTime":    time.Now(),
	})
}

// calculateUserRiskScore calculates a comprehensive risk score for the user
func (c *OAuthSecurityDashboardController) calculateUserRiskScore(userID string) float64 {
	riskScore := 0.0
	maxScore := 10.0

	// Factor 1: Recent security events (weight: 30%)
	securityEventCount, _ := facades.Orm().Query().Model(&models.OAuthSecurityEvent{}).
		Where("user_id = ? AND severity IN ?", userID, []string{"high", "critical"}).
		Where("created_at > ?", time.Now().AddDate(0, 0, -30)). // Last 30 days
		Count()

	if securityEventCount > 0 {
		riskScore += min(float64(securityEventCount)*0.5, 3.0) // Max 3 points
	}

	// Factor 2: Failed login attempts (weight: 25%)
	failedAttempts, _ := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("causer_id = ? AND description = ?", userID, "authentication_failed").
		Where("created_at > ?", time.Now().AddDate(0, 0, -7)). // Last 7 days
		Count()

	if failedAttempts > 0 {
		riskScore += min(float64(failedAttempts)*0.3, 2.5) // Max 2.5 points
	}

	// Factor 3: Number of active devices (weight: 20%)
	activeDevices, _ := facades.Orm().Query().Model(&models.OAuthDeviceCode{}).
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Count()

	if activeDevices > 5 {
		riskScore += min(float64(activeDevices-5)*0.2, 2.0) // Max 2 points
	}

	// Factor 4: Suspicious IP addresses (weight: 15%)
	// Use a subquery approach since direct joins may not be supported
	var suspiciousIPs int64 = 0
	var sessions []models.OAuthSession
	err := facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", userID).
		Where("created_at > ?", time.Now().AddDate(0, 0, -30)).
		Find(&sessions)

	if err == nil {
		for _, session := range sessions {
			var threatCount int64
			threatCount, _ = facades.Orm().Query().
				Table("security_threat_ips").
				Where("ip_address = ? AND is_active = ?", session.IPAddress, true).
				Count()
			if threatCount > 0 {
				suspiciousIPs++
			}
		}
	}

	if suspiciousIPs > 0 {
		riskScore += min(float64(suspiciousIPs)*0.5, 1.5) // Max 1.5 points
	}

	// Factor 5: Account age and MFA status (weight: 10%)
	var user models.User
	err = facades.Orm().Query().Where("id = ?", userID).First(&user)
	if err == nil {
		accountAge := time.Since(user.CreatedAt).Hours() / 24 // Days

		// New accounts are riskier
		if accountAge < 30 {
			riskScore += 1.0
		}

		// No MFA is riskier
		if !user.MfaEnabled {
			riskScore += 0.5
		}
	}

	// Normalize to 0-1 scale
	normalizedScore := riskScore / maxScore
	if normalizedScore > 1.0 {
		normalizedScore = 1.0
	}

	return normalizedScore
}

// getUserDevicesWithDetails gets user devices with detailed information using optimized queries
func (c *OAuthSecurityDashboardController) getUserDevicesWithDetails(userID string) []map[string]interface{} {
	// Get device codes first
	var deviceCodes []models.OAuthDeviceCode
	err := facades.Orm().Query().Model(&models.OAuthDeviceCode{}).
		Where("user_id = ?", userID).
		OrderBy("created_at DESC").
		Limit(20).
		Find(&deviceCodes)

	if err != nil {
		facades.Log().Error("Failed to get user devices", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID,
		})
		return []map[string]interface{}{}
	}

	// Get recent sessions for this user to correlate device information
	var sessions []models.OAuthSession
	facades.Orm().Query().Model(&models.OAuthSession{}).
		Where("user_id = ?", userID).
		OrderBy("last_activity DESC").
		Limit(50).
		Find(&sessions)

	// Create a map of recent session data for quick lookup
	sessionMap := make(map[string]models.OAuthSession)
	for _, session := range sessions {
		if existingSession, exists := sessionMap[session.IPAddress]; !exists || session.LastActivity.After(existingSession.LastActivity) {
			sessionMap[session.IPAddress] = session
		}
	}

	// Convert to result format and correlate with session data
	var result []map[string]interface{}
	for _, device := range deviceCodes {
		deviceInfo := map[string]interface{}{
			"id":          device.ID,
			"device_code": device.ID, // The device code is stored as ID
			"user_code":   device.UserCode,
			"expires_at":  device.ExpiresAt,
			"created_at":  device.CreatedAt,
			"is_active":   device.ExpiresAt.After(time.Now()),
		}

		// Try to find matching session data
		var matchedSession *models.OAuthSession
		for _, session := range sessionMap {
			// Simple correlation - in reality you'd have better device tracking
			if session.CreatedAt.Sub(device.CreatedAt).Abs() < 5*time.Minute {
				matchedSession = &session
				break
			}
		}

		if matchedSession != nil {
			deviceInfo["last_used"] = matchedSession.LastActivity
			deviceInfo["ip_address"] = matchedSession.IPAddress
			deviceInfo["location"] = c.getLocationFromIP(matchedSession.IPAddress)
			deviceInfo["browser"] = c.getBrowserFromUserAgent(*matchedSession.UserAgent)
			deviceInfo["os"] = c.getOSFromUserAgent(*matchedSession.UserAgent)
		} else {
			deviceInfo["last_used"] = nil
			deviceInfo["ip_address"] = ""
			deviceInfo["location"] = "Unknown"
			deviceInfo["browser"] = "Unknown Browser"
			deviceInfo["os"] = "Unknown OS"
		}

		result = append(result, deviceInfo)
	}

	return result
}

// getLocationFromIP gets approximate location from IP address
func (c *OAuthSecurityDashboardController) getLocationFromIP(ipAddress string) string {
	if ipAddress == "" {
		return "Unknown"
	}

	// Check if it's a private IP
	if strings.HasPrefix(ipAddress, "192.168.") ||
		strings.HasPrefix(ipAddress, "10.") ||
		strings.HasPrefix(ipAddress, "172.") ||
		strings.HasPrefix(ipAddress, "127.") {
		return "Local Network"
	}

	// In a real implementation, you would use a GeoIP service
	// For now, return a placeholder
	return "Unknown Location"
}

// getBrowserFromUserAgent extracts browser information from user agent string
func (c *OAuthSecurityDashboardController) getBrowserFromUserAgent(userAgent string) string {
	if userAgent == "" {
		return "Unknown Browser"
	}

	userAgentLower := strings.ToLower(userAgent)

	if strings.Contains(userAgentLower, "chrome") {
		return "Chrome"
	} else if strings.Contains(userAgentLower, "firefox") {
		return "Firefox"
	} else if strings.Contains(userAgentLower, "safari") && !strings.Contains(userAgentLower, "chrome") {
		return "Safari"
	} else if strings.Contains(userAgentLower, "edge") {
		return "Edge"
	} else if strings.Contains(userAgentLower, "opera") {
		return "Opera"
	}

	return "Other Browser"
}

// getOSFromUserAgent extracts OS information from user agent string
func (c *OAuthSecurityDashboardController) getOSFromUserAgent(userAgent string) string {
	if userAgent == "" {
		return "Unknown OS"
	}

	userAgentLower := strings.ToLower(userAgent)

	if strings.Contains(userAgentLower, "windows") {
		return "Windows"
	} else if strings.Contains(userAgentLower, "macintosh") || strings.Contains(userAgentLower, "mac os") {
		return "macOS"
	} else if strings.Contains(userAgentLower, "linux") {
		return "Linux"
	} else if strings.Contains(userAgentLower, "android") {
		return "Android"
	} else if strings.Contains(userAgentLower, "iphone") || strings.Contains(userAgentLower, "ipad") {
		return "iOS"
	}

	return "Other OS"
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
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
