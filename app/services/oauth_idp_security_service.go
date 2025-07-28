package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthIdpSecurityService struct {
	riskService      *OAuthRiskService
	analyticsService *OAuthAnalyticsService
}

type SuspiciousActivity struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	Provider     string                 `json:"provider"`
	ActivityType string                 `json:"activity_type"` // login_attempt, device_change, location_change, etc.
	RiskScore    int                    `json:"risk_score"`
	Details      map[string]interface{} `json:"details"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Location     string                 `json:"location,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Status       string                 `json:"status"`  // detected, investigating, resolved, false_positive
	Actions      []string               `json:"actions"` // Actions taken (block, notify, require_mfa, etc.)
}

type SecurityAlert struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	Provider     string                 `json:"provider"`
	AlertType    string                 `json:"alert_type"` // suspicious_login, new_device, location_anomaly, etc.
	Severity     string                 `json:"severity"`   // low, medium, high, critical
	Message      string                 `json:"message"`
	Details      map[string]interface{} `json:"details"`
	Timestamp    time.Time              `json:"timestamp"`
	Acknowledged bool                   `json:"acknowledged"`
	ResolvedAt   *time.Time             `json:"resolved_at,omitempty"`
}

type LoginPattern struct {
	UserID           string    `json:"user_id"`
	Provider         string    `json:"provider"`
	UsualLocations   []string  `json:"usual_locations"`
	UsualDevices     []string  `json:"usual_devices"`
	UsualTimeRanges  []string  `json:"usual_time_ranges"`
	LastLoginTime    time.Time `json:"last_login_time"`
	LoginFrequency   float64   `json:"login_frequency"` // logins per day
	AverageRiskScore float64   `json:"average_risk_score"`
}

func NewOAuthIdpSecurityService() *OAuthIdpSecurityService {
	return &OAuthIdpSecurityService{
		riskService:      NewOAuthRiskService(),
		analyticsService: NewOAuthAnalyticsService(),
	}
}

// DetectSuspiciousActivity analyzes login attempts for suspicious patterns
func (s *OAuthIdpSecurityService) DetectSuspiciousActivity(ctx context.Context, userID, provider, ipAddress, userAgent string) (*SuspiciousActivity, error) {
	activity := &SuspiciousActivity{
		ID:        s.generateActivityID(),
		UserID:    userID,
		Provider:  provider,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Status:    "detected",
		Details:   make(map[string]interface{}),
		Actions:   []string{},
	}

	// Get user's login patterns
	patterns, err := s.getUserLoginPatterns(userID, provider)
	if err != nil {
		facades.Log().Warning("Failed to get user login patterns", map[string]interface{}{
			"user_id":  userID,
			"provider": provider,
			"error":    err.Error(),
		})
	}

	// Analyze various suspicious indicators
	riskScore := 0

	// 1. Check for unusual location
	if s.isUnusualLocation(ipAddress, patterns) {
		riskScore += 30
		activity.ActivityType = "location_anomaly"
		activity.Details["unusual_location"] = true
		activity.Details["ip_address"] = ipAddress
	}

	// 2. Check for unusual device
	deviceFingerprint := s.generateDeviceFingerprint(userAgent)
	if s.isUnusualDevice(deviceFingerprint, patterns) {
		riskScore += 25
		activity.ActivityType = "device_anomaly"
		activity.Details["unusual_device"] = true
		activity.Details["device_fingerprint"] = deviceFingerprint
	}

	// 3. Check for unusual timing
	if s.isUnusualTiming(time.Now(), patterns) {
		riskScore += 15
		activity.Details["unusual_timing"] = true
	}

	// 4. Check for rapid successive attempts
	if s.hasRapidAttempts(userID, provider) {
		riskScore += 40
		activity.ActivityType = "rapid_attempts"
		activity.Details["rapid_attempts"] = true
	}

	// 5. Check for known malicious IPs
	if s.isMaliciousIP(ipAddress) {
		riskScore += 50
		activity.ActivityType = "malicious_ip"
		activity.Details["malicious_ip"] = true
	}

	// 6. Check for suspicious user agent patterns
	if s.isSuspiciousUserAgent(userAgent) {
		riskScore += 20
		activity.Details["suspicious_user_agent"] = true
	}

	activity.RiskScore = riskScore

	// Determine actions based on risk score
	if riskScore >= 70 {
		activity.Actions = append(activity.Actions, "block_attempt")
		activity.Details["blocked"] = true
	} else if riskScore >= 40 {
		activity.Actions = append(activity.Actions, "require_mfa")
		activity.Details["mfa_required"] = true
	} else if riskScore >= 20 {
		activity.Actions = append(activity.Actions, "notify_user")
		activity.Details["notification_sent"] = true
	}

	// Store suspicious activity
	s.storeSuspiciousActivity(activity)

	// Create security alert if risk is high
	if riskScore >= 40 {
		alert := s.createSecurityAlert(activity)
		s.storeSecurityAlert(alert)
	}

	facades.Log().Info("Suspicious activity detected", map[string]interface{}{
		"activity_id":   activity.ID,
		"user_id":       userID,
		"provider":      provider,
		"risk_score":    riskScore,
		"activity_type": activity.ActivityType,
		"actions":       activity.Actions,
	})

	return activity, nil
}

// AnalyzeLoginPattern analyzes and updates user login patterns
func (s *OAuthIdpSecurityService) AnalyzeLoginPattern(userID, provider, ipAddress, userAgent string) error {
	// Get existing pattern or create new one
	pattern, err := s.getUserLoginPatterns(userID, provider)
	if err != nil {
		pattern = &LoginPattern{
			UserID:           userID,
			Provider:         provider,
			UsualLocations:   []string{},
			UsualDevices:     []string{},
			UsualTimeRanges:  []string{},
			LoginFrequency:   0,
			AverageRiskScore: 0,
		}
	}

	// Update pattern with new data
	location := s.getLocationFromIP(ipAddress)
	if location != "" && !s.contains(pattern.UsualLocations, location) {
		pattern.UsualLocations = append(pattern.UsualLocations, location)
		// Keep only last 5 locations
		if len(pattern.UsualLocations) > 5 {
			pattern.UsualLocations = pattern.UsualLocations[1:]
		}
	}

	deviceFingerprint := s.generateDeviceFingerprint(userAgent)
	if !s.contains(pattern.UsualDevices, deviceFingerprint) {
		pattern.UsualDevices = append(pattern.UsualDevices, deviceFingerprint)
		// Keep only last 3 devices
		if len(pattern.UsualDevices) > 3 {
			pattern.UsualDevices = pattern.UsualDevices[1:]
		}
	}

	// Update timing patterns
	currentHour := time.Now().Hour()
	timeRange := s.getTimeRange(currentHour)
	if !s.contains(pattern.UsualTimeRanges, timeRange) {
		pattern.UsualTimeRanges = append(pattern.UsualTimeRanges, timeRange)
	}

	// Update login frequency
	if !pattern.LastLoginTime.IsZero() {
		timeDiff := time.Since(pattern.LastLoginTime)
		if timeDiff.Hours() < 24 {
			pattern.LoginFrequency += 1.0 / timeDiff.Hours() * 24
		}
	}
	pattern.LastLoginTime = time.Now()

	// Store updated pattern
	return s.storeLoginPattern(pattern)
}

// GetSecurityAlerts retrieves security alerts for a user
func (s *OAuthIdpSecurityService) GetSecurityAlerts(userID string, limit int) ([]SecurityAlert, error) {
	// Query OAuth security events from the database
	var securityEvents []models.OAuthSecurityEvent
	err := facades.Orm().Query().
		Model(&models.OAuthSecurityEvent{}).
		Where("user_id = ?", userID).
		Where("is_resolved = ?", false).
		OrderBy("created_at DESC").
		Limit(limit).
		With("User").
		With("Client").
		Find(&securityEvents)
	if err != nil {
		facades.Log().Error("Failed to fetch security alerts", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to fetch security alerts: %w", err)
	}

	// Convert to SecurityAlert format
	alerts := make([]SecurityAlert, 0, len(securityEvents))
	for _, event := range securityEvents {
		alert := SecurityAlert{
			ID:           event.EventID,
			UserID:       userID,
			Provider:     s.getProviderFromClient(event.Client),
			AlertType:    event.EventType,
			Severity:     s.mapRiskLevelToSeverity(event.RiskLevel),
			Message:      s.generateAlertMessage(event.EventType, event.RiskLevel),
			Details:      s.buildAlertDetails(&event),
			Timestamp:    event.CreatedAt,
			Acknowledged: event.IsResolved,
		}
		alerts = append(alerts, alert)
	}

	// If we don't have enough recent events, add some example alerts for demonstration
	if len(alerts) == 0 {
		alerts = s.generateExampleAlerts(userID, limit)
	}

	return alerts, nil
}

// AcknowledgeAlert marks a security alert as acknowledged
func (s *OAuthIdpSecurityService) AcknowledgeAlert(alertID, userID string) error {
	// Update the security event in the database
	updates := map[string]interface{}{
		"is_resolved":       true,
		"resolved_at":       time.Now(),
		"resolution_action": "acknowledged_by_user",
	}

	result, err := facades.Orm().Query().
		Where("event_id = ? AND user_id = ?", alertID, userID).
		Update(&models.OAuthSecurityEvent{}, updates)
	if err != nil {
		facades.Log().Error("Failed to acknowledge security alert", map[string]interface{}{
			"alert_id": alertID,
			"user_id":  userID,
			"error":    err.Error(),
		})
		return fmt.Errorf("failed to acknowledge security alert: %w", err)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("security alert not found or already acknowledged")
	}

	facades.Log().Info("Security alert acknowledged", map[string]interface{}{
		"alert_id": alertID,
		"user_id":  userID,
	})
	return nil
}

// Helper methods

func (s *OAuthIdpSecurityService) generateActivityID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("activity_%d", time.Now().UnixNano())))
	return fmt.Sprintf("act_%x", hash[:8])
}

func (s *OAuthIdpSecurityService) generateDeviceFingerprint(userAgent string) string {
	hash := sha256.Sum256([]byte(userAgent))
	return fmt.Sprintf("%x", hash[:16])
}

func (s *OAuthIdpSecurityService) getUserLoginPatterns(userID, provider string) (*LoginPattern, error) {
	// In a real implementation, this would query the database
	// For now, return a mock pattern
	return &LoginPattern{
		UserID:           userID,
		Provider:         provider,
		UsualLocations:   []string{"New York, US", "San Francisco, US"},
		UsualDevices:     []string{"chrome_windows", "safari_macos"},
		UsualTimeRanges:  []string{"morning", "afternoon"},
		LastLoginTime:    time.Now().Add(-24 * time.Hour),
		LoginFrequency:   2.5,
		AverageRiskScore: 15.0,
	}, nil
}

func (s *OAuthIdpSecurityService) isUnusualLocation(ipAddress string, patterns *LoginPattern) bool {
	location := s.getLocationFromIP(ipAddress)
	if location == "" {
		return false
	}
	return !s.contains(patterns.UsualLocations, location)
}

func (s *OAuthIdpSecurityService) isUnusualDevice(deviceFingerprint string, patterns *LoginPattern) bool {
	return !s.contains(patterns.UsualDevices, deviceFingerprint)
}

func (s *OAuthIdpSecurityService) isUnusualTiming(loginTime time.Time, patterns *LoginPattern) bool {
	timeRange := s.getTimeRange(loginTime.Hour())
	return !s.contains(patterns.UsualTimeRanges, timeRange)
}

func (s *OAuthIdpSecurityService) hasRapidAttempts(userID, provider string) bool {
	// In a real implementation, this would check recent login attempts
	// For now, return false
	return false
}

func (s *OAuthIdpSecurityService) isMaliciousIP(ipAddress string) bool {
	// Check against known malicious IP lists
	maliciousIPs := []string{
		"203.0.113.1", // Example malicious IP
		"198.51.100.1",
	}

	for _, maliciousIP := range maliciousIPs {
		if ipAddress == maliciousIP {
			return true
		}
	}

	// Check if IP is from a suspicious range
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Check for common suspicious ranges (this is a simplified example)
	if ip.IsLoopback() || ip.IsMulticast() {
		return true
	}

	return false
}

func (s *OAuthIdpSecurityService) isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python", "go-http-client",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

func (s *OAuthIdpSecurityService) getLocationFromIP(ipAddress string) string {
	// In a real implementation, this would use a GeoIP service
	// For now, return mock data based on IP
	if strings.HasPrefix(ipAddress, "192.168.") || strings.HasPrefix(ipAddress, "10.") {
		return "Local Network"
	}
	if strings.HasPrefix(ipAddress, "203.0.113.") {
		return "Unknown Location"
	}
	return "New York, US"
}

func (s *OAuthIdpSecurityService) getTimeRange(hour int) string {
	if hour >= 6 && hour < 12 {
		return "morning"
	} else if hour >= 12 && hour < 18 {
		return "afternoon"
	} else if hour >= 18 && hour < 22 {
		return "evening"
	} else {
		return "night"
	}
}

func (s *OAuthIdpSecurityService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *OAuthIdpSecurityService) storeSuspiciousActivity(activity *SuspiciousActivity) {
	// In a real implementation, this would store in database
	facades.Log().Info("Storing suspicious activity", map[string]interface{}{
		"activity_id": activity.ID,
		"user_id":     activity.UserID,
		"provider":    activity.Provider,
		"risk_score":  activity.RiskScore,
	})
}

func (s *OAuthIdpSecurityService) createSecurityAlert(activity *SuspiciousActivity) *SecurityAlert {
	severity := "low"
	if activity.RiskScore >= 70 {
		severity = "critical"
	} else if activity.RiskScore >= 40 {
		severity = "high"
	} else if activity.RiskScore >= 20 {
		severity = "medium"
	}

	return &SecurityAlert{
		ID:        s.generateAlertID(),
		UserID:    activity.UserID,
		Provider:  activity.Provider,
		AlertType: activity.ActivityType,
		Severity:  severity,
		Message:   s.generateAlertMessage(activity.ActivityType, ""), // No risk level for suspicious activity
		Details:   activity.Details,
		Timestamp: activity.Timestamp,
	}
}

func (s *OAuthIdpSecurityService) generateAlertID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("alert_%d", time.Now().UnixNano())))
	return fmt.Sprintf("alert_%x", hash[:8])
}

func (s *OAuthIdpSecurityService) generateAlertMessage(eventType, riskLevel string) string {
	messages := map[string]string{
		"location_anomaly":      "Login from unusual location detected",
		"device_anomaly":        "Login from new or unusual device detected",
		"rapid_attempts":        "Multiple rapid login attempts detected",
		"malicious_ip":          "Login attempt from known malicious IP address",
		"suspicious_user_agent": "Suspicious user agent detected",
	}

	message, exists := messages[eventType]
	if !exists {
		message = fmt.Sprintf("Suspicious OAuth activity detected: %s", eventType)
	}

	// Add risk level context
	if riskLevel != "" {
		message += " (" + strings.ToUpper(riskLevel) + " Risk)"
	}

	return message
}

func (s *OAuthIdpSecurityService) storeSecurityAlert(alert *SecurityAlert) {
	// In a real implementation, this would store in database
	facades.Log().Info("Security alert created", map[string]interface{}{
		"alert_id":   alert.ID,
		"user_id":    alert.UserID,
		"provider":   alert.Provider,
		"alert_type": alert.AlertType,
		"severity":   alert.Severity,
	})
}

func (s *OAuthIdpSecurityService) storeLoginPattern(pattern *LoginPattern) error {
	// In a real implementation, this would store in database
	facades.Log().Info("Login pattern updated", map[string]interface{}{
		"user_id":         pattern.UserID,
		"provider":        pattern.Provider,
		"login_frequency": pattern.LoginFrequency,
	})
	return nil
}

// Helper methods for alert processing

func (s *OAuthIdpSecurityService) getProviderFromClient(client *models.OAuthClient) string {
	if client == nil {
		return "unknown"
	}

	// Map client names to provider names
	clientName := strings.ToLower(client.Name)
	if strings.Contains(clientName, "google") {
		return "google"
	} else if strings.Contains(clientName, "github") {
		return "github"
	} else if strings.Contains(clientName, "microsoft") {
		return "microsoft"
	} else if strings.Contains(clientName, "facebook") {
		return "facebook"
	}

	return "oauth_client"
}

func (s *OAuthIdpSecurityService) mapRiskLevelToSeverity(riskLevel string) string {
	switch strings.ToUpper(riskLevel) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "MINIMAL":
		return "info"
	default:
		return "medium"
	}
}

func (s *OAuthIdpSecurityService) buildAlertDetails(event *models.OAuthSecurityEvent) map[string]interface{} {
	details := make(map[string]interface{})

	if event.IPAddress != nil {
		details["ip_address"] = *event.IPAddress
	}
	if event.LocationCountry != nil {
		details["country"] = *event.LocationCountry
	}
	if event.LocationRegion != nil {
		details["region"] = *event.LocationRegion
	}
	if event.LocationCity != nil {
		details["city"] = *event.LocationCity
	}
	if event.UserAgent != nil {
		details["user_agent"] = *event.UserAgent
	}

	details["risk_score"] = event.RiskScore
	details["risk_level"] = event.RiskLevel

	// Parse risk factors if available
	if event.RiskFactors != nil && *event.RiskFactors != "" {
		var riskFactors []string
		if err := json.Unmarshal([]byte(*event.RiskFactors), &riskFactors); err == nil {
			details["risk_factors"] = riskFactors
		}
	}

	// Parse event data if available
	if event.EventData != nil && *event.EventData != "" {
		var eventData map[string]interface{}
		if err := json.Unmarshal([]byte(*event.EventData), &eventData); err == nil {
			details["event_data"] = eventData
		}
	}

	return details
}

func (s *OAuthIdpSecurityService) generateExampleAlerts(userID string, limit int) []SecurityAlert {
	// Generate some example alerts for demonstration when no real events exist
	examples := []SecurityAlert{
		{
			ID:        fmt.Sprintf("example_%d", time.Now().Unix()),
			UserID:    userID,
			Provider:  "system",
			AlertType: "account_monitoring",
			Severity:  "info",
			Message:   "Account security monitoring is active",
			Details: map[string]interface{}{
				"monitoring_enabled": true,
				"last_check":         time.Now(),
			},
			Timestamp:    time.Now().Add(-1 * time.Hour),
			Acknowledged: false,
		},
	}

	if limit < len(examples) {
		return examples[:limit]
	}
	return examples
}
