package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type AuditService struct{}

// AuditEvent represents an audit log event
type AuditEvent struct {
	ID          string                 `json:"id"`
	UserID      *string                `json:"user_id,omitempty"`
	Event       string                 `json:"event"`
	Description string                 `json:"description"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Metadata    map[string]interface{} `json:"metadata"`
	Severity    string                 `json:"severity"` // low, medium, high, critical
	CreatedAt   time.Time              `json:"created_at"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Event       string                 `json:"event"`
	UserID      *string                `json:"user_id,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Severity    string                 `json:"severity"`
}

// NewAuditService creates a new audit service
func NewAuditService() *AuditService {
	return &AuditService{}
}

// LogEvent logs a general audit event
func (s *AuditService) LogEvent(userID *string, event, description, ipAddress, userAgent string, metadata map[string]interface{}, severity string) error {
	auditEvent := &AuditEvent{
		ID:          s.generateEventID(),
		UserID:      userID,
		Event:       event,
		Description: description,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Metadata:    metadata,
		Severity:    severity,
		CreatedAt:   time.Now(),
	}

	return s.saveAuditEvent(auditEvent)
}

// LogSecurityEvent logs a security-related event
func (s *AuditService) LogSecurityEvent(securityEvent *SecurityEvent) error {
	return s.LogEvent(
		securityEvent.UserID,
		securityEvent.Event,
		securityEvent.Description,
		securityEvent.IPAddress,
		securityEvent.UserAgent,
		securityEvent.Metadata,
		securityEvent.Severity,
	)
}

// LogLogin logs a user login event
func (s *AuditService) LogLogin(user *models.User, ipAddress, userAgent string, success bool, failureReason string) error {
	event := "user.login"
	description := "User login attempt"
	severity := "low"

	if !success {
		event = "user.login_failed"
		description = "Failed login attempt"
		severity = "medium"
	}

	metadata := map[string]interface{}{
		"success":        success,
		"failure_reason": failureReason,
		"user_email":     user.Email,
	}

	return s.LogEvent(&user.ID, event, description, ipAddress, userAgent, metadata, severity)
}

// LogLogout logs a user logout event
func (s *AuditService) LogLogout(user *models.User, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"user_email": user.Email,
	}

	return s.LogEvent(&user.ID, "user.logout", "User logged out", ipAddress, userAgent, metadata, "low")
}

// LogPasswordChange logs a password change event
func (s *AuditService) LogPasswordChange(user *models.User, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"user_email": user.Email,
	}

	return s.LogEvent(&user.ID, "user.password_changed", "User changed password", ipAddress, userAgent, metadata, "medium")
}

// LogPasswordReset logs a password reset event
func (s *AuditService) LogPasswordReset(user *models.User, ipAddress, userAgent string, success bool) error {
	event := "user.password_reset"
	description := "Password reset requested"
	severity := "medium"

	if !success {
		event = "user.password_reset_failed"
		description = "Failed password reset attempt"
		severity = "high"
	}

	metadata := map[string]interface{}{
		"success":    success,
		"user_email": user.Email,
	}

	return s.LogEvent(&user.ID, event, description, ipAddress, userAgent, metadata, severity)
}

// LogMfaEvent logs MFA-related events
func (s *AuditService) LogMfaEvent(user *models.User, event, description, ipAddress, userAgent string, metadata map[string]interface{}) error {
	severity := "medium"
	if event == "mfa.enabled" || event == "mfa.disabled" {
		severity = "high"
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["user_email"] = user.Email

	return s.LogEvent(&user.ID, event, description, ipAddress, userAgent, metadata, severity)
}

// LogWebAuthnEvent logs WebAuthn-related events
func (s *AuditService) LogWebAuthnEvent(user *models.User, event, description, ipAddress, userAgent string, metadata map[string]interface{}) error {
	severity := "medium"
	if event == "webauthn.credential_registered" || event == "webauthn.credential_removed" {
		severity = "high"
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["user_email"] = user.Email

	return s.LogEvent(&user.ID, event, description, ipAddress, userAgent, metadata, severity)
}

// LogAccountLockout logs an account lockout event
func (s *AuditService) LogAccountLockout(user *models.User, ipAddress, userAgent string, reason string) error {
	metadata := map[string]interface{}{
		"user_email":      user.Email,
		"reason":          reason,
		"failed_attempts": user.FailedLoginAttempts,
	}

	return s.LogEvent(&user.ID, "user.account_locked", "Account locked due to failed login attempts", ipAddress, userAgent, metadata, "high")
}

// LogSuspiciousActivity logs suspicious activity
func (s *AuditService) LogSuspiciousActivity(userID *string, activity, description, ipAddress, userAgent string, metadata map[string]interface{}) error {
	return s.LogEvent(userID, "security.suspicious_activity", description, ipAddress, userAgent, metadata, "critical")
}

// GetUserAuditLogs gets audit logs for a specific user with cursor-based pagination
func (s *AuditService) GetUserAuditLogs(userID string, cursor string, limit int) ([]*AuditEvent, error) {
	// This would typically query the audit logs table with cursor-based pagination
	// For now, return an empty slice
	return []*AuditEvent{}, nil
}

// GetSecurityEvents gets security events with specified severity using cursor-based pagination
func (s *AuditService) GetSecurityEvents(severity string, cursor string, limit int) ([]*AuditEvent, error) {
	// This would typically query the audit logs table with cursor-based pagination
	// For now, return an empty slice
	return []*AuditEvent{}, nil
}

// LogMultiAccountActivity logs multi-account related activities
func (s *AuditService) LogMultiAccountActivity(ctx http.Context, action string, details map[string]interface{}) error {
	// Get current user context
	var currentUserID string
	if userID := ctx.Value("user_id"); userID != nil {
		currentUserID = userID.(string)
	}

	// Prepare activity properties
	properties := map[string]interface{}{
		"action":     action,
		"category":   "multi_account",
		"user_id":    currentUserID,
		"ip_address": ctx.Request().Ip(),
		"user_agent": ctx.Request().Header("User-Agent", ""),
		"session_id": ctx.Request().Session().GetID(),
		"timestamp":  time.Now(),
		"details":    details,
	}

	// Add request context
	properties["request_method"] = ctx.Request().Method()
	properties["request_path"] = ctx.Request().Path()

	// Add referer if available
	if referer := ctx.Request().Header("Referer", ""); referer != "" {
		properties["referer"] = referer
	}

	// Convert properties to JSON
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %v", err)
	}

	// Create activity log entry using the correct structure
	activityLog := models.ActivityLog{
		LogName:     "multi_account",
		Description: s.formatMultiAccountDescription(action, details),
		SubjectType: "User",
		SubjectID:   currentUserID,
		CauserType:  "User",
		CauserID:    currentUserID,
		Properties:  propsJSON,
		TenantID:    "", // Set tenant ID if available in context
	}

	// Save to database
	err = facades.Orm().Query().Create(&activityLog)
	if err != nil {
		facades.Log().Error("Failed to save multi-account activity log", map[string]interface{}{
			"error":      err.Error(),
			"activity":   action,
			"user_id":    currentUserID,
			"session_id": ctx.Request().Session().GetID(),
		})
		return fmt.Errorf("failed to save activity log: %v", err)
	}

	// Log to application logs for real-time monitoring
	logLevel := s.getLogLevelForAction(action)
	logData := map[string]interface{}{
		"audit_id":   activityLog.ID,
		"action":     action,
		"user_id":    currentUserID,
		"ip_address": ctx.Request().Ip(),
		"session_id": ctx.Request().Session().GetID(),
		"details":    details,
	}

	switch logLevel {
	case "warning":
		facades.Log().Warning("Multi-account activity", logData)
	case "error":
		facades.Log().Error("Multi-account security event", logData)
	default:
		facades.Log().Info("Multi-account activity", logData)
	}

	return nil
}

// formatMultiAccountDescription creates human-readable descriptions for multi-account activities
func (s *AuditService) formatMultiAccountDescription(action string, details map[string]interface{}) string {
	switch action {
	case "account_added":
		if email, ok := details["email"].(string); ok {
			return fmt.Sprintf("Added account %s to multi-account session", email)
		}
		return "Added new account to multi-account session"

	case "account_switched":
		if email, ok := details["switched_to_email"].(string); ok {
			return fmt.Sprintf("Switched to account %s", email)
		}
		return "Switched active account"

	case "account_removed":
		if email, ok := details["removed_email"].(string); ok {
			return fmt.Sprintf("Removed account %s from session", email)
		}
		return "Removed account from multi-account session"

	case "session_extended":
		if email, ok := details["email"].(string); ok {
			return fmt.Sprintf("Extended session for account %s", email)
		}
		return "Extended account session"

	case "account_refreshed":
		if email, ok := details["email"].(string); ok {
			return fmt.Sprintf("Refreshed data for account %s", email)
		}
		return "Refreshed account data"

	case "rate_limit_exceeded":
		return "Account switching rate limit exceeded"

	case "session_expired":
		if email, ok := details["email"].(string); ok {
			return fmt.Sprintf("Session expired for account %s", email)
		}
		return "Account session expired"

	case "validation_failed":
		if reason, ok := details["reason"].(string); ok {
			return fmt.Sprintf("Account validation failed: %s", reason)
		}
		return "Account validation failed"

	case "all_accounts_cleared":
		return "Cleared all accounts from multi-account session"

	case "inactive_accounts_cleanup":
		if count, ok := details["removed_count"].(int); ok {
			return fmt.Sprintf("Cleaned up %d inactive account sessions", count)
		}
		return "Cleaned up inactive account sessions"

	default:
		return fmt.Sprintf("Multi-account action: %s", action)
	}
}

// getLogLevelForAction determines the appropriate log level for different actions
func (s *AuditService) getLogLevelForAction(action string) string {
	securityActions := map[string]string{
		"rate_limit_exceeded":      "warning",
		"validation_failed":        "warning",
		"session_expired":          "info",
		"unauthorized_access":      "error",
		"suspicious_activity":      "error",
		"account_takeover_attempt": "error",
	}

	if level, exists := securityActions[action]; exists {
		return level
	}

	return "info"
}

// LogMultiAccountSecurityEvent logs security-related events for multi-account operations
func (s *AuditService) LogMultiAccountSecurityEvent(ctx http.Context, eventType string, severity string, details map[string]interface{}) error {
	// Get current user context
	var currentUserID string
	if userID := ctx.Value("user_id"); userID != nil {
		currentUserID = userID.(string)
	}

	// Enhanced security logging with additional context
	properties := map[string]interface{}{
		"event_type":  eventType,
		"severity":    severity,
		"category":    "security",
		"subcategory": "multi_account",
		"timestamp":   time.Now(),
		"details":     details,
		"ip_address":  ctx.Request().Ip(),
		"user_agent":  ctx.Request().Header("User-Agent", ""),
		"session_id":  ctx.Request().Session().GetID(),
		"request_id":  ctx.Request().Header("X-Request-ID", ""),
	}

	// Add geographic information if available
	if country := ctx.Request().Header("CF-IPCountry", ""); country != "" {
		properties["country"] = country
	}

	// Add current user context
	properties["user_id"] = currentUserID

	// Convert properties to JSON
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %v", err)
	}

	// Create activity log entry
	activityLog := models.ActivityLog{
		LogName:     "security",
		Description: s.formatSecurityEventDescription(eventType, details),
		SubjectType: "User",
		SubjectID:   currentUserID,
		CauserType:  "System",
		CauserID:    "security_monitor",
		Properties:  propsJSON,
		TenantID:    "", // Set tenant ID if available in context
	}

	// Save to database
	err = facades.Orm().Query().Create(&activityLog)
	if err != nil {
		facades.Log().Error("Failed to save security event log", map[string]interface{}{
			"error":      err.Error(),
			"event_type": eventType,
			"severity":   severity,
		})
		return fmt.Errorf("failed to save security event log: %v", err)
	}

	// Log to application logs based on severity
	logData := map[string]interface{}{
		"audit_id":   activityLog.ID,
		"event_type": eventType,
		"severity":   severity,
		"details":    details,
		"user_id":    currentUserID,
		"ip_address": ctx.Request().Ip(),
		"session_id": ctx.Request().Session().GetID(),
	}

	switch severity {
	case "critical":
		facades.Log().Error("CRITICAL SECURITY EVENT", logData)
	case "high":
		facades.Log().Error("High severity security event", logData)
	case "medium":
		facades.Log().Warning("Medium severity security event", logData)
	case "low":
		facades.Log().Info("Low severity security event", logData)
	default:
		facades.Log().Info("Security event", logData)
	}

	return nil
}

// formatSecurityEventDescription creates descriptions for security events
func (s *AuditService) formatSecurityEventDescription(eventType string, details map[string]interface{}) string {
	switch eventType {
	case "suspicious_login_pattern":
		return "Suspicious login pattern detected in multi-account session"
	case "rapid_account_switching":
		return "Rapid account switching detected - possible automation"
	case "session_hijack_attempt":
		return "Possible session hijacking attempt detected"
	case "concurrent_session_abuse":
		return "Concurrent session abuse detected"
	case "privilege_escalation_attempt":
		return "Privilege escalation attempt through account switching"
	default:
		return fmt.Sprintf("Security event: %s", eventType)
	}
}

// GetMultiAccountAuditTrail retrieves audit trail for multi-account activities
func (s *AuditService) GetMultiAccountAuditTrail(userID string, limit int, offset int) ([]models.ActivityLog, error) {
	var activities []models.ActivityLog

	query := facades.Orm().Query().
		Where("subject_id = ? OR causer_id = ?", userID, userID).
		Where("log_name IN (?)", []string{"multi_account", "security"}).
		OrderBy("created_at", "desc")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&activities)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve audit trail: %v", err)
	}

	return activities, nil
}

// GetMultiAccountSecurityEvents retrieves security events for analysis
func (s *AuditService) GetMultiAccountSecurityEvents(timeRange time.Duration, severity string) ([]models.ActivityLog, error) {
	var events []models.ActivityLog

	since := time.Now().Add(-timeRange)
	query := facades.Orm().Query().
		Where("created_at >= ?", since).
		Where("log_name = ?", "security")

	if severity != "" {
		query = query.Where("JSON_EXTRACT(properties, '$.severity') = ?", severity)
	}

	err := query.OrderBy("created_at", "desc").Find(&events)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve security events: %v", err)
	}

	return events, nil
}

// AnalyzeSecurityPatterns analyzes patterns in multi-account usage for security insights
func (s *AuditService) AnalyzeSecurityPatterns(userID string, timeRange time.Duration) (map[string]interface{}, error) {
	since := time.Now().Add(-timeRange)

	// Get all multi-account activities for the user
	var activities []models.ActivityLog
	err := facades.Orm().Query().
		Where("subject_id = ? OR causer_id = ?", userID, userID).
		Where("created_at >= ?", since).
		Where("log_name = ?", "multi_account").
		OrderBy("created_at", "asc").
		Find(&activities)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve activities for analysis: %v", err)
	}

	analysis := map[string]interface{}{
		"total_activities":    len(activities),
		"time_range_hours":    timeRange.Hours(),
		"activity_breakdown":  make(map[string]int),
		"hourly_distribution": make(map[int]int),
		"suspicious_patterns": []string{},
		"risk_score":          0,
	}

	// Analyze activity patterns
	var switchCount int
	var lastSwitchTime time.Time
	var rapidSwitches int

	for _, activity := range activities {
		// Parse properties to get action
		var props map[string]interface{}
		if err := json.Unmarshal(activity.Properties, &props); err == nil {
			if action, ok := props["action"].(string); ok {
				// Count activity types
				if breakdown, ok := analysis["activity_breakdown"].(map[string]int); ok {
					breakdown[action]++
				}

				// Detect rapid switching
				if action == "account_switched" {
					switchCount++
					if !lastSwitchTime.IsZero() && activity.CreatedAt.Sub(lastSwitchTime) < 30*time.Second {
						rapidSwitches++
					}
					lastSwitchTime = activity.CreatedAt
				}
			}
		}

		// Analyze hourly distribution
		hour := activity.CreatedAt.Hour()
		if hourly, ok := analysis["hourly_distribution"].(map[int]int); ok {
			hourly[hour]++
		}
	}

	// Calculate risk score and identify suspicious patterns
	riskScore := 0
	suspiciousPatterns := []string{}

	if switchCount > 50 {
		riskScore += 3
		suspiciousPatterns = append(suspiciousPatterns, "Excessive account switching")
	}

	if rapidSwitches > 10 {
		riskScore += 2
		suspiciousPatterns = append(suspiciousPatterns, "Rapid account switching detected")
	}

	// Check for unusual time patterns
	if hourly, ok := analysis["hourly_distribution"].(map[int]int); ok {
		nightActivity := hourly[0] + hourly[1] + hourly[2] + hourly[3] + hourly[4] + hourly[5]
		if nightActivity > len(activities)/3 {
			riskScore += 1
			suspiciousPatterns = append(suspiciousPatterns, "Unusual activity during night hours")
		}
	}

	analysis["risk_score"] = riskScore
	analysis["suspicious_patterns"] = suspiciousPatterns
	analysis["switch_count"] = switchCount
	analysis["rapid_switches"] = rapidSwitches

	return analysis, nil
}

// Helper methods

func (s *AuditService) generateEventID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

func (s *AuditService) saveAuditEvent(event *AuditEvent) error {
	// Prepare properties
	properties := s.convertMetadataToJSON(event.Metadata)

	// Add additional metadata
	if event.IPAddress != "" {
		properties["ip_address"] = event.IPAddress
	}
	if event.UserAgent != "" {
		properties["user_agent"] = event.UserAgent
	}
	properties["severity"] = event.Severity

	// Convert to JSON
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return err
	}

	// Save to database
	auditLog := &models.ActivityLog{
		LogName:     event.Event,
		Description: event.Description,
		SubjectType: "User",
		SubjectID:   *event.UserID,
		CauserType:  "User",
		CauserID:    *event.UserID,
		Properties:  propsJSON,
	}

	return facades.Orm().Query().Create(auditLog)
}

func (s *AuditService) convertMetadataToJSON(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return make(map[string]interface{})
	}
	return metadata
}
