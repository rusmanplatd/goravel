package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type AuditService struct{}

func NewAuditService() *AuditService {
	return &AuditService{}
}

// AuditEvent represents different types of audit events
type AuditEvent string

const (
	// Authentication Events
	EventLoginSuccess       AuditEvent = "auth.login.success"
	EventLoginFailed        AuditEvent = "auth.login.failed"
	EventLoginLocked        AuditEvent = "auth.login.locked"
	EventLogout             AuditEvent = "auth.logout"
	EventPasswordChanged    AuditEvent = "auth.password.changed"
	EventPasswordReset      AuditEvent = "auth.password.reset"
	EventAccountActivated   AuditEvent = "auth.account.activated"
	EventAccountDeactivated AuditEvent = "auth.account.deactivated"

	// MFA Events
	EventMFAEnabled         AuditEvent = "auth.mfa.enabled"
	EventMFADisabled        AuditEvent = "auth.mfa.disabled"
	EventMFASuccess         AuditEvent = "auth.mfa.success"
	EventMFAFailed          AuditEvent = "auth.mfa.failed"
	EventMFABackupUsed      AuditEvent = "auth.mfa.backup_used"
	EventMFABackupGenerated AuditEvent = "auth.mfa.backup_generated"

	// WebAuthn Events
	EventWebAuthnEnabled    AuditEvent = "auth.webauthn.enabled"
	EventWebAuthnDisabled   AuditEvent = "auth.webauthn.disabled"
	EventWebAuthnRegistered AuditEvent = "auth.webauthn.registered"
	EventWebAuthnRemoved    AuditEvent = "auth.webauthn.removed"
	EventWebAuthnSuccess    AuditEvent = "auth.webauthn.success"
	EventWebAuthnFailed     AuditEvent = "auth.webauthn.failed"

	// Session Events
	EventSessionCreated AuditEvent = "session.created"
	EventSessionExpired AuditEvent = "session.expired"
	EventSessionRevoked AuditEvent = "session.revoked"
	EventTokenRefreshed AuditEvent = "session.token_refreshed"

	// Security Events
	EventRateLimitExceeded   AuditEvent = "security.rate_limit_exceeded"
	EventSuspiciousActivity  AuditEvent = "security.suspicious_activity"
	EventIPBlocked           AuditEvent = "security.ip_blocked"
	EventUnauthorizedAccess  AuditEvent = "security.unauthorized_access"
	EventPrivilegeEscalation AuditEvent = "security.privilege_escalation"
	EventDataBreach          AuditEvent = "security.data_breach"

	// Permission Events
	EventPermissionGranted AuditEvent = "permission.granted"
	EventPermissionRevoked AuditEvent = "permission.revoked"
	EventRoleAssigned      AuditEvent = "role.assigned"
	EventRoleRemoved       AuditEvent = "role.removed"

	// Data Events
	EventDataAccessed AuditEvent = "data.accessed"
	EventDataModified AuditEvent = "data.modified"
	EventDataDeleted  AuditEvent = "data.deleted"
	EventDataExported AuditEvent = "data.exported"

	// Multi-account Events
	EventAccountAdded       AuditEvent = "multi_account.account_added"
	EventAccountSwitched    AuditEvent = "multi_account.account_switched"
	EventAccountRemoved     AuditEvent = "multi_account.account_removed"
	EventSessionExtended    AuditEvent = "multi_account.session_extended"
	EventAccountRefreshed   AuditEvent = "multi_account.account_refreshed"
	EventAllAccountsCleared AuditEvent = "multi_account.all_accounts_cleared"

	// Organization Events
	EventOrganizationCreated AuditEvent = "organization.created"
	EventOrganizationUpdated AuditEvent = "organization.updated"
	EventOrganizationDeleted AuditEvent = "organization.deleted"
	EventUserInvited         AuditEvent = "organization.user_invited"
	EventUserRemoved         AuditEvent = "organization.user_removed"
)

// AuditContext contains context information for audit events
type AuditContext struct {
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Method      string                 `json:"method,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Resource    string                 `json:"resource,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ThreatLevel string                 `json:"threat_level,omitempty"`
	GeoLocation *GeoLocation           `json:"geo_location,omitempty"`
}

// GeoLocation represents geographical information
type GeoLocation struct {
	Country   string  `json:"country,omitempty"`
	Region    string  `json:"region,omitempty"`
	City      string  `json:"city,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	ISP       string  `json:"isp,omitempty"`
}

// LogEvent logs an audit event with context
func (s *AuditService) LogEvent(event AuditEvent, message string, context *AuditContext) {
	// Prepare properties with all context information
	properties := map[string]interface{}{
		"event":        string(event),
		"ip_address":   context.IPAddress,
		"user_agent":   context.UserAgent,
		"path":         context.Path,
		"method":       context.Method,
		"session_id":   context.SessionID,
		"threat_level": context.ThreatLevel,
	}

	// Add metadata if available
	if context.Metadata != nil {
		for k, v := range context.Metadata {
			properties[k] = v
		}
	}

	// Add geo location if available
	if context.GeoLocation != nil {
		properties["geo_location"] = context.GeoLocation
	}

	// Determine severity level
	severity := s.determineSeverity(event)
	properties["severity"] = severity

	// Convert properties to JSON
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		facades.Log().Error("Failed to marshal audit properties", map[string]interface{}{
			"error": err.Error(),
		})
		propsJSON = []byte("{}")
	}

	// Create activity log entry
	activityLog := &models.ActivityLog{
		LogName:     "audit",
		Description: message,
		SubjectType: "User",
		SubjectID:   context.UserID,
		CauserType:  "System",
		CauserID:    "audit_system",
		Properties:  propsJSON,
	}

	// Save to database
	if err := facades.Orm().Query().Create(activityLog); err != nil {
		facades.Log().Error("Failed to save audit log", map[string]interface{}{
			"error":   err.Error(),
			"event":   event,
			"message": message,
		})
	}

	// Log to application log as well
	logLevel := s.getLogLevel(severity)
	logData := map[string]interface{}{
		"audit_event": event,
		"message":     message,
		"context":     context,
		"timestamp":   time.Now(),
	}

	switch logLevel {
	case "error":
		facades.Log().Error("AUDIT: "+message, logData)
	case "warning":
		facades.Log().Warning("AUDIT: "+message, logData)
	case "info":
		facades.Log().Info("AUDIT: "+message, logData)
	default:
		facades.Log().Debug("AUDIT: "+message, logData)
	}

	// Check for security threats
	s.analyzeSecurityThreat(event, context)

	// Send alerts for critical events
	if s.isCriticalEvent(event) {
		s.sendSecurityAlert(event, message, context)
	}
}

// LogEventCompat provides compatibility with the old LogEvent signature
func (s *AuditService) LogEventCompat(userID *string, event, description, ipAddress, userAgent string, metadata map[string]interface{}, severity string) error {
	context := &AuditContext{
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Metadata:  metadata,
	}

	if userID != nil {
		context.UserID = *userID
	}

	s.LogEvent(AuditEvent(event), description, context)
	return nil
}

// LogAuthenticationEvent logs authentication-related events
func (s *AuditService) LogAuthenticationEvent(event AuditEvent, userID string, ctx http.Context, metadata map[string]interface{}) {
	context := s.buildContextFromHTTP(ctx)
	context.UserID = userID
	context.Metadata = metadata

	var message string
	switch event {
	case EventLoginSuccess:
		message = "User successfully authenticated"
	case EventLoginFailed:
		message = "User authentication failed"
	case EventLoginLocked:
		message = "User account locked due to failed attempts"
	case EventLogout:
		message = "User logged out"
	default:
		message = fmt.Sprintf("Authentication event: %s", event)
	}

	s.LogEvent(event, message, context)
}

// LogSecurityEvent logs security-related events
func (s *AuditService) LogSecurityEvent(event AuditEvent, message string, ctx http.Context, metadata map[string]interface{}) {
	context := s.buildContextFromHTTP(ctx)
	context.Metadata = metadata
	context.ThreatLevel = s.assessThreatLevel(event, context)

	s.LogEvent(event, message, context)
}

// LogDataAccess logs data access events
func (s *AuditService) LogDataAccess(resource, action string, userID string, ctx http.Context, metadata map[string]interface{}) {
	context := s.buildContextFromHTTP(ctx)
	context.UserID = userID
	context.Resource = resource
	context.Action = action
	context.Metadata = metadata

	message := fmt.Sprintf("User accessed %s with action %s", resource, action)
	s.LogEvent(EventDataAccessed, message, context)
}

// LogPermissionChange logs permission and role changes
func (s *AuditService) LogPermissionChange(event AuditEvent, targetUserID, changedBy string, details map[string]interface{}) {
	context := &AuditContext{
		UserID:   changedBy,
		Metadata: details,
	}

	if targetUserID != "" {
		context.Metadata["target_user_id"] = targetUserID
	}

	var message string
	switch event {
	case EventPermissionGranted:
		message = "Permission granted to user"
	case EventPermissionRevoked:
		message = "Permission revoked from user"
	case EventRoleAssigned:
		message = "Role assigned to user"
	case EventRoleRemoved:
		message = "Role removed from user"
	default:
		message = fmt.Sprintf("Permission change: %s", event)
	}

	s.LogEvent(event, message, context)
}

// GetUserActivityHistory retrieves activity history for a user
func (s *AuditService) GetUserActivityHistory(userID string, limit int, offset int) ([]models.ActivityLog, error) {
	var activities []models.ActivityLog

	query := facades.Orm().Query().Where("subject_id", userID)
	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.OrderBy("created_at", "desc").Find(&activities)
	return activities, err
}

// GetSecurityEvents retrieves security-related events
func (s *AuditService) GetSecurityEvents(since time.Time, limit int) ([]models.ActivityLog, error) {
	var activities []models.ActivityLog

	securityEvents := []interface{}{
		string(EventRateLimitExceeded),
		string(EventSuspiciousActivity),
		string(EventIPBlocked),
		string(EventUnauthorizedAccess),
		string(EventPrivilegeEscalation),
		string(EventDataBreach),
	}

	query := facades.Orm().Query().
		Where("log_name", "audit").
		Where("JSON_EXTRACT(properties, '$.event') IN (?)", securityEvents).
		Where("created_at", ">=", since)

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.OrderBy("created_at", "desc").Find(&activities)
	return activities, err
}

// DetectAnomalousActivity detects anomalous user activity patterns
func (s *AuditService) DetectAnomalousActivity(userID string) ([]string, error) {
	var anomalies []string

	// Check for unusual login times
	if s.hasUnusualLoginTimes(userID) {
		anomalies = append(anomalies, "Unusual login times detected")
	}

	// Check for multiple IP addresses
	if s.hasMultipleIPs(userID) {
		anomalies = append(anomalies, "Multiple IP addresses used")
	}

	// Check for rapid successive actions
	if s.hasRapidActions(userID) {
		anomalies = append(anomalies, "Rapid successive actions detected")
	}

	// Check for privilege escalation attempts
	if s.hasPrivilegeEscalationAttempts(userID) {
		anomalies = append(anomalies, "Privilege escalation attempts detected")
	}

	return anomalies, nil
}

// Helper methods

func (s *AuditService) buildContextFromHTTP(ctx http.Context) *AuditContext {
	if ctx == nil {
		return &AuditContext{}
	}

	context := &AuditContext{
		IPAddress: s.getClientIP(ctx),
		UserAgent: ctx.Request().Header("User-Agent", ""),
		Path:      ctx.Request().Path(),
		Method:    ctx.Request().Method(),
	}

	// Try to get user ID from context
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			context.UserID = id
		}
	}

	// Try to get session ID from JWT claims
	if claims := ctx.Value("jwt_claims"); claims != nil {
		if jwtClaims, ok := claims.(*JWTClaims); ok {
			context.SessionID = jwtClaims.SessionID
		}
	}

	// Add geo location if available
	context.GeoLocation = s.getGeoLocation(context.IPAddress)

	return context
}

func (s *AuditService) getClientIP(ctx http.Context) string {
	// Check X-Forwarded-For header first
	if xff := ctx.Request().Header("X-Forwarded-For", ""); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := ctx.Request().Header("X-Real-IP", ""); xri != "" {
		return xri
	}

	// Fallback to request IP
	return ctx.Request().Ip()
}

func (s *AuditService) getGeoLocation(ip string) *GeoLocation {
	// This would typically integrate with a GeoIP service
	// For now, return a placeholder
	if ip == "127.0.0.1" || ip == "::1" {
		return &GeoLocation{
			Country: "Local",
			Region:  "Local",
			City:    "Local",
			ISP:     "Local",
		}
	}

	// In production, you would use a service like MaxMind GeoIP
	return &GeoLocation{
		Country: "Unknown",
		Region:  "Unknown",
		City:    "Unknown",
		ISP:     "Unknown",
	}
}

func (s *AuditService) determineSeverity(event AuditEvent) string {
	switch event {
	case EventDataBreach, EventPrivilegeEscalation, EventUnauthorizedAccess:
		return "critical"
	case EventLoginFailed, EventMFAFailed, EventWebAuthnFailed, EventSuspiciousActivity, EventIPBlocked:
		return "high"
	case EventRateLimitExceeded, EventLoginLocked, EventSessionExpired:
		return "medium"
	case EventLoginSuccess, EventLogout, EventMFASuccess, EventWebAuthnSuccess:
		return "low"
	default:
		return "info"
	}
}

func (s *AuditService) getLogLevel(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "warning"
	case "medium", "low":
		return "info"
	default:
		return "debug"
	}
}

func (s *AuditService) assessThreatLevel(event AuditEvent, context *AuditContext) string {
	switch event {
	case EventDataBreach, EventPrivilegeEscalation:
		return "critical"
	case EventUnauthorizedAccess, EventSuspiciousActivity:
		return "high"
	case EventRateLimitExceeded, EventLoginFailed:
		return "medium"
	default:
		return "low"
	}
}

func (s *AuditService) isCriticalEvent(event AuditEvent) bool {
	criticalEvents := []AuditEvent{
		EventDataBreach,
		EventPrivilegeEscalation,
		EventUnauthorizedAccess,
		EventSuspiciousActivity,
	}

	for _, critical := range criticalEvents {
		if event == critical {
			return true
		}
	}

	return false
}

func (s *AuditService) analyzeSecurityThreat(event AuditEvent, context *AuditContext) {
	// Implement threat analysis logic
	// This could include machine learning models, pattern recognition, etc.

	if context.UserID != "" {
		// Check for brute force attacks
		if event == EventLoginFailed {
			s.checkBruteForceAttack(context.UserID, context.IPAddress)
		}

		// Check for account takeover indicators
		if event == EventLoginSuccess {
			s.checkAccountTakeoverIndicators(context.UserID, context)
		}
	}
}

func (s *AuditService) sendSecurityAlert(event AuditEvent, message string, context *AuditContext) {
	// Send alerts to security team
	alertData := map[string]interface{}{
		"event":     event,
		"message":   message,
		"context":   context,
		"timestamp": time.Now(),
		"severity":  s.determineSeverity(event),
	}

	// This would typically send to:
	// - Email alerts
	// - Slack/Discord webhooks
	// - SIEM systems
	// - Security monitoring tools

	facades.Log().Error("SECURITY ALERT", alertData)
}

func (s *AuditService) checkBruteForceAttack(userID, ipAddress string) {
	// Check for multiple failed login attempts
	var activities []models.ActivityLog
	since := time.Now().Add(-15 * time.Minute)

	err := facades.Orm().Query().
		Where("subject_id", userID).
		Where("log_name", "audit").
		Where("JSON_EXTRACT(properties, '$.event') = ?", string(EventLoginFailed)).
		Where("created_at", ">=", since).
		Find(&activities)

	if err == nil && len(activities) > 5 {
		s.LogSecurityEvent(EventSuspiciousActivity,
			"Potential brute force attack detected",
			nil,
			map[string]interface{}{
				"user_id":    userID,
				"ip_address": ipAddress,
				"attempts":   len(activities),
			})
	}
}

func (s *AuditService) checkAccountTakeoverIndicators(userID string, context *AuditContext) {
	// Check for indicators of account takeover:
	// - Login from new location
	// - Login from new device
	// - Unusual time of access
	// - Multiple concurrent sessions

	// This would implement sophisticated detection logic
}

func (s *AuditService) hasUnusualLoginTimes(userID string) bool {
	// Analyze user's typical login patterns and detect anomalies
	return false
}

func (s *AuditService) hasMultipleIPs(userID string) bool {
	// Check if user has logged in from multiple IPs recently
	return false
}

func (s *AuditService) hasRapidActions(userID string) bool {
	// Check for unusually rapid successive actions
	return false
}

func (s *AuditService) hasPrivilegeEscalationAttempts(userID string) bool {
	// Check for attempts to access resources beyond user's permissions
	return false
}

// LogSimpleEvent provides a simplified way to log events for other services
func (s *AuditService) LogSimpleEvent(event AuditEvent, message string, metadata map[string]interface{}) {
	context := &AuditContext{
		Metadata: metadata,
	}
	s.LogEvent(event, message, context)
}

// LogUserEvent logs an event for a specific user
func (s *AuditService) LogUserEvent(userID string, event AuditEvent, message string, metadata map[string]interface{}) {
	context := &AuditContext{
		UserID:   userID,
		Metadata: metadata,
	}
	s.LogEvent(event, message, context)
}
