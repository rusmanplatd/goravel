package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

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
