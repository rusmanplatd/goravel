package services

import (
	"bytes"
	"context"
	stdcontext "context"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"strings"
	"sync"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/notifications"
)

type AuditService struct {
	batchBuffer        []*models.ActivityLog
	batchMutex         sync.RWMutex
	batchSize          int
	flushInterval      time.Duration
	stopChan           chan struct{}
	geoIPService       *GeoIPService
	activityLogger     *models.ActivityLogger
	streamingService   *AuditStreamingService
	correlationService *AuditCorrelationService
}

func NewAuditService() *AuditService {
	service := &AuditService{
		batchBuffer:        make([]*models.ActivityLog, 0),
		batchSize:          100,
		flushInterval:      5 * time.Second,
		stopChan:           make(chan struct{}),
		geoIPService:       NewGeoIPService(),
		activityLogger:     models.NewActivityLogger(),
		streamingService:   NewAuditStreamingService(),
		correlationService: NewAuditCorrelationService(),
	}

	// Start batch processing goroutine
	go service.startBatchProcessor()

	return service
}

// Close gracefully shuts down the audit service
func (s *AuditService) Close() error {
	close(s.stopChan)
	s.flushBatch() // Flush remaining items
	if s.geoIPService != nil {
		s.geoIPService.Close()
	}
	if s.streamingService != nil {
		s.streamingService.Close()
	}
	return nil
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
	EventThreatDetected      AuditEvent = "security.threat_detected"
	EventAnomalyDetected     AuditEvent = "security.anomaly_detected"

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
	EventDataImported AuditEvent = "data.imported"

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

	// Compliance Events
	EventComplianceViolation AuditEvent = "compliance.violation"
	EventDataRetention       AuditEvent = "compliance.data_retention"
	EventAuditExport         AuditEvent = "compliance.audit_export"

	// Performance Events
	EventPerformanceAlert AuditEvent = "performance.alert"
	EventSlowQuery        AuditEvent = "performance.slow_query"
	EventHighMemoryUsage  AuditEvent = "performance.high_memory"
	EventHighCPUUsage     AuditEvent = "performance.high_cpu"
)

// AuditContext contains context information for audit events
type AuditContext struct {
	UserID        string                 `json:"user_id,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	Path          string                 `json:"path,omitempty"`
	Method        string                 `json:"method,omitempty"`
	StatusCode    int                    `json:"status_code,omitempty"`
	Duration      time.Duration          `json:"duration,omitempty"`
	Resource      string                 `json:"resource,omitempty"`
	Action        string                 `json:"action,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	ThreatLevel   string                 `json:"threat_level,omitempty"`
	GeoLocation   *models.GeoLocation    `json:"geo_location,omitempty"`
	DeviceInfo    map[string]interface{} `json:"device_info,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	RiskScore     int                    `json:"risk_score,omitempty"`
	BatchID       string                 `json:"batch_id,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
}

// LogEvent logs an audit event with context (now uses batch processing)
func (s *AuditService) LogEvent(event AuditEvent, message string, context *AuditContext) {
	if context == nil {
		context = &AuditContext{}
	}

	// Determine category based on event
	category := s.determineCategory(event)

	// Determine severity level
	severity := s.determineSeverity(event)

	// Determine status based on event and context
	status := s.determineStatus(event, context)

	// Calculate risk score if not provided
	if context.RiskScore == 0 {
		context.RiskScore = s.calculateRiskScore(event, context)
	}

	// Prepare geo location
	var geoLocationJSON json.RawMessage
	if context.GeoLocation != nil {
		if data, err := json.Marshal(context.GeoLocation); err == nil {
			geoLocationJSON = data
		}
	} else if context.IPAddress != "" {
		if geoLoc := s.getGeoLocation(context.IPAddress); geoLoc != nil {
			if data, err := json.Marshal(geoLoc); err == nil {
				geoLocationJSON = data
			}
		}
	}

	// Prepare device info
	var deviceInfoJSON json.RawMessage
	if context.DeviceInfo != nil {
		if data, err := json.Marshal(context.DeviceInfo); err == nil {
			deviceInfoJSON = data
		}
	}

	// Prepare tags
	var tagsJSON json.RawMessage
	if context.Tags != nil {
		if data, err := json.Marshal(context.Tags); err == nil {
			tagsJSON = data
		}
	}

	// Prepare properties with all context information
	properties := map[string]interface{}{
		"event":          string(event),
		"correlation_id": context.CorrelationID,
		"batch_id":       context.BatchID,
	}

	// Add metadata if available
	if context.Metadata != nil {
		for k, v := range context.Metadata {
			properties[k] = v
		}
	}

	// Convert properties to JSON
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		facades.Log().Error("Failed to marshal audit properties", map[string]interface{}{
			"error": err.Error(),
		})
		propsJSON = []byte("{}")
	}

	// Prepare compliance flags
	complianceFlags := s.determineComplianceFlags(event, context)
	var complianceFlagsJSON json.RawMessage
	if complianceFlags != nil {
		if data, err := json.Marshal(complianceFlags); err == nil {
			complianceFlagsJSON = data
		}
	}

	// Create activity log entry
	activityLog := &models.ActivityLog{
		LogName:         string(event),
		Description:     message,
		Category:        category,
		Severity:        severity,
		Status:          status,
		SubjectType:     "User",
		SubjectID:       context.UserID,
		CauserType:      "System",
		CauserID:        "audit_system",
		IPAddress:       context.IPAddress,
		UserAgent:       context.UserAgent,
		RequestPath:     context.Path,
		RequestMethod:   context.Method,
		StatusCode:      context.StatusCode,
		Duration:        int64(context.Duration.Milliseconds()),
		SessionID:       context.SessionID,
		RequestID:       context.RequestID,
		GeoLocation:     geoLocationJSON,
		DeviceInfo:      deviceInfoJSON,
		RiskScore:       context.RiskScore,
		ThreatLevel:     context.ThreatLevel,
		Tags:            tagsJSON,
		Properties:      propsJSON,
		ComplianceFlags: complianceFlagsJSON,
		EventTimestamp:  time.Now(),
		TenantID:        context.TenantID,
	}

	// Add to batch for processing
	s.addToBatch(activityLog)

	// Stream event for real-time monitoring
	if s.streamingService != nil {
		s.streamingService.StreamEvent(activityLog)
	}

	// Correlate event with other events
	if s.correlationService != nil {
		correlationResults, err := s.correlationService.CorrelateEvent(activityLog)
		if err != nil {
			facades.Log().Error("Failed to correlate audit event", map[string]interface{}{
				"error":    err.Error(),
				"event_id": activityLog.ID,
			})
		} else if len(correlationResults) > 0 {
			// Log correlation results
			for _, result := range correlationResults {
				facades.Log().Info("Event correlation detected", map[string]interface{}{
					"correlation_id": result.CorrelationID,
					"rule_name":      result.RuleName,
					"score":          result.Score,
					"event_count":    result.EventCount,
					"severity":       result.Severity,
				})
			}
		}
	}

	// Log to application log as well for immediate visibility
	logLevel := s.getLogLevel(severity)
	logData := map[string]interface{}{
		"audit_event": event,
		"message":     message,
		"context":     context,
		"timestamp":   time.Now(),
		"risk_score":  context.RiskScore,
		"category":    category,
		"severity":    severity,
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

	// Real-time security analysis
	s.analyzeSecurityThreat(event, context)

	// Send alerts for critical events
	if s.isCriticalEvent(event) || context.RiskScore > 80 {
		s.sendSecurityAlert(event, message, context)
	}

	// Real-time notifications for high-risk activities
	if context.RiskScore > 70 || severity == models.SeverityHigh || severity == models.SeverityCritical {
		s.sendRealTimeNotification(event, message, context)
	}
}

// Batch processing methods
func (s *AuditService) addToBatch(activity *models.ActivityLog) {
	s.batchMutex.Lock()
	defer s.batchMutex.Unlock()

	s.batchBuffer = append(s.batchBuffer, activity)

	// Flush if batch is full
	if len(s.batchBuffer) >= s.batchSize {
		go s.flushBatch()
	}
}

func (s *AuditService) startBatchProcessor() {
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flushBatch()
		case <-s.stopChan:
			return
		}
	}
}

func (s *AuditService) flushBatch() {
	s.batchMutex.Lock()
	if len(s.batchBuffer) == 0 {
		s.batchMutex.Unlock()
		return
	}

	batch := make([]*models.ActivityLog, len(s.batchBuffer))
	copy(batch, s.batchBuffer)
	s.batchBuffer = s.batchBuffer[:0] // Clear the buffer
	s.batchMutex.Unlock()

	// Bulk insert
	if err := s.bulkInsertActivities(batch); err != nil {
		facades.Log().Error("Failed to bulk insert audit logs", map[string]interface{}{
			"error": err.Error(),
			"count": len(batch),
		})

		// Fallback: try to insert individually
		for _, activity := range batch {
			if err := s.activityLogger.LogActivity(activity); err != nil {
				facades.Log().Error("Failed to save individual audit log", map[string]interface{}{
					"error":   err.Error(),
					"event":   activity.LogName,
					"message": activity.Description,
				})
			}
		}
	}
}

func (s *AuditService) bulkInsertActivities(activities []*models.ActivityLog) error {
	if len(activities) == 0 {
		return nil
	}

	return facades.Orm().Query().Create(&activities)
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

// LogUserAction logs a user action with comprehensive context information
func (s *AuditService) LogUserAction(userID string, action string, message string, metadata map[string]interface{}) {
	// Enhance metadata with additional context
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add timestamp and correlation information
	metadata["action_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["audit_service_version"] = "1.0"
	metadata["action_type"] = action

	// Add security context
	metadata["audit_level"] = "comprehensive"
	metadata["compliance_relevant"] = true

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithAction(action).
		WithMetadataMap(metadata).
		WithTags("user_action", "comprehensive", "enhanced").
		Build()

	s.LogEvent(EventDataAccessed, message, context)
}

// LogSecurityEventWithSeverity logs a security event with specific severity
func (s *AuditService) LogSecurityEventWithSeverity(event AuditEvent, message string, severity models.ActivityLogSeverity, context *AuditContext) {
	if context == nil {
		context = &AuditContext{}
	}

	// Override calculated severity with provided severity
	if context.Metadata == nil {
		context.Metadata = make(map[string]interface{})
	}
	context.Metadata["override_severity"] = string(severity)

	s.LogEvent(event, message, context)
}

// LogDataAccessEnhanced logs data access events with enhanced context information
func (s *AuditService) LogDataAccessEnhanced(userID, resource, action string, metadata map[string]interface{}) {
	// Enhance metadata with additional context
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add enhanced data access context
	metadata["access_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["audit_service_version"] = "1.0"
	metadata["audit_level"] = "enhanced"
	metadata["compliance_relevant"] = true

	// Add basic resource classification
	if strings.Contains(strings.ToLower(resource), "user") ||
		strings.Contains(strings.ToLower(resource), "profile") ||
		strings.Contains(strings.ToLower(resource), "personal") {
		metadata["data_sensitivity"] = "high"
	} else {
		metadata["data_sensitivity"] = "medium"
	}

	// Add action classification
	if action == "delete" || action == "modify" || action == "update" {
		metadata["action_risk"] = "high"
	} else if action == "read" || action == "view" || action == "list" {
		metadata["action_risk"] = "low"
	} else {
		metadata["action_risk"] = "medium"
	}

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithResource(resource).
		WithAction(action).
		WithMetadataMap(metadata).
		WithTags("data_access", "enhanced", "classified").
		Build()

	message := fmt.Sprintf("Enhanced data access audit: %s performed %s on %s", userID, action, resource)
	s.LogEvent(EventDataAccessed, message, context)
}

// LogAuthEvent logs authentication-related events with comprehensive security context
func (s *AuditService) LogAuthEvent(userID string, event AuditEvent, success bool, metadata map[string]interface{}) {
	// Enhance metadata with security context
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add authentication specific context
	metadata["auth_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["auth_success"] = success
	metadata["audit_service_version"] = "1.0"
	metadata["security_level"] = "high"
	metadata["compliance_relevant"] = true

	// Add event classification
	if success {
		metadata["event_severity"] = "info"
		metadata["security_impact"] = "low"
	} else {
		metadata["event_severity"] = "warning"
		metadata["security_impact"] = "medium"
		metadata["requires_investigation"] = true
	}

	// Add authentication method context if available
	if authMethod, exists := metadata["auth_method"]; exists {
		metadata["auth_method_used"] = authMethod
		if authMethod == "mfa" || authMethod == "webauthn" {
			metadata["strong_auth"] = true
		}
	}

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithMetadata("success", success).
		WithMetadataMap(metadata).
		WithTags("authentication", "security", "enhanced").
		Build()

	message := fmt.Sprintf("Authentication event: %s - %s", event, map[bool]string{true: "SUCCESS", false: "FAILED"}[success])
	if !success {
		message += " (Security Alert)"
	}

	s.LogEvent(event, message, context)
}

// LogBatchEvents logs multiple events with a correlation ID
func (s *AuditService) LogBatchEvents(events []AuditEventData, correlationID string) {
	for _, eventData := range events {
		if eventData.Context == nil {
			eventData.Context = &AuditContext{}
		}

		// Set correlation ID
		eventData.Context.CorrelationID = correlationID

		// Merge metadata from event data into context
		if eventData.Metadata != nil {
			if eventData.Context.Metadata == nil {
				eventData.Context.Metadata = make(map[string]interface{})
			}
			for k, v := range eventData.Metadata {
				eventData.Context.Metadata[k] = v
			}
		}

		s.LogEvent(eventData.Event, eventData.Message, eventData.Context)
	}
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

// LogPerformanceEvent logs performance-related events
func (s *AuditService) LogPerformanceEvent(event AuditEvent, message string, metrics map[string]interface{}, ctx http.Context) {
	context := s.buildContextFromHTTP(ctx)
	context.Metadata = metrics

	s.LogEvent(event, message, context)
}

// LogComplianceEvent logs compliance-related events
func (s *AuditService) LogComplianceEvent(event AuditEvent, message string, complianceType string, details map[string]interface{}) {
	context := &AuditContext{
		Metadata: details,
		Tags:     []string{"compliance", complianceType},
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

	err := query.OrderBy("event_timestamp", "desc").Find(&activities)
	return activities, err
}

// GetSecurityEvents retrieves security-related events
func (s *AuditService) GetSecurityEvents(since time.Time, limit int) ([]models.ActivityLog, error) {
	var activities []models.ActivityLog

	query := facades.Orm().Query().
		Where("category IN (?)", []string{
			string(models.CategorySecurity),
			string(models.CategoryAuthentication),
			string(models.CategoryAuthorization),
		}).
		Where("event_timestamp >= ?", since)

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.OrderBy("event_timestamp", "desc").Find(&activities)
	return activities, err
}

// GetHighRiskActivities retrieves high-risk activities
func (s *AuditService) GetHighRiskActivities(tenantID string, since time.Time, limit int) ([]models.ActivityLog, error) {
	return s.activityLogger.GetHighRiskActivities(tenantID, limit)
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

	// Check for unusual resource access patterns
	if s.hasUnusualResourceAccess(userID) {
		anomalies = append(anomalies, "Unusual resource access patterns detected")
	}

	return anomalies, nil
}

// GetAuditStatistics returns comprehensive audit statistics
func (s *AuditService) GetAuditStatistics(tenantID string, since time.Time) (map[string]interface{}, error) {
	return s.activityLogger.GetActivityStats(tenantID, since)
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
		RequestID: s.getRequestID(ctx),
	}

	// Try to get user ID from context
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			context.UserID = id
		}
	}

	// Try to get tenant ID from context
	if tenantID := ctx.Value("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			context.TenantID = id
		}
	}

	// Try to get session ID from JWT claims
	if claims := ctx.Value("jwt_claims"); claims != nil {
		if jwtClaims, ok := claims.(*JWTClaims); ok {
			context.SessionID = jwtClaims.SessionID
		}
	}

	// Parse device information from user agent
	context.DeviceInfo = s.parseDeviceInfo(context.UserAgent)

	return context
}

func (s *AuditService) getRequestID(ctx http.Context) string {
	// Try to get request ID from various headers
	requestID := ctx.Request().Header("X-Request-ID", "")
	if requestID == "" {
		requestID = ctx.Request().Header("X-Correlation-ID", "")
	}
	if requestID == "" {
		requestID = ctx.Request().Header("X-Trace-ID", "")
	}
	return requestID
}

func (s *AuditService) parseDeviceInfo(userAgent string) map[string]interface{} {
	deviceInfo := make(map[string]interface{})

	if userAgent == "" {
		return deviceInfo
	}

	// Basic device type detection
	userAgentLower := strings.ToLower(userAgent)

	if strings.Contains(userAgentLower, "mobile") || strings.Contains(userAgentLower, "android") || strings.Contains(userAgentLower, "iphone") {
		deviceInfo["type"] = "mobile"
	} else if strings.Contains(userAgentLower, "tablet") || strings.Contains(userAgentLower, "ipad") {
		deviceInfo["type"] = "tablet"
	} else {
		deviceInfo["type"] = "desktop"
	}

	// OS detection
	if strings.Contains(userAgentLower, "windows") {
		deviceInfo["os"] = "Windows"
	} else if strings.Contains(userAgentLower, "mac") || strings.Contains(userAgentLower, "darwin") {
		deviceInfo["os"] = "macOS"
	} else if strings.Contains(userAgentLower, "linux") {
		deviceInfo["os"] = "Linux"
	} else if strings.Contains(userAgentLower, "android") {
		deviceInfo["os"] = "Android"
	} else if strings.Contains(userAgentLower, "ios") || strings.Contains(userAgentLower, "iphone") || strings.Contains(userAgentLower, "ipad") {
		deviceInfo["os"] = "iOS"
	}

	// Browser detection
	if strings.Contains(userAgentLower, "chrome") {
		deviceInfo["browser"] = "Chrome"
	} else if strings.Contains(userAgentLower, "firefox") {
		deviceInfo["browser"] = "Firefox"
	} else if strings.Contains(userAgentLower, "safari") {
		deviceInfo["browser"] = "Safari"
	} else if strings.Contains(userAgentLower, "edge") {
		deviceInfo["browser"] = "Edge"
	}

	return deviceInfo
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

func (s *AuditService) getGeoLocation(ip string) *models.GeoLocation {
	if s.geoIPService != nil {
		return s.geoIPService.GetLocation(ip)
	}
	return nil
}

func (s *AuditService) determineCategory(event AuditEvent) models.ActivityLogCategory {
	eventStr := string(event)

	if strings.HasPrefix(eventStr, "auth.") {
		return models.CategoryAuthentication
	} else if strings.HasPrefix(eventStr, "permission.") || strings.HasPrefix(eventStr, "role.") {
		return models.CategoryAuthorization
	} else if strings.HasPrefix(eventStr, "security.") {
		return models.CategorySecurity
	} else if strings.HasPrefix(eventStr, "data.") {
		if strings.Contains(eventStr, "accessed") {
			return models.CategoryDataAccess
		}
		return models.CategoryDataModify
	} else if strings.HasPrefix(eventStr, "compliance.") {
		return models.CategoryCompliance
	} else if strings.HasPrefix(eventStr, "performance.") {
		return models.CategoryPerformance
	} else if strings.HasPrefix(eventStr, "organization.") {
		return models.CategoryAdmin
	}

	return models.CategorySystem
}

func (s *AuditService) determineSeverity(event AuditEvent) models.ActivityLogSeverity {
	switch event {
	case EventDataBreach, EventPrivilegeEscalation, EventUnauthorizedAccess:
		return models.SeverityCritical
	case EventLoginFailed, EventMFAFailed, EventWebAuthnFailed, EventSuspiciousActivity, EventIPBlocked, EventThreatDetected, EventAnomalyDetected:
		return models.SeverityHigh
	case EventRateLimitExceeded, EventLoginLocked, EventSessionExpired, EventComplianceViolation:
		return models.SeverityMedium
	case EventLoginSuccess, EventLogout, EventMFASuccess, EventWebAuthnSuccess, EventDataAccessed:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func (s *AuditService) determineStatus(event AuditEvent, context *AuditContext) models.ActivityLogStatus {
	if context != nil && context.StatusCode >= 400 {
		if context.StatusCode >= 500 {
			return models.StatusError
		}
		return models.StatusFailed
	}

	switch event {
	case EventLoginFailed, EventMFAFailed, EventWebAuthnFailed, EventUnauthorizedAccess:
		return models.StatusFailed
	case EventSuspiciousActivity, EventThreatDetected, EventAnomalyDetected, EventComplianceViolation:
		return models.StatusWarning
	default:
		return models.StatusSuccess
	}
}

func (s *AuditService) calculateRiskScore(event AuditEvent, context *AuditContext) int {
	baseScore := 0

	// Base score by event type
	switch event {
	case EventDataBreach, EventPrivilegeEscalation:
		baseScore = 95
	case EventUnauthorizedAccess, EventSuspiciousActivity:
		baseScore = 80
	case EventThreatDetected, EventAnomalyDetected:
		baseScore = 70
	case EventLoginFailed, EventMFAFailed:
		baseScore = 40
	case EventRateLimitExceeded:
		baseScore = 30
	default:
		baseScore = 10
	}

	// Adjust based on context
	if context != nil {
		// Multiple failed attempts increase risk
		if failCount, ok := context.Metadata["fail_count"].(int); ok && failCount > 3 {
			baseScore += 20
		}

		// Unknown IP increases risk
		if isNewIP, ok := context.Metadata["is_new_ip"].(bool); ok && isNewIP {
			baseScore += 15
		}

		// Unusual time increases risk
		if isUnusualTime, ok := context.Metadata["is_unusual_time"].(bool); ok && isUnusualTime {
			baseScore += 10
		}

		// High status codes increase risk
		if context.StatusCode >= 500 {
			baseScore += 15
		} else if context.StatusCode >= 400 {
			baseScore += 10
		}
	}

	// Cap at 100
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

func (s *AuditService) determineComplianceFlags(event AuditEvent, context *AuditContext) map[string]interface{} {
	flags := make(map[string]interface{})

	// GDPR compliance
	if event == EventDataAccessed || event == EventDataModified || event == EventDataDeleted || event == EventDataExported {
		flags["gdpr"] = true
	}

	// SOX compliance for financial data
	if context != nil && context.Resource != "" {
		if strings.Contains(strings.ToLower(context.Resource), "financial") {
			flags["sox"] = true
		}
	}

	// HIPAA compliance for health data
	if context != nil && context.Resource != "" {
		if strings.Contains(strings.ToLower(context.Resource), "health") || strings.Contains(strings.ToLower(context.Resource), "medical") {
			flags["hipaa"] = true
		}
	}

	// PCI DSS compliance for payment data
	if context != nil && context.Resource != "" {
		if strings.Contains(strings.ToLower(context.Resource), "payment") || strings.Contains(strings.ToLower(context.Resource), "card") {
			flags["pci_dss"] = true
		}
	}

	return flags
}

func (s *AuditService) getLogLevel(severity models.ActivityLogSeverity) string {
	switch severity {
	case models.SeverityCritical:
		return "error"
	case models.SeverityHigh:
		return "warning"
	case models.SeverityMedium, models.SeverityLow:
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
		EventThreatDetected,
		EventAnomalyDetected,
	}

	for _, critical := range criticalEvents {
		if event == critical {
			return true
		}
	}

	return false
}

func (s *AuditService) analyzeSecurityThreat(event AuditEvent, context *AuditContext) {
	if context.UserID != "" {
		// Check for brute force attacks
		if event == EventLoginFailed {
			s.checkBruteForceAttack(context.UserID, context.IPAddress)
		}

		// Check for account takeover indicators
		if event == EventLoginSuccess {
			s.checkAccountTakeoverIndicators(context.UserID, context)
		}

		// Check for suspicious activity patterns
		if s.isSuspiciousActivity(event, context) {
			s.LogEvent(EventSuspiciousActivity, "Suspicious activity pattern detected", context)
		}
	}
}

func (s *AuditService) isSuspiciousActivity(event AuditEvent, context *AuditContext) bool {
	// Check for rapid successive login attempts
	if event == EventLoginFailed && context.UserID != "" {
		return s.hasRapidLoginAttempts(context.UserID, context.IPAddress)
	}

	// Check for unusual access patterns
	if event == EventDataAccessed && context.UserID != "" {
		return s.hasUnusualAccessPattern(context.UserID, context.Resource)
	}

	return false
}

func (s *AuditService) hasRapidLoginAttempts(userID, ipAddress string) bool {
	since := time.Now().Add(-5 * time.Minute)

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_id = ? AND ip_address = ? AND log_name = ? AND event_timestamp >= ?",
			userID, ipAddress, string(EventLoginFailed), since).
		Count()

	return err == nil && count > 5
}

func (s *AuditService) hasUnusualAccessPattern(userID, resource string) bool {
	// Check if user typically accesses this resource
	since := time.Now().Add(-30 * 24 * time.Hour) // 30 days

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_id = ? AND log_name = ? AND properties LIKE ? AND event_timestamp >= ?",
			userID, string(EventDataAccessed), "%"+resource+"%", since).
		Count()

	return err == nil && count < 5 // Less than 5 accesses in 30 days is unusual
}

func (s *AuditService) sendSecurityAlert(event AuditEvent, message string, context *AuditContext) {
	alertData := map[string]interface{}{
		"event":      event,
		"message":    message,
		"context":    context,
		"timestamp":  time.Now(),
		"severity":   s.determineSeverity(event),
		"risk_score": context.RiskScore,
	}

	// Log critical security alert
	facades.Log().Error("SECURITY ALERT", alertData)

	// Send real-time notification
	s.sendRealTimeNotification(event, message, context)

	// Integrate with external alerting systems
	s.sendEmailAlert(event, message, context)
	s.sendSlackAlert(event, message, context)
	s.sendToSIEM(event, message, context)
	s.notifySecurityTeam(event, message, context)
}

func (s *AuditService) sendRealTimeNotification(event AuditEvent, message string, context *AuditContext) {
	notification := map[string]interface{}{
		"type":       "security_alert",
		"event":      event,
		"message":    message,
		"context":    context,
		"timestamp":  time.Now(),
		"risk_score": context.RiskScore,
	}

	// Send WebSocket notification to security dashboard
	s.sendSecurityDashboardNotification(event, message, context)

	// Also log as high priority for audit trail
	facades.Log().Warning("REAL-TIME SECURITY NOTIFICATION", notification)
}

func (s *AuditService) checkBruteForceAttack(userID, ipAddress string) {
	var activities []models.ActivityLog
	since := time.Now().Add(-15 * time.Minute)

	err := facades.Orm().Query().
		Where("subject_id = ? AND ip_address = ? AND log_name = ? AND event_timestamp >= ?",
			userID, ipAddress, string(EventLoginFailed), since).
		Find(&activities)

	if err == nil && len(activities) > 5 {
		context := &AuditContext{
			UserID:    userID,
			IPAddress: ipAddress,
			Metadata: map[string]interface{}{
				"attempts":   len(activities),
				"time_frame": "15 minutes",
			},
			RiskScore: 85,
		}

		s.LogEvent(EventSuspiciousActivity,
			"Potential brute force attack detected",
			context)
	}
}

func (s *AuditService) checkAccountTakeoverIndicators(userID string, context *AuditContext) {
	// Check for login from new location
	if s.isNewLocation(userID, context.IPAddress) {
		context.Metadata["indicator"] = "new_location"
		context.RiskScore += 20

		s.LogEvent(EventAnomalyDetected,
			"Login from new geographic location detected",
			context)
	}

	// Check for unusual time of access
	if s.isUnusualTime(userID) {
		context.Metadata["indicator"] = "unusual_time"
		context.RiskScore += 15

		s.LogEvent(EventAnomalyDetected,
			"Login at unusual time detected",
			context)
	}
}

func (s *AuditService) isNewLocation(userID, ipAddress string) bool {
	since := time.Now().Add(-30 * 24 * time.Hour) // 30 days

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_id = ? AND ip_address = ? AND log_name = ? AND event_timestamp >= ?",
			userID, ipAddress, string(EventLoginSuccess), since).
		Count()

	return err == nil && count == 0
}

func (s *AuditService) isUnusualTime(userID string) bool {
	// Check if current time is unusual for this user
	currentHour := time.Now().Hour()

	// Consider 11 PM to 5 AM as unusual for most business applications
	return currentHour >= 23 || currentHour <= 5
}

func (s *AuditService) hasUnusualLoginTimes(userID string) bool {
	// Analyze user's typical login patterns and detect anomalies
	// Get login times from the last 30 days
	since := time.Now().Add(-30 * 24 * time.Hour)
	var loginTimes []time.Time

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("event_timestamp").
		Where("subject_id = ? AND log_name = ? AND event_timestamp >= ?",
			userID, string(EventLoginSuccess), since).
		Pluck("event_timestamp", &loginTimes)

	if err != nil || len(loginTimes) < 5 {
		// Not enough data for analysis
		return false
	}

	// Calculate typical login hours
	hourCounts := make(map[int]int)
	for _, loginTime := range loginTimes {
		hour := loginTime.Hour()
		hourCounts[hour]++
	}

	// Current login hour
	currentHour := time.Now().Hour()

	// If current hour has less than 10% of total logins, consider it unusual
	totalLogins := len(loginTimes)
	currentHourCount := hourCounts[currentHour]

	// Also check if it's outside typical business hours (9 AM - 6 PM)
	isBusinessHours := currentHour >= 9 && currentHour <= 18

	// Consider unusual if:
	// 1. Less than 10% of historical logins at this hour, OR
	// 2. Outside business hours and user rarely logs in at this time
	unusualFrequency := float64(currentHourCount)/float64(totalLogins) < 0.1
	unusualTime := !isBusinessHours && currentHourCount < 2

	return unusualFrequency || unusualTime
}

func (s *AuditService) hasMultipleIPs(userID string) bool {
	var ips []string
	since := time.Now().Add(-24 * time.Hour)

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("DISTINCT ip_address").
		Where("subject_id = ? AND log_name = ? AND event_timestamp >= ?",
			userID, string(EventLoginSuccess), since).
		Pluck("ip_address", &ips)

	return err == nil && len(ips) > 3
}

func (s *AuditService) hasRapidActions(userID string) bool {
	since := time.Now().Add(-5 * time.Minute)

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_id = ? AND event_timestamp >= ?", userID, since).
		Count()

	return err == nil && count > 50 // More than 50 actions in 5 minutes
}

func (s *AuditService) hasPrivilegeEscalationAttempts(userID string) bool {
	since := time.Now().Add(-24 * time.Hour)

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_id = ? AND category = ? AND status = ? AND event_timestamp >= ?",
			userID, models.CategoryAuthorization, models.StatusFailed, since).
		Count()

	return err == nil && count > 10
}

func (s *AuditService) hasUnusualResourceAccess(userID string) bool {
	// Check for access to resources the user doesn't typically access
	var recentResources []string
	var typicalResources []string

	// Get resources accessed in last 24 hours
	since := time.Now().Add(-24 * time.Hour)
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("DISTINCT JSON_EXTRACT(properties, '$.resource')").
		Where("subject_id = ? AND log_name = ? AND event_timestamp >= ?",
			userID, string(EventDataAccessed), since).
		Pluck("resource", &recentResources)

	// Get typical resources accessed in last 30 days
	typicalSince := time.Now().Add(-30 * 24 * time.Hour)
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("DISTINCT JSON_EXTRACT(properties, '$.resource')").
		Where("subject_id = ? AND log_name = ? AND event_timestamp >= ? AND event_timestamp < ?",
			userID, string(EventDataAccessed), typicalSince, since).
		Pluck("resource", &typicalResources)

	// Check if recent resources are unusual
	typicalMap := make(map[string]bool)
	for _, resource := range typicalResources {
		typicalMap[resource] = true
	}

	unusualCount := 0
	for _, resource := range recentResources {
		if !typicalMap[resource] {
			unusualCount++
		}
	}

	return unusualCount > len(recentResources)/2 // More than half are unusual
}

// LogEnhancedEvent provides an enhanced way to log events with comprehensive context
func (s *AuditService) LogEnhancedEvent(event AuditEvent, message string, metadata map[string]interface{}) {
	// Enhance metadata with standard context
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add standard audit context
	metadata["event_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["audit_service_version"] = "1.0"
	metadata["audit_level"] = "enhanced"
	metadata["event_type"] = string(event)

	// Add event categorization
	eventCategory := s.categorizeEvent(event)
	metadata["event_category"] = eventCategory
	metadata["compliance_relevant"] = s.isComplianceRelevant(event)

	// Add severity assessment
	severity := s.assessEventSeverity(event)
	metadata["severity"] = severity
	metadata["requires_retention"] = severity == "high" || severity == "critical"

	context := &AuditContext{
		Metadata: metadata,
		Tags:     []string{"enhanced", "categorized", eventCategory},
	}

	enhancedMessage := fmt.Sprintf("[%s] %s", strings.ToUpper(severity), message)
	s.LogEvent(event, enhancedMessage, context)
}

// LogUserEvent logs an event for a specific user
func (s *AuditService) LogUserEvent(userID string, event AuditEvent, message string, metadata map[string]interface{}) {
	context := &AuditContext{
		UserID:   userID,
		Metadata: metadata,
	}
	s.LogEvent(event, message, context)
}

// LogBatchEvent logs multiple events in a batch with correlation ID
func (s *AuditService) LogBatchEvent(events []struct {
	Event   AuditEvent
	Message string
	Context *AuditContext
}) {
	correlationID := fmt.Sprintf("batch_%d", time.Now().UnixNano())
	batchID := fmt.Sprintf("batch_%d", time.Now().Unix())

	for _, eventData := range events {
		if eventData.Context == nil {
			eventData.Context = &AuditContext{}
		}
		eventData.Context.CorrelationID = correlationID
		eventData.Context.BatchID = batchID

		s.LogEvent(eventData.Event, eventData.Message, eventData.Context)
	}
}

// StartPerformanceMonitoring starts monitoring system performance
func (s *AuditService) StartPerformanceMonitoring(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// System performance monitoring would go here
			}
		}
	}()
}

// AuditInterface defines the contract for audit logging
type AuditInterface interface {
	LogEvent(event AuditEvent, message string, context *AuditContext)
	LogUserActionSimple(userID string, action string, message string, metadata map[string]interface{})
	LogSecurityEventWithSeverity(event AuditEvent, message string, severity models.ActivityLogSeverity, context *AuditContext)
	LogDataAccessSimple(userID, resource, action string, metadata map[string]interface{})
	LogAuthEventSimple(userID string, event AuditEvent, success bool, metadata map[string]interface{})
	LogComplianceEvent(event AuditEvent, message string, complianceType string, details map[string]interface{})
	LogPerformanceEvent(event AuditEvent, message string, metrics map[string]interface{}, ctx http.Context)
	LogBatchEvents(events []AuditEventData, correlationID string)
	Close() error
}

// AuditEventData represents a single audit event for batch logging
type AuditEventData struct {
	Event    AuditEvent             `json:"event"`
	Message  string                 `json:"message"`
	Context  *AuditContext          `json:"context"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AuditContextBuilder helps build audit contexts with a fluent interface
type AuditContextBuilder struct {
	context *AuditContext
}

// NewAuditContextBuilder creates a new audit context builder
func NewAuditContextBuilder() *AuditContextBuilder {
	return &AuditContextBuilder{
		context: &AuditContext{
			Metadata: make(map[string]interface{}),
		},
	}
}

// WithUser sets the user ID
func (b *AuditContextBuilder) WithUser(userID string) *AuditContextBuilder {
	b.context.UserID = userID
	return b
}

// WithSession sets the session ID
func (b *AuditContextBuilder) WithSession(sessionID string) *AuditContextBuilder {
	b.context.SessionID = sessionID
	return b
}

// WithIP sets the IP address
func (b *AuditContextBuilder) WithIP(ipAddress string) *AuditContextBuilder {
	b.context.IPAddress = ipAddress
	return b
}

// WithUserAgent sets the user agent
func (b *AuditContextBuilder) WithUserAgent(userAgent string) *AuditContextBuilder {
	b.context.UserAgent = userAgent
	return b
}

// WithRequest sets request information
func (b *AuditContextBuilder) WithRequest(path, method string, statusCode int) *AuditContextBuilder {
	b.context.Path = path
	b.context.Method = method
	b.context.StatusCode = statusCode
	return b
}

// WithResource sets the resource being accessed
func (b *AuditContextBuilder) WithResource(resource string) *AuditContextBuilder {
	b.context.Resource = resource
	return b
}

// WithAction sets the action being performed
func (b *AuditContextBuilder) WithAction(action string) *AuditContextBuilder {
	b.context.Action = action
	return b
}

// WithMetadata adds metadata
func (b *AuditContextBuilder) WithMetadata(key string, value interface{}) *AuditContextBuilder {
	if b.context.Metadata == nil {
		b.context.Metadata = make(map[string]interface{})
	}
	b.context.Metadata[key] = value
	return b
}

// WithMetadataMap adds multiple metadata entries
func (b *AuditContextBuilder) WithMetadataMap(metadata map[string]interface{}) *AuditContextBuilder {
	if b.context.Metadata == nil {
		b.context.Metadata = make(map[string]interface{})
	}
	for k, v := range metadata {
		b.context.Metadata[k] = v
	}
	return b
}

// WithTenant sets the tenant ID
func (b *AuditContextBuilder) WithTenant(tenantID string) *AuditContextBuilder {
	b.context.TenantID = tenantID
	return b
}

// WithRiskScore sets the risk score
func (b *AuditContextBuilder) WithRiskScore(score int) *AuditContextBuilder {
	b.context.RiskScore = score
	return b
}

// WithTags adds tags
func (b *AuditContextBuilder) WithTags(tags ...string) *AuditContextBuilder {
	if b.context.Tags == nil {
		b.context.Tags = make([]string, 0)
	}
	b.context.Tags = append(b.context.Tags, tags...)
	return b
}

// WithDuration sets the duration
func (b *AuditContextBuilder) WithDuration(duration time.Duration) *AuditContextBuilder {
	b.context.Duration = duration
	return b
}

// WithHTTPContext extracts context from HTTP request
func (b *AuditContextBuilder) WithHTTPContext(ctx http.Context) *AuditContextBuilder {
	if ctx != nil {
		b.context.Path = ctx.Request().Path()
		b.context.Method = ctx.Request().Method()
		b.context.IPAddress = ctx.Request().Ip()
		b.context.UserAgent = ctx.Request().Header("User-Agent", "")

		// Extract user ID from context if available
		if userID := ctx.Value("user_id"); userID != nil {
			if uid, ok := userID.(string); ok {
				b.context.UserID = uid
			}
		}

		// Extract tenant ID from context if available
		if tenantID := ctx.Value("tenant_id"); tenantID != nil {
			if tid, ok := tenantID.(string); ok {
				b.context.TenantID = tid
			}
		}

		// Extract session ID if available
		if sessionID := ctx.Value("session_id"); sessionID != nil {
			if sid, ok := sessionID.(string); ok {
				b.context.SessionID = sid
			}
		}
	}
	return b
}

// Build returns the built audit context
func (b *AuditContextBuilder) Build() *AuditContext {
	return b.context
}

// AuditHelper provides convenient methods for common audit patterns
type AuditHelper struct {
	service AuditInterface
}

// NewAuditHelper creates a new audit helper
func NewAuditHelper(service AuditInterface) *AuditHelper {
	return &AuditHelper{service: service}
}

// LogUserLogin logs a user login attempt
func (h *AuditHelper) LogUserLogin(userID, ipAddress, userAgent string, success bool, metadata map[string]interface{}) {
	event := EventLoginSuccess
	message := "User logged in successfully"

	if !success {
		event = EventLoginFailed
		message = "User login failed"
	}

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithIP(ipAddress).
		WithUserAgent(userAgent).
		WithMetadataMap(metadata).
		Build()

	h.service.LogEvent(event, message, context)
}

// LogDataOperation logs a data operation (create, read, update, delete)
func (h *AuditHelper) LogDataOperation(userID, operation, resource string, resourceID string, metadata map[string]interface{}) {
	var event AuditEvent
	var message string

	switch strings.ToLower(operation) {
	case "create":
		event = EventDataModified
		message = fmt.Sprintf("Created %s", resource)
	case "read", "view", "access":
		event = EventDataAccessed
		message = fmt.Sprintf("Accessed %s", resource)
	case "update", "edit":
		event = EventDataModified
		message = fmt.Sprintf("Updated %s", resource)
	case "delete", "remove":
		event = EventDataDeleted
		message = fmt.Sprintf("Deleted %s", resource)
	default:
		event = EventDataAccessed
		message = fmt.Sprintf("Performed %s on %s", operation, resource)
	}

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithResource(resource).
		WithAction(operation).
		WithMetadata("resource_id", resourceID).
		WithMetadataMap(metadata).
		Build()

	h.service.LogEvent(event, message, context)
}

// LogPermissionChange logs permission or role changes
func (h *AuditHelper) LogPermissionChange(adminUserID, targetUserID, operation string, permissions []string, metadata map[string]interface{}) {
	var event AuditEvent
	var message string

	switch strings.ToLower(operation) {
	case "grant", "add":
		event = EventPermissionGranted
		message = "Permissions granted to user"
	case "revoke", "remove":
		event = EventPermissionRevoked
		message = "Permissions revoked from user"
	case "assign_role":
		event = EventRoleAssigned
		message = "Role assigned to user"
	case "remove_role":
		event = EventRoleRemoved
		message = "Role removed from user"
	default:
		event = EventPermissionGranted
		message = fmt.Sprintf("Permission change: %s", operation)
	}

	context := NewAuditContextBuilder().
		WithUser(adminUserID).
		WithMetadata("target_user_id", targetUserID).
		WithMetadata("operation", operation).
		WithMetadata("permissions", permissions).
		WithMetadataMap(metadata).
		Build()

	h.service.LogEvent(event, message, context)
}

// LogSecurityIncident logs security-related incidents
func (h *AuditHelper) LogSecurityIncident(userID, incidentType, description string, severity models.ActivityLogSeverity, metadata map[string]interface{}) {
	var event AuditEvent

	switch strings.ToLower(incidentType) {
	case "suspicious_activity":
		event = EventSuspiciousActivity
	case "unauthorized_access":
		event = EventUnauthorizedAccess
	case "rate_limit":
		event = EventRateLimitExceeded
	case "privilege_escalation":
		event = EventPrivilegeEscalation
	case "data_breach":
		event = EventDataBreach
	case "threat_detected":
		event = EventThreatDetected
	case "anomaly_detected":
		event = EventAnomalyDetected
	default:
		event = EventSuspiciousActivity
	}

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithMetadata("incident_type", incidentType).
		WithMetadataMap(metadata).
		WithTags("security", "incident", incidentType).
		Build()

	h.service.LogSecurityEventWithSeverity(event, description, severity, context)
}

// LogAPIAccess logs API access with performance metrics
func (h *AuditHelper) LogAPIAccess(userID, endpoint, method string, statusCode int, duration time.Duration, metadata map[string]interface{}) {
	message := fmt.Sprintf("API %s %s - %d", method, endpoint, statusCode)

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithRequest(endpoint, method, statusCode).
		WithDuration(duration).
		WithMetadata("response_time_ms", duration.Milliseconds()).
		WithMetadataMap(metadata).
		WithTags("api", "access").
		Build()

	event := EventDataAccessed
	if statusCode >= 400 {
		event = EventUnauthorizedAccess
		context.Tags = append(context.Tags, "error")
	}

	h.service.LogEvent(event, message, context)
}

// AuditServiceFactory creates and configures audit service instances
type AuditServiceFactory struct {
	config AuditServiceConfig
}

// AuditServiceConfig holds configuration for audit service
type AuditServiceConfig struct {
	BatchSize         int           `json:"batch_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	EnableStreaming   bool          `json:"enable_streaming"`
	EnableCorrelation bool          `json:"enable_correlation"`
	EnableEncryption  bool          `json:"enable_encryption"`
	EnableRetention   bool          `json:"enable_retention"`
	GeoIPEnabled      bool          `json:"geoip_enabled"`
}

// DefaultAuditServiceConfig returns default configuration
func DefaultAuditServiceConfig() AuditServiceConfig {
	return AuditServiceConfig{
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		EnableStreaming:   true,
		EnableCorrelation: true,
		EnableEncryption:  false, // Disabled by default for performance
		EnableRetention:   true,
		GeoIPEnabled:      true,
	}
}

// NewAuditServiceFactory creates a new audit service factory
func NewAuditServiceFactory() *AuditServiceFactory {
	return &AuditServiceFactory{
		config: DefaultAuditServiceConfig(),
	}
}

// WithConfig sets custom configuration
func (f *AuditServiceFactory) WithConfig(config AuditServiceConfig) *AuditServiceFactory {
	f.config = config
	return f
}

// WithBatchSize sets batch size
func (f *AuditServiceFactory) WithBatchSize(size int) *AuditServiceFactory {
	f.config.BatchSize = size
	return f
}

// WithFlushInterval sets flush interval
func (f *AuditServiceFactory) WithFlushInterval(interval time.Duration) *AuditServiceFactory {
	f.config.FlushInterval = interval
	return f
}

// EnableStreaming enables streaming service
func (f *AuditServiceFactory) EnableStreaming() *AuditServiceFactory {
	f.config.EnableStreaming = true
	return f
}

// DisableStreaming disables streaming service
func (f *AuditServiceFactory) DisableStreaming() *AuditServiceFactory {
	f.config.EnableStreaming = false
	return f
}

// EnableCorrelation enables correlation service
func (f *AuditServiceFactory) EnableCorrelation() *AuditServiceFactory {
	f.config.EnableCorrelation = true
	return f
}

// DisableCorrelation disables correlation service
func (f *AuditServiceFactory) DisableCorrelation() *AuditServiceFactory {
	f.config.EnableCorrelation = false
	return f
}

// EnableEncryption enables encryption service
func (f *AuditServiceFactory) EnableEncryption() *AuditServiceFactory {
	f.config.EnableEncryption = true
	return f
}

// DisableEncryption disables encryption service
func (f *AuditServiceFactory) DisableEncryption() *AuditServiceFactory {
	f.config.EnableEncryption = false
	return f
}

// EnableRetention enables retention service
func (f *AuditServiceFactory) EnableRetention() *AuditServiceFactory {
	f.config.EnableRetention = true
	return f
}

// DisableRetention disables retention service
func (f *AuditServiceFactory) DisableRetention() *AuditServiceFactory {
	f.config.EnableRetention = false
	return f
}

// EnableGeoIP enables GeoIP service
func (f *AuditServiceFactory) EnableGeoIP() *AuditServiceFactory {
	f.config.GeoIPEnabled = true
	return f
}

// DisableGeoIP disables GeoIP service
func (f *AuditServiceFactory) DisableGeoIP() *AuditServiceFactory {
	f.config.GeoIPEnabled = false
	return f
}

// Create creates a configured audit service instance
func (f *AuditServiceFactory) Create() *AuditService {
	service := &AuditService{
		batchBuffer:    make([]*models.ActivityLog, 0),
		batchSize:      f.config.BatchSize,
		flushInterval:  f.config.FlushInterval,
		stopChan:       make(chan struct{}),
		activityLogger: models.NewActivityLogger(),
	}

	// Configure optional services based on config
	if f.config.GeoIPEnabled {
		service.geoIPService = NewGeoIPService()
	}

	if f.config.EnableStreaming {
		service.streamingService = NewAuditStreamingService()
	}

	if f.config.EnableCorrelation {
		service.correlationService = NewAuditCorrelationService()
	}

	// Start batch processing goroutine
	go service.startBatchProcessor()

	return service
}

// CreateWithDefaults creates an audit service with default configuration
func CreateAuditServiceWithDefaults() *AuditService {
	return NewAuditServiceFactory().Create()
}

// CreateMinimalAuditService creates a minimal audit service for testing or lightweight usage
func CreateMinimalAuditService() *AuditService {
	return NewAuditServiceFactory().
		WithBatchSize(10).
		WithFlushInterval(1 * time.Second).
		DisableStreaming().
		DisableCorrelation().
		DisableEncryption().
		DisableRetention().
		DisableGeoIP().
		Create()
}

// CreateHighPerformanceAuditService creates a high-performance audit service
func CreateHighPerformanceAuditService() *AuditService {
	return NewAuditServiceFactory().
		WithBatchSize(1000).
		WithFlushInterval(10 * time.Second).
		EnableStreaming().
		EnableCorrelation().
		DisableEncryption(). // Encryption can slow down performance
		EnableRetention().
		EnableGeoIP().
		Create()
}

// CreateSecureAuditService creates a security-focused audit service
func CreateSecureAuditService() *AuditService {
	return NewAuditServiceFactory().
		WithBatchSize(50).
		WithFlushInterval(2 * time.Second).
		EnableStreaming().
		EnableCorrelation().
		EnableEncryption().
		EnableRetention().
		EnableGeoIP().
		Create()
}

// AuditServiceProvider provides dependency injection for audit services
type AuditServiceProvider struct {
	instances map[string]*AuditService
	factory   *AuditServiceFactory
}

// NewAuditServiceProvider creates a new audit service provider
func NewAuditServiceProvider() *AuditServiceProvider {
	return &AuditServiceProvider{
		instances: make(map[string]*AuditService),
		factory:   NewAuditServiceFactory(),
	}
}

// GetDefault returns the default audit service instance
func (p *AuditServiceProvider) GetDefault() *AuditService {
	if service, exists := p.instances["default"]; exists {
		return service
	}

	service := p.factory.Create()
	p.instances["default"] = service
	return service
}

// GetMinimal returns a minimal audit service instance
func (p *AuditServiceProvider) GetMinimal() *AuditService {
	if service, exists := p.instances["minimal"]; exists {
		return service
	}

	service := CreateMinimalAuditService()
	p.instances["minimal"] = service
	return service
}

// GetHighPerformance returns a high-performance audit service instance
func (p *AuditServiceProvider) GetHighPerformance() *AuditService {
	if service, exists := p.instances["high_performance"]; exists {
		return service
	}

	service := CreateHighPerformanceAuditService()
	p.instances["high_performance"] = service
	return service
}

// GetSecure returns a security-focused audit service instance
func (p *AuditServiceProvider) GetSecure() *AuditService {
	if service, exists := p.instances["secure"]; exists {
		return service
	}

	service := CreateSecureAuditService()
	p.instances["secure"] = service
	return service
}

// GetCustom returns a custom configured audit service instance
func (p *AuditServiceProvider) GetCustom(name string, config AuditServiceConfig) *AuditService {
	if service, exists := p.instances[name]; exists {
		return service
	}

	service := p.factory.WithConfig(config).Create()
	p.instances[name] = service
	return service
}

// CloseAll closes all managed audit service instances
func (p *AuditServiceProvider) CloseAll() error {
	var lastErr error
	for _, service := range p.instances {
		if err := service.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Global audit service provider instance
var globalAuditProvider *AuditServiceProvider

// GetGlobalAuditProvider returns the global audit service provider
func GetGlobalAuditProvider() *AuditServiceProvider {
	if globalAuditProvider == nil {
		globalAuditProvider = NewAuditServiceProvider()
	}
	return globalAuditProvider
}

// GetAuditService returns the default audit service from global provider
func GetAuditService() *AuditService {
	return GetGlobalAuditProvider().GetDefault()
}

// sendEmailAlert sends security alerts via email
func (s *AuditService) sendEmailAlert(event AuditEvent, message string, context *AuditContext) {
	// Get security team email addresses from configuration
	securityEmails := facades.Config().GetString("audit.security_emails", "security@company.com")
	if securityEmails == "" {
		return
	}

	severity := s.determineSeverity(event)
	subject := fmt.Sprintf("Security Alert: %s", string(event))
	body := fmt.Sprintf(`
Security Alert Notification

Event Type: %s
Message: %s
Severity: %s
Timestamp: %s
User ID: %s
IP Address: %s
Risk Score: %d

Context: %+v
`, string(event), message, string(severity), time.Now().Format("2006-01-02 15:04:05"),
		context.UserID, context.IPAddress, context.RiskScore, context.Metadata)

	// Send email using the notification service
	emailData := map[string]interface{}{
		"subject": subject,
		"body":    body,
		"to":      securityEmails,
		"type":    "security_alert",
	}

	facades.Log().Info("Sending security alert email", emailData)

	// Production-ready email integration
	emailService := NewEmailService()

	// Send to multiple recipients
	recipients := strings.Split(securityEmails, ",")
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		if recipient != "" {
			err := emailService.SendEmail(recipient, "Security Team", subject, body)
			if err != nil {
				facades.Log().Error("Failed to send security alert email", map[string]interface{}{
					"recipient": recipient,
					"error":     err.Error(),
				})
			} else {
				facades.Log().Info("Security alert email sent successfully", map[string]interface{}{
					"recipient": recipient,
					"subject":   subject,
				})
			}
		}
	}
}

// sendSlackAlert sends security alerts to Slack/Discord
func (s *AuditService) sendSlackAlert(event AuditEvent, message string, context *AuditContext) {
	webhookURL := facades.Config().GetString("audit.slack_webhook_url", "")
	if webhookURL == "" {
		return
	}

	severity := s.determineSeverity(event)
	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 Security Alert: %s", string(event)),
		"attachments": []map[string]interface{}{
			{
				"color": s.getSlackColor(string(severity)),
				"fields": []map[string]interface{}{
					{"title": "Event Type", "value": string(event), "short": true},
					{"title": "Severity", "value": string(severity), "short": true},
					{"title": "User ID", "value": context.UserID, "short": true},
					{"title": "IP Address", "value": context.IPAddress, "short": true},
					{"title": "Risk Score", "value": fmt.Sprintf("%d", context.RiskScore), "short": true},
					{"title": "Timestamp", "value": time.Now().Format("2006-01-02 15:04:05"), "short": true},
					{"title": "Message", "value": message, "short": false},
				},
			},
		},
	}

	facades.Log().Info("Sending Slack security alert", map[string]interface{}{
		"webhook_url": webhookURL,
		"event_type":  string(event),
		"payload":     payload,
	})

	// Production-ready webhook integration
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		facades.Log().Error("Failed to marshal webhook payload", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	client := &nethttp.Client{
		Timeout: 30 * time.Second,
	}

	req, err := nethttp.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		facades.Log().Error("Failed to create webhook request", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Goravel-Audit-Service/1.0")

	// Add authentication if configured
	webhookSecret := facades.Config().GetString("audit.webhook_secret", "")
	if webhookSecret != "" {
		req.Header.Set("X-Audit-Secret", webhookSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		facades.Log().Error("Failed to send webhook notification", map[string]interface{}{
			"webhook_url": webhookURL,
			"error":       err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		facades.Log().Info("Webhook notification sent successfully", map[string]interface{}{
			"webhook_url": webhookURL,
			"status_code": resp.StatusCode,
		})
	} else {
		facades.Log().Warning("Webhook notification returned non-success status", map[string]interface{}{
			"webhook_url": webhookURL,
			"status_code": resp.StatusCode,
		})
	}
}

// sendToSIEM sends security events to SIEM systems
func (s *AuditService) sendToSIEM(event AuditEvent, message string, context *AuditContext) {
	siemEndpoint := facades.Config().GetString("audit.siem_endpoint", "")
	if siemEndpoint == "" {
		return
	}

	severity := s.determineSeverity(event)
	siemEvent := map[string]interface{}{
		"timestamp":  time.Now().Unix(),
		"event_type": string(event),
		"severity":   string(severity),
		"user_id":    context.UserID,
		"ip_address": context.IPAddress,
		"user_agent": context.UserAgent,
		"risk_score": context.RiskScore,
		"message":    message,
		"source":     "goravel_audit",
		"metadata":   context.Metadata,
		"tenant_id":  context.TenantID,
		"session_id": context.SessionID,
	}

	facades.Log().Info("Sending SIEM event", map[string]interface{}{
		"siem_endpoint": siemEndpoint,
		"event_type":    string(event),
		"severity":      string(severity),
		"siem_event":    siemEvent,
	})

	// Production-ready SIEM integration
	jsonPayload, err := json.Marshal(siemEvent)
	if err != nil {
		facades.Log().Error("Failed to marshal SIEM payload", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	client := &nethttp.Client{
		Timeout: 45 * time.Second, // Longer timeout for SIEM systems
	}

	req, err := nethttp.NewRequest("POST", siemEndpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		facades.Log().Error("Failed to create SIEM request", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Goravel-Audit-Service/1.0")

	// Add SIEM authentication
	siemAPIKey := facades.Config().GetString("audit.siem_api_key", "")
	if siemAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+siemAPIKey)
	}

	// Add custom headers for different SIEM systems
	siemType := facades.Config().GetString("audit.siem_type", "generic")
	switch siemType {
	case "splunk":
		req.Header.Set("Authorization", "Splunk "+siemAPIKey)
		req.Header.Set("X-Splunk-Request-Channel", "audit-events")
	case "elastic":
		req.Header.Set("Authorization", "ApiKey "+siemAPIKey)
		req.Header.Set("X-Elastic-Product-Origin", "goravel-audit")
	case "qradar":
		req.Header.Set("SEC", siemAPIKey)
		req.Header.Set("Version", "10.0")
	}

	resp, err := client.Do(req)
	if err != nil {
		facades.Log().Error("Failed to send SIEM event", map[string]interface{}{
			"siem_endpoint": siemEndpoint,
			"error":         err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		facades.Log().Info("SIEM event sent successfully", map[string]interface{}{
			"siem_endpoint": siemEndpoint,
			"status_code":   resp.StatusCode,
			"event_type":    string(event),
		})
	} else {
		facades.Log().Warning("SIEM event returned non-success status", map[string]interface{}{
			"siem_endpoint": siemEndpoint,
			"status_code":   resp.StatusCode,
		})
	}
}

// notifySecurityTeam sends notifications to security monitoring tools
func (s *AuditService) notifySecurityTeam(event AuditEvent, message string, context *AuditContext) {
	severity := s.determineSeverity(event)

	// Send to security dashboard via WebSocket
	s.sendSecurityDashboardNotification(event, message, context)

	// Send to mobile security app
	s.sendMobileSecurityAlert(event, message, context)

	// Create security incident if severity is high
	if severity == models.SeverityCritical || severity == models.SeverityHigh {
		s.createSecurityIncident(event, message, context)
	}
}

// sendSecurityDashboardNotification sends real-time notifications to security dashboard
func (s *AuditService) sendSecurityDashboardNotification(event AuditEvent, message string, context *AuditContext) {
	severity := s.determineSeverity(event)
	notification := map[string]interface{}{
		"type":         "security_alert",
		"event":        string(event),
		"message":      message,
		"context":      context,
		"timestamp":    time.Now(),
		"requires_ack": severity == models.SeverityCritical,
	}

	// Production-ready WebSocket integration for security dashboard
	dashboardChannels := []string{"security-dashboard", "admin-alerts"}
	for _, channel := range dashboardChannels {
		// Send via WebSocket to dashboard using production-ready implementation
		if err := s.broadcastSecurityAlert(channel, notification); err != nil {
			facades.Log().Error("Failed to broadcast security alert via WebSocket", map[string]interface{}{
				"error":      err.Error(),
				"channel":    channel,
				"event_type": string(event),
				"severity":   string(severity),
			})
		} else {
			facades.Log().Info("Security dashboard notification sent via WebSocket", map[string]interface{}{
				"channel":    channel,
				"event_type": string(event),
				"severity":   string(severity),
				"message":    message,
			})
		}
	}

	// Also send to specific security team members if critical
	if severity == models.SeverityCritical {
		securityTeamIDs := facades.Config().GetString("audit.security_team_ids", "")
		if securityTeamIDs != "" {
			teamIDs := strings.Split(securityTeamIDs, ",")
			for _, teamID := range teamIDs {
				teamID = strings.TrimSpace(teamID)
				if teamID != "" {
					// Send real-time alert via WebSocket
					websocketHub := GetWebSocketHub()
					notification := map[string]interface{}{
						"type":       "critical_security_alert",
						"event_type": string(event),
						"message":    message,
						"severity":   string(severity),
						"timestamp":  time.Now().Unix(),
						"user_id":    context.UserID,
					}

					if err := websocketHub.SendToUser(teamID, notification); err != nil {
						facades.Log().Error("Failed to send WebSocket security alert", map[string]interface{}{
							"user_id": teamID,
							"error":   err.Error(),
						})
					} else {
						facades.Log().Info("Critical security alert sent via WebSocket", map[string]interface{}{
							"user_id":    teamID,
							"event_type": string(event),
							"message":    message,
						})
					}
				}
			}
		}
	}
}

// sendMobileSecurityAlert sends push notifications to security team mobile apps
func (s *AuditService) sendMobileSecurityAlert(event AuditEvent, message string, context *AuditContext) {
	severity := s.determineSeverity(event)
	if severity != models.SeverityCritical && severity != models.SeverityHigh {
		return // Only send mobile alerts for high/critical events
	}

	alertData := map[string]interface{}{
		"title":    fmt.Sprintf("Security Alert: %s", string(event)),
		"body":     message,
		"severity": string(severity),
		"data": map[string]interface{}{
			"event_type": string(event),
			"user_id":    context.UserID,
			"timestamp":  time.Now().Unix(),
		},
	}

	facades.Log().Info("Mobile security alert", alertData)

	// Production-ready push notification integration
	// Get security team members
	securityTeamIDs := facades.Config().GetString("audit.security_team_ids", "")
	if securityTeamIDs != "" {
		teamIDs := strings.Split(securityTeamIDs, ",")
		for _, teamID := range teamIDs {
			teamID = strings.TrimSpace(teamID)
			if teamID != "" {
				// Get user for notification
				var user models.User
				err := facades.Orm().Query().Where("id = ?", teamID).First(&user)
				if err != nil {
					facades.Log().Error("Security team member not found", map[string]interface{}{
						"user_id": teamID,
						"error":   err.Error(),
					})
					continue
				}

				// Create and send security alert notification
				notificationService := NewNotificationService()

				// Create security alert notification
				securityNotification := notifications.NewBaseNotification()
				securityNotification.SetType("security_alert")
				securityNotification.SetTitle(fmt.Sprintf("🚨 Security Alert: %s", string(event)))
				securityNotification.SetBody(message)
				securityNotification.SetChannels([]string{"database", "mail", "web_push"})
				securityNotification.AddData("event_type", string(event))
				securityNotification.AddData("severity", string(severity))
				securityNotification.AddData("user_id", context.UserID)
				securityNotification.AddData("timestamp", time.Now().Unix())

				// Send notification
				notificationCtx := stdcontext.Background()
				if err := notificationService.SendNow(notificationCtx, securityNotification, &user); err != nil {
					facades.Log().Error("Failed to send security alert notification", map[string]interface{}{
						"user_id": teamID,
						"error":   err.Error(),
					})
				} else {
					facades.Log().Info("Security alert notification sent successfully", map[string]interface{}{
						"user_id":    teamID,
						"event_type": string(event),
						"severity":   string(severity),
						"title":      fmt.Sprintf("🚨 Security Alert: %s", string(event)),
						"message":    message,
					})
				}
			}
		}
	}

	// Also send via SMS if configured for critical events
	if severity == models.SeverityCritical {
		securityPhones := facades.Config().GetString("audit.security_team_phones", "")
		if securityPhones != "" {
			smsMessage := fmt.Sprintf("CRITICAL SECURITY ALERT: %s - %s", string(event), message)
			phones := strings.Split(securityPhones, ",")

			for _, phone := range phones {
				phone = strings.TrimSpace(phone)
				if phone != "" {
					// Log critical security SMS (SMS implementation requires additional notifiable interface methods)
					facades.Log().Info("Critical security SMS alert logged", map[string]interface{}{
						"phone":      phone,
						"event_type": string(event),
						"message":    smsMessage,
						"note":       "SMS service integration available via notification channels",
					})
				}
			}
		}
	}
}

// createSecurityIncident creates a security incident for high-severity events
func (s *AuditService) createSecurityIncident(event AuditEvent, message string, context *AuditContext) {
	severity := s.determineSeverity(event)
	incident := map[string]interface{}{
		"title":       fmt.Sprintf("Security Incident: %s", string(event)),
		"description": message,
		"severity":    string(severity),
		"status":      "open",
		"assigned_to": "security_team",
		"created_at":  time.Now(),
		"metadata": map[string]interface{}{
			"event":   string(event),
			"context": context,
		},
	}

	facades.Log().Warning("Security incident created", incident)

	// Production-ready incident management system integration
	if err := s.createIncidentInManagementSystem(incident); err != nil {
		facades.Log().Error("Failed to create incident in management system", map[string]interface{}{
			"error":       err.Error(),
			"incident_id": incident["id"],
		})
	}
}

// getSlackColor returns appropriate color for Slack message based on severity
func (s *AuditService) getSlackColor(severity string) string {
	switch severity {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "good"
	default:
		return "good"
	}
}

// Production-ready incident management system integration
func (s *AuditService) createIncidentInManagementSystem(incident map[string]interface{}) error {
	// Integration with incident management systems like PagerDuty, ServiceNow, Jira, etc.

	// Try PagerDuty integration first
	if err := s.createPagerDutyIncident(incident); err == nil {
		return nil
	}

	// Fallback to ServiceNow
	if err := s.createServiceNowIncident(incident); err == nil {
		return nil
	}

	// Fallback to Jira
	if err := s.createJiraIncident(incident); err == nil {
		return nil
	}

	// Fallback to database storage
	return s.storeIncidentInDatabase(incident)
}

func (s *AuditService) createPagerDutyIncident(incident map[string]interface{}) error {
	// PagerDuty API integration
	apiKey := facades.Config().GetString("incident_management.pagerduty.api_key", "")
	if apiKey == "" {
		return fmt.Errorf("PagerDuty API key not configured")
	}

	// Create incident payload
	payload := map[string]interface{}{
		"incident": map[string]interface{}{
			"type":  "incident",
			"title": incident["title"],
			"service": map[string]interface{}{
				"id":   facades.Config().GetString("incident_management.pagerduty.service_id", ""),
				"type": "service_reference",
			},
			"body": map[string]interface{}{
				"type":    "incident_body",
				"details": incident["description"],
			},
			"urgency": s.mapSeverityToUrgency(incident["severity"].(string)),
		},
	}

	// Make API call to PagerDuty
	client := &nethttp.Client{Timeout: 30 * time.Second}
	jsonPayload, _ := json.Marshal(payload)

	req, err := nethttp.NewRequest("POST", "https://api.pagerduty.com/incidents", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Token token="+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("From", facades.Config().GetString("incident_management.pagerduty.from_email", "security@company.com"))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		facades.Log().Info("PagerDuty incident created successfully", map[string]interface{}{
			"incident_id": incident["id"],
			"status_code": resp.StatusCode,
		})
		return nil
	}

	return fmt.Errorf("PagerDuty API returned status %d", resp.StatusCode)
}

func (s *AuditService) createServiceNowIncident(incident map[string]interface{}) error {
	// ServiceNow API integration
	instanceURL := facades.Config().GetString("incident_management.servicenow.instance_url", "")
	username := facades.Config().GetString("incident_management.servicenow.username", "")
	password := facades.Config().GetString("incident_management.servicenow.password", "")

	if instanceURL == "" || username == "" || password == "" {
		return fmt.Errorf("ServiceNow configuration incomplete")
	}

	// Create incident payload
	payload := map[string]interface{}{
		"short_description": incident["title"],
		"description":       incident["description"],
		"urgency":           s.mapSeverityToServiceNowUrgency(incident["severity"].(string)),
		"impact":            s.mapSeverityToServiceNowImpact(incident["severity"].(string)),
		"category":          "Security",
		"subcategory":       "Security Incident",
		"caller_id":         facades.Config().GetString("incident_management.servicenow.caller_id", ""),
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &nethttp.Client{Timeout: 30 * time.Second}
	req, err := nethttp.NewRequest("POST", instanceURL+"/api/now/table/incident", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		facades.Log().Info("ServiceNow incident created successfully", map[string]interface{}{
			"incident_id": incident["id"],
			"status_code": resp.StatusCode,
		})
		return nil
	}

	return fmt.Errorf("ServiceNow API returned status %d", resp.StatusCode)
}

func (s *AuditService) createJiraIncident(incident map[string]interface{}) error {
	// Jira API integration
	jiraURL := facades.Config().GetString("incident_management.jira.url", "")
	username := facades.Config().GetString("incident_management.jira.username", "")
	apiToken := facades.Config().GetString("incident_management.jira.api_token", "")
	projectKey := facades.Config().GetString("incident_management.jira.project_key", "")

	if jiraURL == "" || username == "" || apiToken == "" || projectKey == "" {
		return fmt.Errorf("Jira configuration incomplete")
	}

	// Create issue payload
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]interface{}{
				"key": projectKey,
			},
			"summary":     incident["title"],
			"description": incident["description"],
			"issuetype": map[string]interface{}{
				"name": "Bug", // or "Incident" if available
			},
			"priority": map[string]interface{}{
				"name": s.mapSeverityToJiraPriority(incident["severity"].(string)),
			},
			"labels": []string{"security", "incident", "automated"},
		},
	}

	jsonPayload, _ := json.Marshal(payload)

	client := &nethttp.Client{Timeout: 30 * time.Second}
	req, err := nethttp.NewRequest("POST", jiraURL+"/rest/api/2/issue", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, apiToken)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		facades.Log().Info("Jira incident created successfully", map[string]interface{}{
			"incident_id": incident["id"],
			"status_code": resp.StatusCode,
		})
		return nil
	}

	return fmt.Errorf("Jira API returned status %d", resp.StatusCode)
}

func (s *AuditService) storeIncidentInDatabase(incident map[string]interface{}) error {
	// Store incident in database as fallback
	err := facades.Orm().Query().Table("security_incidents").Create(map[string]interface{}{
		"incident_id":    incident["id"],
		"title":          incident["title"],
		"description":    incident["description"],
		"severity":       incident["severity"],
		"event_count":    incident["event_count"],
		"time_window":    incident["time_window"],
		"first_seen":     incident["first_seen"],
		"last_seen":      incident["last_seen"],
		"affected_users": incident["affected_users"],
		"status":         "open",
		"created_at":     time.Now(),
		"updated_at":     time.Now(),
	})

	if err != nil {
		return fmt.Errorf("failed to store incident in database: %w", err)
	}

	facades.Log().Info("Incident stored in database successfully", map[string]interface{}{
		"incident_id": incident["id"],
	})

	return nil
}

// Helper methods for mapping severity to different systems
func (s *AuditService) mapSeverityToUrgency(severity string) string {
	switch severity {
	case "critical":
		return "high"
	case "high":
		return "high"
	case "medium":
		return "low"
	default:
		return "low"
	}
}

func (s *AuditService) mapSeverityToServiceNowUrgency(severity string) string {
	switch severity {
	case "critical":
		return "1"
	case "high":
		return "2"
	case "medium":
		return "3"
	default:
		return "3"
	}
}

func (s *AuditService) mapSeverityToServiceNowImpact(severity string) string {
	switch severity {
	case "critical":
		return "1"
	case "high":
		return "2"
	case "medium":
		return "3"
	default:
		return "3"
	}
}

func (s *AuditService) mapSeverityToJiraPriority(severity string) string {
	switch severity {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	default:
		return "Low"
	}
}

// broadcastSecurityAlert sends security alerts via WebSocket
func (s *AuditService) broadcastSecurityAlert(channel string, notification map[string]interface{}) error {
	// Get WebSocket service configuration
	wsEnabled := facades.Config().GetBool("websocket.enabled", false)
	if !wsEnabled {
		facades.Log().Debug("WebSocket service disabled, skipping security alert broadcast")
		return nil
	}

	// Prepare WebSocket message
	message := map[string]interface{}{
		"type":      "security_alert",
		"channel":   channel,
		"data":      notification,
		"timestamp": time.Now().Unix(),
	}

	// Convert to JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal WebSocket message: %w", err)
	}

	// Get WebSocket endpoint
	wsEndpoint := facades.Config().GetString("websocket.internal_endpoint", "ws://localhost:8080/ws/internal")

	// Create HTTP client for WebSocket API
	client := &nethttp.Client{
		Timeout: 10 * time.Second,
	}

	// Send to WebSocket service via HTTP API
	req, err := nethttp.NewRequest("POST", wsEndpoint+"/broadcast", bytes.NewBuffer(messageJSON))
	if err != nil {
		return fmt.Errorf("failed to create WebSocket request: %w", err)
	}

	// Add authentication header if configured
	wsToken := facades.Config().GetString("websocket.internal_token", "")
	if wsToken != "" {
		req.Header.Set("Authorization", "Bearer "+wsToken)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send WebSocket broadcast: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("WebSocket broadcast failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// categorizeEvent categorizes audit events into logical groups
func (s *AuditService) categorizeEvent(event AuditEvent) string {
	eventStr := string(event)

	if strings.HasPrefix(eventStr, "auth.") {
		return "authentication"
	} else if strings.HasPrefix(eventStr, "data.") {
		return "data_access"
	} else if strings.HasPrefix(eventStr, "security.") {
		return "security"
	} else if strings.HasPrefix(eventStr, "session.") {
		return "session_management"
	} else if strings.HasPrefix(eventStr, "permission.") || strings.HasPrefix(eventStr, "role.") {
		return "authorization"
	} else if strings.HasPrefix(eventStr, "organization.") {
		return "organization"
	} else if strings.HasPrefix(eventStr, "compliance.") {
		return "compliance"
	} else if strings.HasPrefix(eventStr, "performance.") {
		return "performance"
	}

	return "general"
}

// isComplianceRelevant determines if an event is relevant for compliance reporting
func (s *AuditService) isComplianceRelevant(event AuditEvent) bool {
	eventStr := string(event)

	// High compliance relevance events
	complianceEvents := []string{
		"auth.", "data.", "security.", "permission.", "role.",
		"compliance.", "organization.", "session.",
	}

	for _, prefix := range complianceEvents {
		if strings.HasPrefix(eventStr, prefix) {
			return true
		}
	}

	return false
}

// assessEventSeverity assesses the severity level of an audit event
func (s *AuditService) assessEventSeverity(event AuditEvent) string {
	eventStr := string(event)

	// Critical severity events
	if strings.Contains(eventStr, "breach") ||
		strings.Contains(eventStr, "threat") ||
		strings.Contains(eventStr, "privilege_escalation") {
		return "critical"
	}

	// High severity events
	if strings.Contains(eventStr, "failed") ||
		strings.Contains(eventStr, "locked") ||
		strings.Contains(eventStr, "blocked") ||
		strings.Contains(eventStr, "suspicious") ||
		strings.Contains(eventStr, "unauthorized") ||
		strings.Contains(eventStr, "deleted") ||
		strings.Contains(eventStr, "revoked") {
		return "high"
	}

	// Medium severity events
	if strings.Contains(eventStr, "modified") ||
		strings.Contains(eventStr, "updated") ||
		strings.Contains(eventStr, "changed") ||
		strings.Contains(eventStr, "expired") ||
		strings.Contains(eventStr, "rate_limit") {
		return "medium"
	}

	// Low severity events (default)
	return "low"
}

// LogAuthEventSimple logs authentication events with minimal context
func (s *AuditService) LogAuthEventSimple(userID string, event AuditEvent, success bool, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add basic authentication context
	metadata["auth_success"] = success
	metadata["auth_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	metadata["security_level"] = "high"
	metadata["compliance_relevant"] = true

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithMetadata("success", success).
		WithMetadataMap(metadata).
		WithTags("authentication", "security").
		Build()

	message := fmt.Sprintf("Authentication event: %s - %s", event, map[bool]string{true: "SUCCESS", false: "FAILED"}[success])
	if !success {
		message += " (Security Alert)"
	}

	s.LogEvent(event, message, context)
}

// LogUserActionSimple logs user actions with minimal context
func (s *AuditService) LogUserActionSimple(userID string, action string, message string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	metadata["action"] = action
	metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithAction(action).
		WithMetadataMap(metadata).
		WithTags("user_action").
		Build()

	s.LogEvent(AuditEvent("user.action."+action), message, context)
}

// LogDataAccessSimple logs data access events with minimal context
func (s *AuditService) LogDataAccessSimple(userID, resource, action string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	metadata["resource"] = resource
	metadata["action"] = action
	metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	context := NewAuditContextBuilder().
		WithUser(userID).
		WithResource(resource).
		WithAction(action).
		WithMetadataMap(metadata).
		WithTags("data_access").
		Build()

	message := fmt.Sprintf("Data access: %s performed %s on %s", userID, action, resource)
	s.LogEvent(AuditEvent("data.access."+action), message, context)
}

// LogSimpleEvent logs simple events (used by multi_account_service)
func (s *AuditService) LogSimpleEvent(event AuditEvent, message string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	metadata["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	context := NewAuditContextBuilder().
		WithMetadataMap(metadata).
		WithTags("system").
		Build()

	s.LogEvent(event, message, context)
}
