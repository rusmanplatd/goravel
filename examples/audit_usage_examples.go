package examples

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/middleware"
	"goravel/app/models"
	"goravel/app/services"
)

// AuditUsageExamples demonstrates various ways to use the audit logging system
type AuditUsageExamples struct {
	auditService *services.AuditService
	auditHelper  *services.AuditHelper
}

// NewAuditUsageExamples creates a new example instance
func NewAuditUsageExamples() *AuditUsageExamples {
	auditService := services.GetAuditService()
	return &AuditUsageExamples{
		auditService: auditService,
		auditHelper:  services.NewAuditHelper(auditService),
	}
}

// Example 1: Basic audit logging with context builder
func (e *AuditUsageExamples) ExampleBasicLogging(userID string, ctx http.Context) {
	// Using the context builder for structured audit logging
	auditContext := services.NewAuditContextBuilder().
		WithUser(userID).
		WithHTTPContext(ctx).
		WithResource("user_profile").
		WithAction("update").
		WithMetadata("field_changed", "email").
		WithMetadata("old_value", "old@example.com").
		WithMetadata("new_value", "new@example.com").
		WithTags("profile", "email_change").
		WithRiskScore(25).
		Build()

	e.auditService.LogEvent(services.EventDataModified, "User email address updated", auditContext)
}

// Example 2: Using audit helper for common patterns
func (e *AuditUsageExamples) ExampleHelperPatterns(userID string) {
	// Login logging
	e.auditHelper.LogUserLogin(userID, "192.168.1.1", "Mozilla/5.0...", true, map[string]interface{}{
		"login_method": "password",
		"mfa_enabled":  true,
	})

	// Data operation logging
	e.auditHelper.LogDataOperation(userID, "create", "document", "doc123", map[string]interface{}{
		"document_type": "contract",
		"size_bytes":    1024,
	})

	// Permission change logging
	e.auditHelper.LogPermissionChange("admin123", userID, "grant", []string{"read", "write"}, map[string]interface{}{
		"resource": "documents",
		"reason":   "project_assignment",
	})

	// Security incident logging
	e.auditHelper.LogSecurityIncident(userID, "suspicious_activity", "Multiple failed login attempts detected", models.SeverityHigh, map[string]interface{}{
		"failed_attempts": 5,
		"time_window":     "5 minutes",
		"ip_addresses":    []string{"192.168.1.100", "192.168.1.101"},
	})
}

// Example 3: Using different audit service configurations
func (e *AuditUsageExamples) ExampleServiceConfigurations() {
	// Get different pre-configured audit services
	provider := services.GetGlobalAuditProvider()

	// High-performance service for bulk operations
	highPerfService := provider.GetHighPerformance()
	highPerfHelper := services.NewAuditHelper(highPerfService)

	// Security-focused service for sensitive operations
	secureService := provider.GetSecure()
	secureHelper := services.NewAuditHelper(secureService)

	// Minimal service for testing
	minimalService := provider.GetMinimal()
	minimalHelper := services.NewAuditHelper(minimalService)

	// Custom configuration
	customConfig := services.AuditServiceConfig{
		BatchSize:         50,
		FlushInterval:     3 * time.Second,
		EnableStreaming:   true,
		EnableCorrelation: false,
		EnableEncryption:  true,
		EnableRetention:   true,
		GeoIPEnabled:      false,
	}
	customService := provider.GetCustom("custom_audit", customConfig)
	customHelper := services.NewAuditHelper(customService)

	// Use different services for different purposes
	highPerfHelper.LogDataOperation("user123", "bulk_import", "users", "batch456", map[string]interface{}{
		"record_count": 1000,
	})

	secureHelper.LogSecurityIncident("user123", "data_breach", "Potential data breach detected", models.SeverityCritical, map[string]interface{}{
		"affected_records": 500,
		"data_types":       []string{"pii", "financial"},
	})

	minimalHelper.LogUserLogin("user123", "127.0.0.1", "test-agent", true, map[string]interface{}{
		"test_mode": true,
	})

	customHelper.LogDataOperation("user123", "export", "sensitive_data", "export789", map[string]interface{}{
		"export_type":    "gdpr_request",
		"encryption_key": "key123",
	})
}

// Example 4: Batch logging for related events
func (e *AuditUsageExamples) ExampleBatchLogging(userID string) {
	correlationID := "batch_" + time.Now().Format("20060102150405")

	events := []services.AuditEventData{
		{
			Event:   services.EventDataAccessed,
			Message: "User accessed document list",
			Context: services.NewAuditContextBuilder().
				WithUser(userID).
				WithResource("documents").
				WithAction("list").
				Build(),
			Metadata: map[string]interface{}{
				"page":     1,
				"per_page": 20,
			},
		},
		{
			Event:   services.EventDataAccessed,
			Message: "User downloaded document",
			Context: services.NewAuditContextBuilder().
				WithUser(userID).
				WithResource("document").
				WithAction("download").
				Build(),
			Metadata: map[string]interface{}{
				"document_id": "doc123",
				"file_size":   2048,
			},
		},
		{
			Event:   services.EventDataModified,
			Message: "User updated document metadata",
			Context: services.NewAuditContextBuilder().
				WithUser(userID).
				WithResource("document").
				WithAction("update").
				Build(),
			Metadata: map[string]interface{}{
				"document_id": "doc123",
				"fields":      []string{"title", "description"},
			},
		},
	}

	e.auditService.LogBatchEvents(events, correlationID)
}

// Example 5: API access logging with performance metrics
func (e *AuditUsageExamples) ExampleAPILogging(userID, endpoint, method string, statusCode int, duration time.Duration) {
	e.auditHelper.LogAPIAccess(userID, endpoint, method, statusCode, duration, map[string]interface{}{
		"response_size": 1024,
		"cache_hit":     false,
		"db_queries":    3,
	})
}

// Example 6: Complex audit context with all features
func (e *AuditUsageExamples) ExampleComplexContext(userID string, ctx http.Context) {
	// Build a comprehensive audit context
	auditContext := services.NewAuditContextBuilder().
		WithUser(userID).
		WithHTTPContext(ctx).
		WithResource("financial_report").
		WithAction("generate").
		WithMetadata("report_type", "quarterly").
		WithMetadata("period", "Q4-2024").
		WithMetadata("departments", []string{"finance", "sales", "marketing"}).
		WithMetadata("confidential", true).
		WithTags("financial", "report", "quarterly", "confidential").
		WithRiskScore(75). // High risk due to financial data
		WithDuration(5 * time.Second).
		Build()

	e.auditService.LogEvent(services.EventDataAccessed, "Quarterly financial report generated", auditContext)
}

// Example 7: Error handling and recovery
func (e *AuditUsageExamples) ExampleErrorHandling(userID string) {
	// Safe logging that won't crash the application
	defer func() {
		if r := recover(); r != nil {
			// Log the panic but don't let it crash the app
			e.auditService.LogEvent(services.EventSuspiciousActivity, "Audit logging panic recovered", &services.AuditContext{
				UserID: userID,
				Metadata: map[string]interface{}{
					"panic_reason": r,
					"recovery":     true,
				},
			})
		}
	}()

	// Potentially problematic operation
	e.auditService.LogEvent(services.EventDataAccessed, "Operation with potential issues", &services.AuditContext{
		UserID: userID,
		Metadata: map[string]interface{}{
			"test_data": map[string]interface{}{
				"nested": "value",
			},
		},
	})
}

// Example 8: Factory pattern usage
func (e *AuditUsageExamples) ExampleFactoryPattern() {
	// Create a custom audit service using the factory
	factory := services.NewAuditServiceFactory()

	// Configure for high-throughput scenario
	auditService := factory.
		WithBatchSize(500).
		WithFlushInterval(30 * time.Second).
		EnableStreaming().
		DisableEncryption(). // For performance
		EnableCorrelation().
		Create()

	helper := services.NewAuditHelper(auditService)

	// Use the custom service
	helper.LogDataOperation("user123", "bulk_process", "records", "batch789", map[string]interface{}{
		"processing_mode": "high_throughput",
		"record_count":    10000,
	})

	// Don't forget to close when done
	defer auditService.Close()
}

// Example 9: Compliance and regulatory logging
func (e *AuditUsageExamples) ExampleComplianceLogging(userID string) {
	// GDPR compliance logging
	e.auditService.LogComplianceEvent(
		services.EventDataExported,
		"Personal data exported for GDPR request",
		"gdpr",
		map[string]interface{}{
			"request_id":      "gdpr_123",
			"data_subject":    userID,
			"export_format":   "json",
			"data_categories": []string{"personal", "preferences", "activity"},
		},
	)

	// HIPAA compliance logging
	e.auditService.LogComplianceEvent(
		services.EventDataAccessed,
		"Medical record accessed",
		"hipaa",
		map[string]interface{}{
			"patient_id":     "patient_456",
			"accessing_user": userID,
			"access_purpose": "treatment",
			"phi_categories": []string{"demographics", "diagnoses"},
		},
	)

	// SOX compliance logging
	e.auditService.LogComplianceEvent(
		services.EventDataModified,
		"Financial data modified",
		"sox",
		map[string]interface{}{
			"transaction_id": "txn_789",
			"amount":         1000.00,
			"approver":       "manager_123",
			"control_id":     "SOX_001",
		},
	)
}

// Example 10: Integration with middleware
func (e *AuditUsageExamples) ExampleMiddlewareIntegration() {
	// Create audit middleware with custom configuration
	auditMiddleware := middleware.NewAuditMiddleware().
		WithErrorHandler(&CustomErrorHandler{}).
		WithMetricsCollector(&CustomMetricsCollector{})

	// Configure audit settings
	config := middleware.AuditConfig{
		Enabled:              true,
		LogRequests:          true,
		LogResponses:         false,
		LogHeaders:           true,
		LogBody:              false,
		MaxBodySize:          2048,
		SecurityMonitoring:   true,
		PerformanceTracking:  true,
		ComplianceLogging:    true,
		SensitiveDataMasking: true,
		ErrorRecovery:        true,
		AsyncProcessing:      true,
		MaxProcessingTime:    200 * time.Millisecond,
	}

	// Use the configured middleware
	_ = auditMiddleware.WithConfig(config)
}

// Custom error handler example
type CustomErrorHandler struct{}

func (h *CustomErrorHandler) HandleError(err error, ctx http.Context, operation string) {
	// Custom error handling logic
	// Could send to external monitoring service, etc.
}

// Custom metrics collector example
type CustomMetricsCollector struct{}

func (m *CustomMetricsCollector) RecordRequestDuration(path, method string, duration time.Duration, statusCode int) {
	// Custom metrics recording logic
}

func (m *CustomMetricsCollector) RecordAuditProcessingTime(duration time.Duration) {
	// Custom audit processing time recording
}

func (m *CustomMetricsCollector) IncrementErrorCount(errorType string) {
	// Custom error count incrementing
}

func (m *CustomMetricsCollector) RecordRequestSize(size int64) {
	// Custom request size recording
}

func (m *CustomMetricsCollector) RecordResponseSize(size int64) {
	// Custom response size recording
}
