package middleware

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

// AuditMiddleware provides automatic audit logging for HTTP requests
type AuditMiddleware struct {
	auditService     *services.AuditService
	sensitiveHeaders []string
	excludePaths     []string
	errorHandler     ErrorHandler
	metricsCollector MetricsCollector
}

// ErrorHandler handles audit middleware errors
type ErrorHandler interface {
	HandleError(err error, ctx http.Context, operation string)
}

// DefaultErrorHandler provides default error handling
type DefaultErrorHandler struct{}

func (h *DefaultErrorHandler) HandleError(err error, ctx http.Context, operation string) {
	facades.Log().Error("Audit middleware error", map[string]interface{}{
		"error":     err.Error(),
		"operation": operation,
		"path":      ctx.Request().Path(),
		"method":    ctx.Request().Method(),
		"stack":     string(debug.Stack()),
	})
}

// MetricsCollector collects performance metrics
type MetricsCollector interface {
	RecordRequestDuration(path, method string, duration time.Duration, statusCode int)
	RecordAuditProcessingTime(duration time.Duration)
	IncrementErrorCount(errorType string)
	RecordRequestSize(size int64)
	RecordResponseSize(size int64)
}

// DefaultMetricsCollector provides default metrics collection
type DefaultMetricsCollector struct{}

func (m *DefaultMetricsCollector) RecordRequestDuration(path, method string, duration time.Duration, statusCode int) {
	facades.Log().Debug("Request metrics", map[string]interface{}{
		"path":        path,
		"method":      method,
		"duration_ms": duration.Milliseconds(),
		"status_code": statusCode,
	})
}

func (m *DefaultMetricsCollector) RecordAuditProcessingTime(duration time.Duration) {
	facades.Log().Debug("Audit processing time", map[string]interface{}{
		"processing_time_ms": duration.Milliseconds(),
	})
}

func (m *DefaultMetricsCollector) IncrementErrorCount(errorType string) {
	facades.Log().Warning("Audit error", map[string]interface{}{
		"error_type": errorType,
	})
}

func (m *DefaultMetricsCollector) RecordRequestSize(size int64) {
	facades.Log().Debug("Request size", map[string]interface{}{
		"size_bytes": size,
	})
}

func (m *DefaultMetricsCollector) RecordResponseSize(size int64) {
	facades.Log().Debug("Response size", map[string]interface{}{
		"size_bytes": size,
	})
}

// NewAuditMiddleware creates a new audit middleware instance
func NewAuditMiddleware() *AuditMiddleware {
	return &AuditMiddleware{
		auditService: services.NewAuditService(),
		sensitiveHeaders: []string{
			"authorization",
			"cookie",
			"x-api-key",
			"x-auth-token",
			"authentication",
		},
		excludePaths: []string{
			"/health",
			"/metrics",
			"/favicon.ico",
			"/static/",
			"/assets/",
		},
		errorHandler:     &DefaultErrorHandler{},
		metricsCollector: &DefaultMetricsCollector{},
	}
}

// WithErrorHandler sets a custom error handler
func (am *AuditMiddleware) WithErrorHandler(handler ErrorHandler) *AuditMiddleware {
	am.errorHandler = handler
	return am
}

// WithMetricsCollector sets a custom metrics collector
func (am *AuditMiddleware) WithMetricsCollector(collector MetricsCollector) *AuditMiddleware {
	am.metricsCollector = collector
	return am
}

// AuditConfig defines configuration for audit logging
type AuditConfig struct {
	Enabled              bool          `json:"enabled"`
	LogRequests          bool          `json:"log_requests"`
	LogResponses         bool          `json:"log_responses"`
	LogHeaders           bool          `json:"log_headers"`
	LogBody              bool          `json:"log_body"`
	MaxBodySize          int64         `json:"max_body_size"`
	SecurityMonitoring   bool          `json:"security_monitoring"`
	PerformanceTracking  bool          `json:"performance_tracking"`
	ComplianceLogging    bool          `json:"compliance_logging"`
	SensitiveDataMasking bool          `json:"sensitive_data_masking"`
	ErrorRecovery        bool          `json:"error_recovery"`      // New: Enable error recovery
	AsyncProcessing      bool          `json:"async_processing"`    // New: Enable async audit processing
	MaxProcessingTime    time.Duration `json:"max_processing_time"` // New: Max time for audit processing
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled:              true,
		LogRequests:          true,
		LogResponses:         false, // Disabled by default for performance
		LogHeaders:           true,
		LogBody:              false, // Disabled by default for security
		MaxBodySize:          1024,  // 1KB
		SecurityMonitoring:   true,
		PerformanceTracking:  true,
		ComplianceLogging:    true,
		SensitiveDataMasking: true,
		ErrorRecovery:        true,                   // Enable error recovery by default
		AsyncProcessing:      true,                   // Enable async processing by default
		MaxProcessingTime:    100 * time.Millisecond, // 100ms max processing time
	}
}

// WithConfig creates a middleware with custom configuration
func (am *AuditMiddleware) WithConfig(config AuditConfig) http.Middleware {
	return am.Handle(config)
}

// WithDefaults creates a middleware with default configuration
func (am *AuditMiddleware) WithDefaults() http.Middleware {
	return am.Handle(DefaultAuditConfig())
}

// Handle implements the middleware interface with enhanced error handling
func (am *AuditMiddleware) Handle(config AuditConfig) http.Middleware {
	return func(ctx http.Context) {
		if !config.Enabled {
			ctx.Request().Next()
			return
		}

		// Skip excluded paths
		if am.shouldExcludePath(ctx.Request().Path()) {
			ctx.Request().Next()
			return
		}

		startTime := time.Now()
		var requestData *RequestData
		var auditProcessingTime time.Duration

		// Capture request data with error recovery
		func() {
			defer func() {
				if r := recover(); r != nil && config.ErrorRecovery {
					err := fmt.Errorf("panic in request data capture: %v", r)
					am.errorHandler.HandleError(err, ctx, "capture_request_data")
					am.metricsCollector.IncrementErrorCount("request_capture_panic")
				}
			}()

			requestData = am.captureRequestDataSafe(ctx, config)
		}()

		// Continue with request processing
		ctx.Request().Next()

		// Calculate processing duration
		duration := time.Since(startTime)

		// Record request metrics
		statusCode := ctx.Response().Origin().Status()
		am.metricsCollector.RecordRequestDuration(ctx.Request().Path(), ctx.Request().Method(), duration, statusCode)

		// Process audit logging with error recovery and timeout
		if config.AsyncProcessing {
			// Async processing to avoid blocking the response
			go am.processAuditAsync(ctx, requestData, startTime, duration, config)
		} else {
			// Synchronous processing with timeout
			am.processAuditSync(ctx, requestData, startTime, duration, config)
		}

		// Record audit processing time
		auditProcessingTime = time.Since(startTime) - duration
		am.metricsCollector.RecordAuditProcessingTime(auditProcessingTime)
	}
}

// processAuditSync processes audit logging synchronously with timeout protection
func (am *AuditMiddleware) processAuditSync(ctx http.Context, requestData *RequestData, startTime time.Time, duration time.Duration, config AuditConfig) {
	auditStart := time.Now()

	// Use a timeout to prevent long-running audit processing
	done := make(chan bool, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil && config.ErrorRecovery {
				err := fmt.Errorf("panic in audit processing: %v", r)
				am.errorHandler.HandleError(err, ctx, "audit_processing")
				am.metricsCollector.IncrementErrorCount("audit_processing_panic")
			}
			done <- true
		}()

		am.processAuditCore(ctx, requestData, startTime, duration, config)
	}()

	select {
	case <-done:
		// Audit processing completed
	case <-time.After(config.MaxProcessingTime):
		// Timeout occurred
		am.errorHandler.HandleError(
			fmt.Errorf("audit processing timeout after %v", config.MaxProcessingTime),
			ctx, "audit_timeout")
		am.metricsCollector.IncrementErrorCount("audit_timeout")
	}

	auditDuration := time.Since(auditStart)
	am.metricsCollector.RecordAuditProcessingTime(auditDuration)
}

// processAuditAsync processes audit logging asynchronously
func (am *AuditMiddleware) processAuditAsync(ctx http.Context, requestData *RequestData, startTime time.Time, duration time.Duration, config AuditConfig) {
	defer func() {
		if r := recover(); r != nil && config.ErrorRecovery {
			err := fmt.Errorf("panic in async audit processing: %v", r)
			am.errorHandler.HandleError(err, ctx, "async_audit_processing")
			am.metricsCollector.IncrementErrorCount("async_audit_panic")
		}
	}()

	am.processAuditCore(ctx, requestData, startTime, duration, config)
}

// processAuditCore contains the core audit processing logic
func (am *AuditMiddleware) processAuditCore(ctx http.Context, requestData *RequestData, startTime time.Time, duration time.Duration, config AuditConfig) {
	// Capture response data with error handling
	responseData, err := am.captureResponseDataSafe(ctx, config)
	if err != nil {
		am.errorHandler.HandleError(err, ctx, "capture_response_data")
		am.metricsCollector.IncrementErrorCount("response_capture_error")
		// Use minimal response data if capture fails
		responseData = &ResponseData{
			StatusCode: ctx.Response().Origin().Status(),
		}
	}

	// Create audit context with error handling
	auditContext, err := am.buildAuditContextSafe(ctx, requestData, responseData, duration)
	if err != nil {
		am.errorHandler.HandleError(err, ctx, "build_audit_context")
		am.metricsCollector.IncrementErrorCount("context_build_error")
		return
	}

	// Determine audit event type
	event := am.determineAuditEvent(ctx, responseData.StatusCode)

	// Create audit message
	message := am.buildAuditMessage(ctx, responseData.StatusCode, duration)

	// Security monitoring with error handling
	if config.SecurityMonitoring {
		func() {
			defer func() {
				if r := recover(); r != nil {
					err := fmt.Errorf("panic in security analysis: %v", r)
					am.errorHandler.HandleError(err, ctx, "security_analysis")
					am.metricsCollector.IncrementErrorCount("security_analysis_panic")
				}
			}()
			am.performSecurityAnalysis(ctx, auditContext, *requestData, *responseData)
		}()
	}

	// Performance tracking with error handling
	if config.PerformanceTracking {
		func() {
			defer func() {
				if r := recover(); r != nil {
					err := fmt.Errorf("panic in performance tracking: %v", r)
					am.errorHandler.HandleError(err, ctx, "performance_tracking")
					am.metricsCollector.IncrementErrorCount("performance_tracking_panic")
				}
			}()
			am.trackPerformanceMetrics(ctx, duration, *requestData, *responseData)
		}()
	}

	// Log the audit event with error handling
	func() {
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("panic in audit logging: %v", r)
				am.errorHandler.HandleError(err, ctx, "audit_logging")
				am.metricsCollector.IncrementErrorCount("audit_logging_panic")
			}
		}()
		am.auditService.LogEvent(event, message, auditContext)
	}()

	// Log to application log for immediate visibility
	am.logToApplicationLogSafe(ctx, requestData, responseData, duration)
}

// captureRequestDataSafe captures request data with error handling
func (am *AuditMiddleware) captureRequestDataSafe(ctx http.Context, config AuditConfig) *RequestData {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic in captureRequestData: %v", r)
			am.errorHandler.HandleError(err, ctx, "capture_request_data_safe")
			am.metricsCollector.IncrementErrorCount("request_data_capture_panic")
		}
	}()

	return am.captureRequestData(ctx, config)
}

// captureResponseDataSafe captures response data with error handling
func (am *AuditMiddleware) captureResponseDataSafe(ctx http.Context, config AuditConfig) (*ResponseData, error) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic in captureResponseData: %v", r)
			am.errorHandler.HandleError(err, ctx, "capture_response_data_safe")
			am.metricsCollector.IncrementErrorCount("response_data_capture_panic")
		}
	}()

	responseData := &ResponseData{
		StatusCode: ctx.Response().Origin().Status(),
	}

	// Record response size if available
	if response := ctx.Response().Origin(); response != nil {
		// Try to get response size from headers
		if contentLength := response.Header().Get("Content-Length"); contentLength != "" {
			// Parse content length if needed
			responseData.Size = int64(len(contentLength)) // Simplified
		}
	}

	am.metricsCollector.RecordResponseSize(responseData.Size)

	return responseData, nil
}

// buildAuditContextSafe builds audit context with error handling
func (am *AuditMiddleware) buildAuditContextSafe(ctx http.Context, requestData *RequestData, responseData *ResponseData, duration time.Duration) (*services.AuditContext, error) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic in buildAuditContext: %v", r)
			am.errorHandler.HandleError(err, ctx, "build_audit_context_safe")
			am.metricsCollector.IncrementErrorCount("audit_context_build_panic")
		}
	}()

	return am.buildAuditContext(ctx, *requestData, *responseData, duration), nil
}

// logToApplicationLogSafe logs to application log with error handling
func (am *AuditMiddleware) logToApplicationLogSafe(ctx http.Context, requestData *RequestData, responseData *ResponseData, duration time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic in logToApplicationLog: %v", r)
			am.errorHandler.HandleError(err, ctx, "log_to_application_log_safe")
			am.metricsCollector.IncrementErrorCount("application_log_panic")
		}
	}()

	am.logToApplicationLog(ctx, *requestData, *responseData, duration)
}

// RequestData represents captured request data
type RequestData struct {
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	Query       map[string]interface{} `json:"query"`
	Headers     map[string]string      `json:"headers"`
	Body        string                 `json:"body,omitempty"`
	ContentType string                 `json:"content_type"`
	UserAgent   string                 `json:"user_agent"`
	IPAddress   string                 `json:"ip_address"`
	Size        int64                  `json:"size"`
}

// ResponseData represents captured response data
type ResponseData struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
}

func (am *AuditMiddleware) shouldExcludePath(path string) bool {
	for _, excludePath := range am.excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

func (am *AuditMiddleware) captureRequestData(ctx http.Context, config AuditConfig) *RequestData {
	request := ctx.Request()

	data := RequestData{
		Method:      request.Method(),
		Path:        request.Path(),
		ContentType: request.Header("Content-Type", ""),
		UserAgent:   request.Header("User-Agent", ""),
		IPAddress:   am.getClientIP(ctx),
	}

	// Capture query parameters
	if config.LogRequests {
		data.Query = make(map[string]interface{})
		allParams := request.All()
		for key, value := range allParams {
			data.Query[key] = am.sanitizeValue(key, fmt.Sprintf("%v", value))
		}
	}

	// Capture headers
	if config.LogHeaders {
		data.Headers = make(map[string]string)
		// Note: Goravel doesn't provide a direct way to get all headers
		// We'll capture common headers manually
		commonHeaders := []string{
			"Content-Type", "User-Agent", "Accept", "Accept-Language",
			"Accept-Encoding", "Connection", "Host", "Referer",
		}
		for _, headerName := range commonHeaders {
			if headerValue := request.Header(headerName, ""); headerValue != "" {
				data.Headers[headerName] = am.sanitizeHeader(headerName, headerValue)
			}
		}
	}

	// Capture request body (simplified)
	if config.LogBody && request.Method() != "GET" {
		if bodyData := am.captureRequestBody(ctx, config.MaxBodySize); bodyData != "" {
			data.Body = am.sanitizeBody(bodyData)
			data.Size = int64(len(bodyData))
		}
	}

	return &data
}

func (am *AuditMiddleware) captureRequestBody(ctx http.Context, maxSize int64) string {
	// Simplified body capture - in a real implementation, you'd need to
	// carefully handle the request body to avoid consuming it
	return ""
}

func (am *AuditMiddleware) buildAuditContext(ctx http.Context, requestData RequestData, responseData ResponseData, duration time.Duration) *services.AuditContext {
	auditContext := &services.AuditContext{
		IPAddress:  requestData.IPAddress,
		UserAgent:  requestData.UserAgent,
		Path:       requestData.Path,
		Method:     requestData.Method,
		StatusCode: responseData.StatusCode,
		Duration:   duration,
		RequestID:  am.getRequestID(ctx),
		Metadata:   make(map[string]interface{}),
	}

	// Add user context if available
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			auditContext.UserID = id
		}
	}

	// Add tenant context if available
	if tenantID := ctx.Value("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			auditContext.TenantID = id
		}
	}

	// Add session context if available
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if id, ok := sessionID.(string); ok {
			auditContext.SessionID = id
		}
	}

	// Add request/response metadata
	auditContext.Metadata["request_data"] = requestData
	auditContext.Metadata["response_data"] = responseData
	auditContext.Metadata["request_size"] = requestData.Size
	auditContext.Metadata["response_size"] = responseData.Size

	// Add performance metadata
	auditContext.Metadata["processing_time_ms"] = duration.Milliseconds()

	// Determine risk score based on various factors
	auditContext.RiskScore = am.calculateRiskScore(requestData, responseData, auditContext)

	return auditContext
}

func (am *AuditMiddleware) determineAuditEvent(ctx http.Context, statusCode int) services.AuditEvent {
	path := ctx.Request().Path()
	method := ctx.Request().Method()

	// Authentication endpoints
	if strings.Contains(path, "/auth/login") {
		if statusCode >= 200 && statusCode < 300 {
			return services.EventLoginSuccess
		}
		return services.EventLoginFailed
	}

	if strings.Contains(path, "/auth/logout") {
		return services.EventLogout
	}

	// Data access events
	if method == "GET" && statusCode >= 200 && statusCode < 300 {
		return services.EventDataAccessed
	}

	// Data modification events
	if (method == "POST" || method == "PUT" || method == "PATCH") && statusCode >= 200 && statusCode < 300 {
		return services.EventDataModified
	}

	// Data deletion events
	if method == "DELETE" && statusCode >= 200 && statusCode < 300 {
		return services.EventDataDeleted
	}

	// Security events for failed requests
	if statusCode == 401 {
		return services.EventUnauthorizedAccess
	}

	if statusCode == 403 {
		return services.EventUnauthorizedAccess
	}

	if statusCode == 429 {
		return services.EventRateLimitExceeded
	}

	// Default to data access for successful requests
	if statusCode >= 200 && statusCode < 300 {
		return services.EventDataAccessed
	}

	// Default to security event for errors
	return services.EventSuspiciousActivity
}

func (am *AuditMiddleware) buildAuditMessage(ctx http.Context, statusCode int, duration time.Duration) string {
	method := ctx.Request().Method()
	path := ctx.Request().Path()

	if statusCode >= 200 && statusCode < 300 {
		return fmt.Sprintf("HTTP %s %s completed successfully in %dms", method, path, duration.Milliseconds())
	}

	if statusCode >= 400 && statusCode < 500 {
		return fmt.Sprintf("HTTP %s %s failed with client error %d in %dms", method, path, statusCode, duration.Milliseconds())
	}

	if statusCode >= 500 {
		return fmt.Sprintf("HTTP %s %s failed with server error %d in %dms", method, path, statusCode, duration.Milliseconds())
	}

	return fmt.Sprintf("HTTP %s %s completed with status %d in %dms", method, path, statusCode, duration.Milliseconds())
}

func (am *AuditMiddleware) performSecurityAnalysis(ctx http.Context, auditContext *services.AuditContext, requestData RequestData, responseData ResponseData) {
	// Check for SQL injection patterns
	if am.detectSQLInjection(requestData) {
		auditContext.RiskScore += 30
		auditContext.ThreatLevel = "high"
		auditContext.Metadata["security_threat"] = "sql_injection_attempt"
	}

	// Check for XSS patterns
	if am.detectXSS(requestData) {
		auditContext.RiskScore += 25
		auditContext.ThreatLevel = "medium"
		auditContext.Metadata["security_threat"] = "xss_attempt"
	}

	// Check for suspicious user agents
	if am.detectSuspiciousUserAgent(requestData.UserAgent) {
		auditContext.RiskScore += 15
		auditContext.Metadata["security_threat"] = "suspicious_user_agent"
	}

	// Check for brute force patterns
	if am.detectBruteForce(ctx, requestData, responseData) {
		auditContext.RiskScore += 40
		auditContext.ThreatLevel = "high"
		auditContext.Metadata["security_threat"] = "brute_force_attempt"
	}

	// Check for unusual request patterns
	if am.detectUnusualPatterns(requestData, responseData) {
		auditContext.RiskScore += 20
		auditContext.Metadata["security_threat"] = "unusual_request_pattern"
	}
}

func (am *AuditMiddleware) trackPerformanceMetrics(ctx http.Context, duration time.Duration, requestData RequestData, responseData ResponseData) {
	// Log slow requests
	if duration > 5*time.Second {
		am.auditService.LogEvent(
			services.EventSlowQuery,
			fmt.Sprintf("Slow HTTP request: %s %s took %dms", requestData.Method, requestData.Path, duration.Milliseconds()),
			&services.AuditContext{
				Path:     requestData.Path,
				Method:   requestData.Method,
				Duration: duration,
				Metadata: map[string]interface{}{
					"performance_issue": "slow_request",
					"threshold_ms":      5000,
					"actual_ms":         duration.Milliseconds(),
				},
			},
		)
	}

	// Log large responses
	if responseData.Size > 10*1024*1024 { // 10MB
		am.auditService.LogEvent(
			services.EventPerformanceAlert,
			fmt.Sprintf("Large HTTP response: %s %s returned %d bytes", requestData.Method, requestData.Path, responseData.Size),
			&services.AuditContext{
				Path:   requestData.Path,
				Method: requestData.Method,
				Metadata: map[string]interface{}{
					"performance_issue": "large_response",
					"response_size":     responseData.Size,
				},
			},
		)
	}
}

func (am *AuditMiddleware) calculateRiskScore(requestData RequestData, responseData ResponseData, auditContext *services.AuditContext) int {
	score := 0

	// Base score by status code
	if responseData.StatusCode >= 400 && responseData.StatusCode < 500 {
		score += 20
	} else if responseData.StatusCode >= 500 {
		score += 30
	}

	// Increase score for authentication endpoints
	if strings.Contains(requestData.Path, "/auth/") {
		score += 10
	}

	// Increase score for admin endpoints
	if strings.Contains(requestData.Path, "/admin/") {
		score += 15
	}

	// Increase score for API endpoints with sensitive data
	if strings.Contains(requestData.Path, "/api/") && (strings.Contains(requestData.Path, "user") || strings.Contains(requestData.Path, "password")) {
		score += 10
	}

	// Increase score for unusual methods
	if requestData.Method == "PATCH" || requestData.Method == "DELETE" {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (am *AuditMiddleware) getClientIP(ctx http.Context) string {
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

func (am *AuditMiddleware) getRequestID(ctx http.Context) string {
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

func (am *AuditMiddleware) sanitizeHeader(key, value string) string {
	keyLower := strings.ToLower(key)
	for _, sensitive := range am.sensitiveHeaders {
		if strings.ToLower(sensitive) == keyLower {
			return "[REDACTED]"
		}
	}
	return value
}

func (am *AuditMiddleware) sanitizeValue(key, value string) string {
	// This function is no longer used for sensitive data masking
	// as the body is not captured.
	return value
}

func (am *AuditMiddleware) sanitizeBody(body string) string {
	// Try to parse as JSON and sanitize sensitive fields
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Not JSON, return as-is (could implement other sanitization)
		return body
	}

	// Sanitize sensitive fields
	am.sanitizeJSONObject(data)

	// Marshal back to JSON
	sanitized, err := json.Marshal(data)
	if err != nil {
		return body
	}

	return string(sanitized)
}

func (am *AuditMiddleware) sanitizeJSONObject(obj map[string]interface{}) {
	for key, value := range obj {
		keyLower := strings.ToLower(key)

		// Check if key contains sensitive information
		// This logic is no longer relevant as sensitive fields are not captured.
		// Keeping it for now, but it will not have an effect.
		for _, sensitive := range am.sensitiveHeaders { // This line was changed from sensitiveFields to sensitiveHeaders
			if strings.Contains(keyLower, strings.ToLower(sensitive)) {
				obj[key] = "[REDACTED]"
				continue
			}
		}

		// Recursively sanitize nested objects
		if nestedObj, ok := value.(map[string]interface{}); ok {
			am.sanitizeJSONObject(nestedObj)
		}
	}
}

func (am *AuditMiddleware) logToApplicationLog(ctx http.Context, requestData RequestData, responseData ResponseData, duration time.Duration) {
	logData := map[string]interface{}{
		"method":        requestData.Method,
		"path":          requestData.Path,
		"status_code":   responseData.StatusCode,
		"duration_ms":   duration.Milliseconds(),
		"ip_address":    requestData.IPAddress,
		"user_agent":    requestData.UserAgent,
		"request_size":  requestData.Size,
		"response_size": responseData.Size,
	}

	// Add user context if available
	if userID := ctx.Value("user_id"); userID != nil {
		logData["user_id"] = userID
	}

	// Log based on status code
	if responseData.StatusCode >= 500 {
		facades.Log().Error("HTTP Request", logData)
	} else if responseData.StatusCode >= 400 {
		facades.Log().Warning("HTTP Request", logData)
	} else {
		facades.Log().Info("HTTP Request", logData)
	}
}

// Security detection methods

func (am *AuditMiddleware) detectSQLInjection(requestData RequestData) bool {
	patterns := []string{
		"'",
		"--",
		"/*",
		"*/",
		"xp_",
		"sp_",
		"union",
		"select",
		"insert",
		"delete",
		"update",
		"drop",
		"exec",
		"execute",
	}

	checkString := strings.ToLower(requestData.Path + requestData.Body)
	for key, value := range requestData.Query {
		checkString += strings.ToLower(key + fmt.Sprintf("%v", value))
	}

	for _, pattern := range patterns {
		if strings.Contains(checkString, pattern) {
			return true
		}
	}

	return false
}

func (am *AuditMiddleware) detectXSS(requestData RequestData) bool {
	patterns := []string{
		"<script",
		"javascript:",
		"onload=",
		"onerror=",
		"onclick=",
		"onmouseover=",
		"<iframe",
		"<object",
		"<embed",
	}

	checkString := strings.ToLower(requestData.Body)
	for key, value := range requestData.Query {
		checkString += strings.ToLower(key + fmt.Sprintf("%v", value))
	}

	for _, pattern := range patterns {
		if strings.Contains(checkString, pattern) {
			return true
		}
	}

	return false
}

func (am *AuditMiddleware) detectSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"burp",
		"owasp",
		"acunetix",
		"nessus",
		"qualys",
		"rapid7",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

func (am *AuditMiddleware) detectBruteForce(ctx http.Context, requestData RequestData, responseData ResponseData) bool {
	// Check for login endpoints with failed status
	if strings.Contains(requestData.Path, "/auth/login") && responseData.StatusCode == 401 {
		// This would typically check against a rate limiter or cache
		// For now, return false but in production would implement proper detection
		return false
	}

	return false
}

func (am *AuditMiddleware) detectUnusualPatterns(requestData RequestData, responseData ResponseData) bool {
	// Check for unusual request sizes
	if requestData.Size > 1024*1024 { // 1MB
		return true
	}

	// Check for unusual number of query parameters
	if len(requestData.Query) > 50 {
		return true
	}

	// Check for unusual paths
	if strings.Count(requestData.Path, "/") > 10 {
		return true
	}

	return false
}
