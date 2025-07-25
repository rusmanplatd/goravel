package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"goravel/app/services"

	"github.com/gin-gonic/gin"
	"github.com/goravel/framework/contracts/http"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ObservabilityMiddleware provides comprehensive observability for HTTP requests
type ObservabilityMiddleware struct {
	telemetryService *services.TelemetryService
}

// NewObservabilityMiddleware creates a new observability middleware
func NewObservabilityMiddleware(telemetryService *services.TelemetryService) *ObservabilityMiddleware {
	return &ObservabilityMiddleware{
		telemetryService: telemetryService,
	}
}

// Handle implements the middleware interface for Goravel
func (m *ObservabilityMiddleware) Handle(ctx http.Context) http.Response {
	startTime := time.Now()

	// Recover from panics and record them
	defer func() {
		if r := recover(); r != nil {
			spanCtx := context.Background()
			m.telemetryService.RecordPanic(spanCtx, "http_middleware")
			m.telemetryService.GetLogger().WithFields(map[string]interface{}{
				"panic": r,
				"path":  ctx.Request().Path(),
			}).Error("Panic recovered in observability middleware")
			panic(r) // Re-panic to maintain normal panic behavior
		}
	}()

	// Create a new span for this request
	tracer := m.telemetryService.GetTracer()
	method := ctx.Request().Method()
	path := ctx.Request().Path()
	spanName := fmt.Sprintf("%s %s", method, path)

	requestCtx := context.Background()
	spanCtx, span := tracer.Start(requestCtx, spanName,
		trace.WithAttributes(
			attribute.String("http.method", method),
			attribute.String("http.path", path),
			attribute.String("http.user_agent", ctx.Request().Header("User-Agent", "")),
			attribute.String("http.remote_addr", ctx.Request().Ip()),
			attribute.String("http.host", ctx.Request().Header("Host", "")),
			attribute.String("http.scheme", m.getScheme(ctx)),
		),
	)
	defer span.End()

	// Increment active requests counter
	m.telemetryService.IncActiveHTTPRequests(spanCtx)
	defer m.telemetryService.DecActiveHTTPRequests(spanCtx)

	// Record request size if available
	if contentLength := ctx.Request().Header("Content-Length", ""); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			m.telemetryService.RecordHTTPRequestSize(spanCtx, size)
			span.SetAttributes(attribute.Int64("http.request_size", size))
		}
	}

	// Log request start
	logger := m.telemetryService.GetLogger()
	logger.WithContext(spanCtx).WithFields(map[string]interface{}{
		"method":      method,
		"path":        path,
		"remote_addr": ctx.Request().Ip(),
		"user_agent":  ctx.Request().Header("User-Agent", ""),
		"trace_id":    span.SpanContext().TraceID().String(),
		"span_id":     span.SpanContext().SpanID().String(),
		"host":        ctx.Request().Header("Host", ""),
	}).Info("HTTP request started")

	// Continue to the next middleware/handler
	ctx.Request().Next()

	// Get response after processing
	response := ctx.Response()
	duration := time.Since(startTime)
	statusCode := response.Origin().Status()

	// Get response size if available
	responseSize := int64(0)
	if response.Origin().Size() > 0 {
		responseSize = int64(response.Origin().Size())
		m.telemetryService.RecordHTTPResponseSize(spanCtx, responseSize)
	}

	// Add response attributes to span
	span.SetAttributes(
		attribute.Int("http.status_code", statusCode),
		attribute.Float64("http.duration_ms", float64(duration.Nanoseconds())/1e6),
		attribute.Int64("http.response_size", responseSize),
	)

	// Set span status based on HTTP status code
	if statusCode >= 400 {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
		// Record error metrics for 4xx and 5xx responses
		errorType := "client_error"
		if statusCode >= 500 {
			errorType = "server_error"
		}
		m.telemetryService.RecordError(spanCtx, errorType, "http_handler")
	} else {
		span.SetStatus(codes.Ok, "")
	}

	// Record metrics
	m.telemetryService.RecordHTTPRequest(
		spanCtx,
		method,
		path,
		strconv.Itoa(statusCode),
		duration.Seconds(),
	)

	// Log request completion
	logLevel := "info"
	if statusCode >= 500 {
		logLevel = "error"
	} else if statusCode >= 400 {
		logLevel = "warn"
	}

	logEntry := logger.WithContext(spanCtx).WithFields(map[string]interface{}{
		"method":        method,
		"path":          path,
		"status_code":   statusCode,
		"duration_ms":   float64(duration.Nanoseconds()) / 1e6,
		"response_size": responseSize,
		"trace_id":      span.SpanContext().TraceID().String(),
		"span_id":       span.SpanContext().SpanID().String(),
	})

	switch logLevel {
	case "error":
		logEntry.Error("HTTP request completed with error")
	case "warn":
		logEntry.Warn("HTTP request completed with client error")
	default:
		logEntry.Info("HTTP request completed successfully")
	}

	return nil
}

// getScheme determines the request scheme (http/https)
func (m *ObservabilityMiddleware) getScheme(ctx http.Context) string {
	if ctx.Request().Header("X-Forwarded-Proto", "") == "https" {
		return "https"
	}
	if ctx.Request().Header("X-Forwarded-Ssl", "") == "on" {
		return "https"
	}
	return "http"
}

// GinMiddleware returns a Gin middleware function for OpenTelemetry instrumentation
func (m *ObservabilityMiddleware) GinMiddleware() gin.HandlerFunc {
	// Use the official otelgin middleware with custom configuration
	return otelgin.Middleware("goravel-app",
		otelgin.WithTracerProvider(otel.GetTracerProvider()),
		otelgin.WithPropagators(otel.GetTextMapPropagator()),
	)
}

// MetricsMiddleware returns a Gin middleware specifically for metrics collection
func (m *ObservabilityMiddleware) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Increment active requests
		ctx := c.Request.Context()
		m.telemetryService.IncActiveHTTPRequests(ctx)
		defer m.telemetryService.DecActiveHTTPRequests(ctx)

		// Process request
		c.Next()

		// Record metrics
		duration := time.Since(startTime)
		route := c.FullPath()
		if route == "" {
			route = "unknown"
		}

		m.telemetryService.RecordHTTPRequest(
			ctx,
			c.Request.Method,
			route,
			strconv.Itoa(c.Writer.Status()),
			duration.Seconds(),
		)
	}
}

// LoggingMiddleware returns a Gin middleware for structured logging
func (m *ObservabilityMiddleware) LoggingMiddleware() gin.HandlerFunc {
	logger := m.telemetryService.GetLogger()

	return func(c *gin.Context) {
		startTime := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(startTime)

		// Get client IP
		clientIP := c.ClientIP()

		// Get method
		method := c.Request.Method

		// Get status code
		statusCode := c.Writer.Status()

		// Get body size
		bodySize := c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		// Determine log level based on status code
		logEntry := logger.WithFields(map[string]interface{}{
			"status_code": statusCode,
			"latency_ms":  float64(latency.Nanoseconds()) / 1e6,
			"client_ip":   clientIP,
			"method":      method,
			"path":        path,
			"body_size":   bodySize,
			"user_agent":  c.Request.UserAgent(),
		})

		// Add trace information if available
		if span := trace.SpanFromContext(c.Request.Context()); span.SpanContext().IsValid() {
			logEntry = logEntry.WithFields(map[string]interface{}{
				"trace_id": span.SpanContext().TraceID().String(),
				"span_id":  span.SpanContext().SpanID().String(),
			})
		}

		switch {
		case statusCode >= 500:
			logEntry.Error("Server error")
		case statusCode >= 400:
			logEntry.Warn("Client error")
		case statusCode >= 300:
			logEntry.Info("Redirection")
		default:
			logEntry.Info("Success")
		}
	}
}
