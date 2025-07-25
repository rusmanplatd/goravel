package examples

import (
	"context"
	"net/http"

	"goravel/app/http/middleware"
	"goravel/app/services"

	"github.com/gin-gonic/gin"
	"github.com/goravel/framework/facades"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// This file demonstrates how to use the observability features in your Goravel application

// ExampleHTTPHandler shows how to use observability middleware with HTTP handlers
func ExampleHTTPHandler() {
	// Get telemetry service from container
	telemetryInterface, _ := facades.App().Make("telemetry")
	telemetryService := telemetryInterface.(*services.TelemetryService)

	// Create observability middleware
	obsMiddleware := middleware.NewObservabilityMiddleware(telemetryService)

	// Create Gin router
	router := gin.New()

	// Add observability middleware
	router.Use(obsMiddleware.GinMiddleware())     // OpenTelemetry tracing
	router.Use(obsMiddleware.MetricsMiddleware()) // Metrics collection
	router.Use(obsMiddleware.LoggingMiddleware()) // Structured logging

	// Example API endpoint
	router.GET("/api/users/:id", func(c *gin.Context) {
		ctx := c.Request.Context()

		// Manual span creation for detailed tracing
		tracer := otel.Tracer("user-service")
		ctx, span := tracer.Start(ctx, "get-user")
		defer span.End()

		userID := c.Param("id")
		span.SetAttributes(attribute.String("user.id", userID))

		// Simulate business logic with custom instrumentation
		user, err := getUserFromDatabase(ctx, userID)
		if err != nil {
			span.SetAttributes(attribute.String("error", err.Error()))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		span.SetAttributes(attribute.String("user.name", user.Name))
		c.JSON(http.StatusOK, user)
	})

	// Start server
	router.Run(":8080")
}

// ExampleCustomMetrics shows how to record custom metrics
func ExampleCustomMetrics(ctx context.Context) {
	// Get telemetry service
	telemetryInterface, _ := facades.App().Make("telemetry")
	telemetryService := telemetryInterface.(*services.TelemetryService)

	// Record HTTP request metrics
	telemetryService.RecordHTTPRequest(ctx, "GET", "/api/users", "200", 0.045)
	telemetryService.RecordHTTPRequestSize(ctx, 1024)
	telemetryService.RecordHTTPResponseSize(ctx, 2048)

	// Record database query metrics
	telemetryService.RecordDBQuery(ctx, "SELECT", 0.012)
	telemetryService.RecordDBTransaction(ctx, "UPDATE")

	// Increment/decrement active request counters
	telemetryService.IncActiveHTTPRequests(ctx)
	defer telemetryService.DecActiveHTTPRequests(ctx)

	// Set active database connections
	telemetryService.SetActiveDBConnections(ctx, 10)

	// Record application metrics
	telemetryService.UpdateMemoryUsage(ctx, 1024*1024*64) // 64MB
	telemetryService.UpdateGoroutineCount(ctx, 100)

	// Record errors and panics
	telemetryService.RecordError(ctx, "validation_error", "user_service")
}

// ExampleStructuredLogging shows how to use structured logging with trace correlation
func ExampleStructuredLogging(ctx context.Context) {
	// Get telemetry service
	telemetryInterface, _ := facades.App().Make("telemetry")
	telemetryService := telemetryInterface.(*services.TelemetryService)
	logger := telemetryService.GetLogger()

	// Log with context (includes trace information automatically)
	logger.WithContext(ctx).WithFields(map[string]interface{}{
		"user_id":    "12345",
		"action":     "login",
		"ip_address": "192.168.1.100",
	}).Info("User login successful")

	// Log errors with additional context
	logger.WithContext(ctx).WithFields(map[string]interface{}{
		"error_code": "AUTH_FAILED",
		"attempt":    3,
	}).Error("Authentication failed")

	// Log performance metrics
	logger.WithContext(ctx).WithFields(map[string]interface{}{
		"operation":   "database_query",
		"duration_ms": 150.5,
		"query_type":  "SELECT",
	}).Warn("Slow database query detected")
}

// ExampleManualTracing shows how to create custom spans and traces
func ExampleManualTracing(ctx context.Context) {
	tracer := otel.Tracer("business-logic")

	// Create a parent span
	ctx, parentSpan := tracer.Start(ctx, "process-order")
	defer parentSpan.End()

	parentSpan.SetAttributes(
		attribute.String("order.id", "order-123"),
		attribute.String("customer.id", "customer-456"),
	)

	// Create child spans for different operations
	ctx, validateSpan := tracer.Start(ctx, "validate-order")
	// Simulate validation logic
	validateSpan.SetAttributes(attribute.Bool("validation.passed", true))
	validateSpan.End()

	ctx, paymentSpan := tracer.Start(ctx, "process-payment")
	// Simulate payment processing
	paymentSpan.SetAttributes(
		attribute.String("payment.method", "credit_card"),
		attribute.Float64("payment.amount", 99.99),
	)
	paymentSpan.End()

	ctx, inventorySpan := tracer.Start(ctx, "update-inventory")
	// Simulate inventory update
	inventorySpan.SetAttributes(attribute.Int("inventory.updated_items", 2))
	inventorySpan.End()

	parentSpan.SetAttributes(attribute.String("order.status", "completed"))
}

// ExampleErrorHandling shows how to handle errors with observability
func ExampleErrorHandling(ctx context.Context) error {
	tracer := otel.Tracer("error-handling")
	ctx, span := tracer.Start(ctx, "risky-operation")
	defer span.End()

	// Get logger
	telemetryInterface, _ := facades.App().Make("telemetry")
	telemetryService := telemetryInterface.(*services.TelemetryService)
	logger := telemetryService.GetLogger()

	// Simulate an operation that might fail
	err := performRiskyOperation(ctx)
	if err != nil {
		// Record error in span
		span.SetAttributes(
			attribute.String("error.type", "database_error"),
			attribute.String("error.message", err.Error()),
		)

		// Log error with context
		logger.WithContext(ctx).WithFields(map[string]interface{}{
			"error":     err.Error(),
			"operation": "risky-operation",
		}).Error("Operation failed")

		return err
	}

	span.SetAttributes(attribute.String("result", "success"))
	logger.WithContext(ctx).Info("Operation completed successfully")
	return nil
}

// Mock types and functions for examples

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func getUserFromDatabase(ctx context.Context, userID string) (*User, error) {
	// This would typically make a database call
	// The GORM instrumentation will automatically trace database queries
	return &User{ID: userID, Name: "John Doe"}, nil
}

func performRiskyOperation(ctx context.Context) error {
	// Simulate some operation that might fail
	return nil
}
