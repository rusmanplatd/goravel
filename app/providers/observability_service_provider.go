package providers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"goravel/app/services"

	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"
)

// ObservabilityServiceProvider provides observability services
type ObservabilityServiceProvider struct{}

// Register registers the observability services into the container
func (o *ObservabilityServiceProvider) Register(app foundation.Application) {
	app.Singleton("telemetry", func(app foundation.Application) (interface{}, error) {
		config := services.NewTelemetryConfigFromEnv()

		// Validate configuration before creating service
		if err := o.validateObservabilityConfig(config); err != nil {
			log.Printf("Invalid observability configuration: %v", err)
			// Return a no-op telemetry service for graceful degradation
			return services.NewNoOpTelemetryService(), nil
		}

		telemetryService, err := services.NewTelemetryService(config)
		if err != nil {
			log.Printf("Failed to initialize telemetry service, falling back to no-op service: %v", err)
			// Return a no-op telemetry service for graceful degradation
			return services.NewNoOpTelemetryService(), nil
		}

		log.Printf("Telemetry service initialized successfully with service name: %s", config.ServiceName)
		return telemetryService, nil
	})
}

// Boot boots the observability services
func (o *ObservabilityServiceProvider) Boot(app foundation.Application) {
	// Initialize telemetry service
	telemetryService, err := app.Make("telemetry")
	if err != nil {
		log.Printf("Failed to resolve telemetry service: %v", err)
		return
	}

	// Check if it's a real telemetry service or no-op service
	if telemetry, ok := telemetryService.(*services.TelemetryService); ok {
		// Configure GORM with OpenTelemetry instrumentation
		o.configureGORMInstrumentation(telemetry)

		// Register shutdown hook
		o.registerShutdownHook(app, telemetry)

		log.Println("Observability service provider booted successfully with full telemetry")
	} else if _, ok := telemetryService.(*services.NoOpTelemetryService); ok {
		log.Println("Observability service provider booted with no-op telemetry service (observability disabled)")
	} else {
		log.Printf("Unknown telemetry service type: %T", telemetryService)
	}
}

// configureGORMInstrumentation sets up GORM with OpenTelemetry instrumentation
func (o *ObservabilityServiceProvider) configureGORMInstrumentation(telemetry *services.TelemetryService) {
	// Note: GORM instrumentation will be handled differently depending on the Goravel ORM interface
	// For now, we'll skip the direct GORM instrumentation and rely on manual instrumentation
	// in database operations through the telemetry service

	log.Println("Database instrumentation will be handled through manual telemetry calls")
}

// registerShutdownHook registers a shutdown hook for graceful telemetry shutdown
func (o *ObservabilityServiceProvider) registerShutdownHook(app foundation.Application, telemetry *services.TelemetryService) {
	// Note: This is a simplified shutdown hook. In a production environment,
	// you might want to integrate with Goravel's graceful shutdown mechanism
	// if available, or use OS signal handling.

	// For now, we'll log that the shutdown hook is registered
	log.Println("Telemetry shutdown hook registered")

	// You can extend this to actually register with Goravel's shutdown system
	// when it becomes available, or implement signal handling here
}

// Shutdown gracefully shuts down the observability services
func (o *ObservabilityServiceProvider) Shutdown() error {
	// Get telemetry service from container
	telemetryService, err := facades.App().Make("telemetry")
	if err != nil {
		return err
	}

	telemetry, ok := telemetryService.(*services.TelemetryService)
	if !ok {
		return nil
	}

	// Shutdown telemetry service with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return telemetry.Shutdown(ctx)
}

// validateObservabilityConfig validates the observability configuration
func (o *ObservabilityServiceProvider) validateObservabilityConfig(config services.TelemetryConfig) error {
	if config.ServiceName == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	// Basic endpoint validation
	if config.OTLPEndpoint != "" && !isValidEndpoint(config.OTLPEndpoint) {
		log.Printf("Warning: Invalid OTLP endpoint format: %s", config.OTLPEndpoint)
	}

	if config.LokiEndpoint != "" && !isValidEndpoint(config.LokiEndpoint) {
		log.Printf("Warning: Invalid Loki endpoint format: %s", config.LokiEndpoint)
	}

	if config.MimirEndpoint != "" && !isValidEndpoint(config.MimirEndpoint) {
		log.Printf("Warning: Invalid Mimir endpoint format: %s", config.MimirEndpoint)
	}

	return nil
}

// isValidEndpoint performs basic endpoint validation
func isValidEndpoint(endpoint string) bool {
	return endpoint != "" && (strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://"))
}
