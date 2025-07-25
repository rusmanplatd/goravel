package services

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

// TelemetryService manages OpenTelemetry configuration and provides instrumentation
type TelemetryService struct {
	tracer         trace.Tracer
	meter          metric.Meter
	logger         *logrus.Logger
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	resource       *resource.Resource

	// HTTP Metrics instruments
	httpRequestsTotal   metric.Int64Counter
	httpRequestDuration metric.Float64Histogram
	httpActiveRequests  metric.Int64UpDownCounter
	httpRequestSize     metric.Int64Histogram
	httpResponseSize    metric.Int64Histogram

	// Database Metrics instruments
	dbConnectionsActive metric.Int64UpDownCounter
	dbQueryDuration     metric.Float64Histogram
	dbQueryTotal        metric.Int64Counter
	dbTransactionTotal  metric.Int64Counter

	// Application Metrics instruments
	appStartupTime metric.Float64Histogram
	memoryUsage    metric.Int64UpDownCounter
	goroutineCount metric.Int64UpDownCounter

	// Error Metrics instruments
	errorTotal metric.Int64Counter
	panicTotal metric.Int64Counter

	// Health check related
	healthStatus map[string]bool
	healthMutex  sync.RWMutex
	healthTicker *time.Ticker
	healthStopCh chan struct{}
}

// TelemetryConfig holds configuration for telemetry setup
type TelemetryConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string
	LokiEndpoint   string
	MimirEndpoint  string
	EnableStdout   bool
}

// NewTelemetryService creates and initializes a new telemetry service
func NewTelemetryService(config TelemetryConfig) (*TelemetryService, error) {
	service := &TelemetryService{
		logger:       logrus.New(),
		healthStatus: make(map[string]bool),
		healthStopCh: make(chan struct{}),
	}

	// Initialize resource
	if err := service.initResource(config); err != nil {
		return nil, fmt.Errorf("failed to initialize resource: %w", err)
	}

	// Initialize tracing
	if err := service.initTracing(config); err != nil {
		return nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	// Initialize metrics
	if err := service.initMetrics(config); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Initialize logging
	service.initLogging(config)

	// Initialize metric instruments
	if err := service.initInstruments(); err != nil {
		return nil, fmt.Errorf("failed to initialize instruments: %w", err)
	}

	// Start health checks
	service.startHealthChecks(config)

	return service, nil
}

// initResource creates the OpenTelemetry resource
func (t *TelemetryService) initResource(config TelemetryConfig) error {
	var err error
	t.resource, err = resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
			semconv.DeploymentEnvironmentKey.String(config.Environment),
			attribute.String("component", "goravel-app"),
		),
	)
	return err
}

// initTracing sets up OpenTelemetry tracing
func (t *TelemetryService) initTracing(config TelemetryConfig) error {
	var exporters []sdktrace.SpanExporter

	// OTLP HTTP exporter for Tempo
	if config.OTLPEndpoint != "" {
		otlpExporter, err := otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpoint(config.OTLPEndpoint),
			otlptracehttp.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}
		exporters = append(exporters, otlpExporter)
	}

	// Stdout exporter for development
	if config.EnableStdout {
		stdoutExporter, err := stdouttrace.New(
			stdouttrace.WithPrettyPrint(),
		)
		if err != nil {
			return fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}
		exporters = append(exporters, stdoutExporter)
	}

	// Create tracer provider
	var spanProcessors []sdktrace.SpanProcessor
	for _, exporter := range exporters {
		spanProcessors = append(spanProcessors, sdktrace.NewBatchSpanProcessor(exporter))
	}

	var options []sdktrace.TracerProviderOption
	options = append(options, sdktrace.WithResource(t.resource))
	options = append(options, sdktrace.WithSampler(sdktrace.AlwaysSample()))
	for _, processor := range spanProcessors {
		options = append(options, sdktrace.WithSpanProcessor(processor))
	}

	t.tracerProvider = sdktrace.NewTracerProvider(options...)

	// Set global tracer provider
	otel.SetTracerProvider(t.tracerProvider)

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer
	t.tracer = t.tracerProvider.Tracer("goravel-app")

	return nil
}

// initMetrics sets up OpenTelemetry metrics
func (t *TelemetryService) initMetrics(config TelemetryConfig) error {
	var exporters []sdkmetric.Exporter

	// OTLP HTTP exporter for Mimir
	if config.MimirEndpoint != "" {
		otlpExporter, err := otlpmetrichttp.New(
			context.Background(),
			otlpmetrichttp.WithEndpoint(config.MimirEndpoint),
			otlpmetrichttp.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("failed to create OTLP metric exporter: %w", err)
		}
		exporters = append(exporters, otlpExporter)
	}

	// Stdout exporter for development
	if config.EnableStdout {
		stdoutExporter, err := stdoutmetric.New()
		if err != nil {
			return fmt.Errorf("failed to create stdout metric exporter: %w", err)
		}
		exporters = append(exporters, stdoutExporter)
	}

	// Create meter provider
	var readers []sdkmetric.Reader
	for _, exporter := range exporters {
		readers = append(readers, sdkmetric.NewPeriodicReader(
			exporter,
			sdkmetric.WithInterval(30*time.Second),
		))
	}

	var options []sdkmetric.Option
	options = append(options, sdkmetric.WithResource(t.resource))
	for _, reader := range readers {
		options = append(options, sdkmetric.WithReader(reader))
	}

	t.meterProvider = sdkmetric.NewMeterProvider(options...)

	// Set global meter provider
	otel.SetMeterProvider(t.meterProvider)

	// Create meter
	t.meter = t.meterProvider.Meter("goravel-app")

	return nil
}

// initLogging sets up structured logging with Loki integration
func (t *TelemetryService) initLogging(config TelemetryConfig) {
	t.logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	t.logger.SetLevel(logrus.InfoLevel)

	// Add service information to all log entries
	t.logger = t.logger.WithFields(logrus.Fields{
		"service":     config.ServiceName,
		"version":     config.ServiceVersion,
		"environment": config.Environment,
	}).Logger
}

// initInstruments creates metric instruments
func (t *TelemetryService) initInstruments() error {
	var err error

	// HTTP metrics
	t.httpRequestsTotal, err = t.meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	t.httpRequestDuration, err = t.meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	t.httpActiveRequests, err = t.meter.Int64UpDownCounter(
		"http_active_requests",
		metric.WithDescription("Number of active HTTP requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	t.httpRequestSize, err = t.meter.Int64Histogram(
		"http_request_size_bytes",
		metric.WithDescription("HTTP request size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	t.httpResponseSize, err = t.meter.Int64Histogram(
		"http_response_size_bytes",
		metric.WithDescription("HTTP response size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	// Database metrics
	t.dbConnectionsActive, err = t.meter.Int64UpDownCounter(
		"db_connections_active",
		metric.WithDescription("Number of active database connections"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	t.dbQueryDuration, err = t.meter.Float64Histogram(
		"db_query_duration_seconds",
		metric.WithDescription("Database query duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	t.dbQueryTotal, err = t.meter.Int64Counter(
		"db_queries_total",
		metric.WithDescription("Total number of database queries"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	t.dbTransactionTotal, err = t.meter.Int64Counter(
		"db_transactions_total",
		metric.WithDescription("Total number of database transactions"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Application metrics
	t.appStartupTime, err = t.meter.Float64Histogram(
		"app_startup_duration_seconds",
		metric.WithDescription("Application startup duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	t.memoryUsage, err = t.meter.Int64UpDownCounter(
		"app_memory_usage_bytes",
		metric.WithDescription("Application memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	t.goroutineCount, err = t.meter.Int64UpDownCounter(
		"app_goroutines_active",
		metric.WithDescription("Number of active goroutines"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Error metrics
	t.errorTotal, err = t.meter.Int64Counter(
		"app_errors_total",
		metric.WithDescription("Total number of application errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	t.panicTotal, err = t.meter.Int64Counter(
		"app_panics_total",
		metric.WithDescription("Total number of application panics"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	return nil
}

// GetTracer returns the OpenTelemetry tracer
func (t *TelemetryService) GetTracer() trace.Tracer {
	return t.tracer
}

// GetMeter returns the OpenTelemetry meter
func (t *TelemetryService) GetMeter() metric.Meter {
	return t.meter
}

// GetLogger returns the structured logger
func (t *TelemetryService) GetLogger() *logrus.Logger {
	return t.logger
}

// RecordHTTPRequest records HTTP request metrics
func (t *TelemetryService) RecordHTTPRequest(ctx context.Context, method, route, statusCode string, duration float64) {
	attributes := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("route", route),
		attribute.String("status_code", statusCode),
	}

	t.httpRequestsTotal.Add(ctx, 1, metric.WithAttributes(attributes...))
	t.httpRequestDuration.Record(ctx, duration, metric.WithAttributes(attributes...))
}

// IncActiveHTTPRequests increments active HTTP requests counter
func (t *TelemetryService) IncActiveHTTPRequests(ctx context.Context) {
	t.httpActiveRequests.Add(ctx, 1)
}

// DecActiveHTTPRequests decrements active HTTP requests counter
func (t *TelemetryService) DecActiveHTTPRequests(ctx context.Context) {
	t.httpActiveRequests.Add(ctx, -1)
}

// RecordDBQuery records database query metrics
func (t *TelemetryService) RecordDBQuery(ctx context.Context, operation string, duration float64) {
	attributes := []attribute.KeyValue{
		attribute.String("operation", operation),
	}

	t.dbQueryDuration.Record(ctx, duration, metric.WithAttributes(attributes...))
}

// SetActiveDBConnections sets the number of active database connections
func (t *TelemetryService) SetActiveDBConnections(ctx context.Context, count int64) {
	// Reset counter and set new value
	t.dbConnectionsActive.Add(ctx, count)
}

// RecordHTTPRequestSize records HTTP request size metrics
func (t *TelemetryService) RecordHTTPRequestSize(ctx context.Context, size int64) {
	t.httpRequestSize.Record(ctx, size)
}

// RecordHTTPResponseSize records HTTP response size metrics
func (t *TelemetryService) RecordHTTPResponseSize(ctx context.Context, size int64) {
	t.httpResponseSize.Record(ctx, size)
}

// RecordDBTransaction records database transaction metrics
func (t *TelemetryService) RecordDBTransaction(ctx context.Context, operation string) {
	attributes := []attribute.KeyValue{
		attribute.String("operation", operation),
	}
	t.dbTransactionTotal.Add(ctx, 1, metric.WithAttributes(attributes...))
}

// RecordError records application error metrics
func (t *TelemetryService) RecordError(ctx context.Context, errorType, component string) {
	attributes := []attribute.KeyValue{
		attribute.String("error_type", errorType),
		attribute.String("component", component),
	}
	t.errorTotal.Add(ctx, 1, metric.WithAttributes(attributes...))
}

// RecordPanic records application panic metrics
func (t *TelemetryService) RecordPanic(ctx context.Context, component string) {
	attributes := []attribute.KeyValue{
		attribute.String("component", component),
	}
	t.panicTotal.Add(ctx, 1, metric.WithAttributes(attributes...))
}

// RecordStartupTime records application startup time
func (t *TelemetryService) RecordStartupTime(ctx context.Context, duration float64) {
	t.appStartupTime.Record(ctx, duration)
}

// UpdateMemoryUsage updates memory usage metrics
func (t *TelemetryService) UpdateMemoryUsage(ctx context.Context, bytes int64) {
	t.memoryUsage.Add(ctx, bytes)
}

// UpdateGoroutineCount updates goroutine count metrics
func (t *TelemetryService) UpdateGoroutineCount(ctx context.Context, count int64) {
	t.goroutineCount.Add(ctx, count)
}

// Shutdown gracefully shuts down the telemetry service
func (t *TelemetryService) Shutdown(ctx context.Context) error {
	var err error

	// Stop health checks
	t.stopHealthChecks()

	if t.tracerProvider != nil {
		if shutdownErr := t.tracerProvider.Shutdown(ctx); shutdownErr != nil {
			err = fmt.Errorf("failed to shutdown tracer provider: %w", shutdownErr)
		}
	}

	if t.meterProvider != nil {
		if shutdownErr := t.meterProvider.Shutdown(ctx); shutdownErr != nil {
			if err != nil {
				err = fmt.Errorf("%v; failed to shutdown meter provider: %w", err, shutdownErr)
			} else {
				err = fmt.Errorf("failed to shutdown meter provider: %w", shutdownErr)
			}
		}
	}

	return err
}

// startHealthChecks starts periodic health checks for observability backends
func (t *TelemetryService) startHealthChecks(config TelemetryConfig) {
	// Start health check ticker (every 30 seconds)
	t.healthTicker = time.NewTicker(30 * time.Second)

	go t.runHealthChecks(config)
}

// stopHealthChecks stops the health check routine
func (t *TelemetryService) stopHealthChecks() {
	if t.healthTicker != nil {
		t.healthTicker.Stop()
	}

	select {
	case t.healthStopCh <- struct{}{}:
	default:
	}
}

// runHealthChecks runs periodic health checks
func (t *TelemetryService) runHealthChecks(config TelemetryConfig) {
	// Initial health check
	t.performHealthChecks(config)

	for {
		select {
		case <-t.healthTicker.C:
			t.performHealthChecks(config)
		case <-t.healthStopCh:
			return
		}
	}
}

// performHealthChecks performs health checks on all configured backends
func (t *TelemetryService) performHealthChecks(config TelemetryConfig) {
	t.healthMutex.Lock()
	defer t.healthMutex.Unlock()

	// Check OTLP endpoint
	if config.OTLPEndpoint != "" {
		t.healthStatus["otlp"] = t.checkEndpointHealth(config.OTLPEndpoint)
	}

	// Check Loki endpoint
	if config.LokiEndpoint != "" {
		t.healthStatus["loki"] = t.checkEndpointHealth(config.LokiEndpoint + "/ready")
	}

	// Check Mimir endpoint
	if config.MimirEndpoint != "" {
		t.healthStatus["mimir"] = t.checkEndpointHealth(config.MimirEndpoint)
	}
}

// checkEndpointHealth checks if an endpoint is healthy
func (t *TelemetryService) checkEndpointHealth(endpoint string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500
}

// GetHealthStatus returns the current health status of all backends
func (t *TelemetryService) GetHealthStatus() map[string]bool {
	t.healthMutex.RLock()
	defer t.healthMutex.RUnlock()

	status := make(map[string]bool)
	for k, v := range t.healthStatus {
		status[k] = v
	}

	return status
}

// IsHealthy returns true if all configured backends are healthy
func (t *TelemetryService) IsHealthy() bool {
	t.healthMutex.RLock()
	defer t.healthMutex.RUnlock()

	for _, healthy := range t.healthStatus {
		if !healthy {
			return false
		}
	}

	return len(t.healthStatus) > 0
}

// NewTelemetryConfigFromEnv creates telemetry config from environment variables
func NewTelemetryConfigFromEnv() TelemetryConfig {
	return TelemetryConfig{
		ServiceName:    getEnvOrDefault("OTEL_SERVICE_NAME", "goravel-app"),
		ServiceVersion: getEnvOrDefault("OTEL_SERVICE_VERSION", "1.0.0"),
		Environment:    getEnvOrDefault("APP_ENV", "development"),
		OTLPEndpoint:   getEnvOrDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://tempo:4318"),
		LokiEndpoint:   getEnvOrDefault("LOKI_ENDPOINT", "http://loki:3100"),
		MimirEndpoint:  getEnvOrDefault("MIMIR_ENDPOINT", "http://mimir:9009/api/v1/push"),
		EnableStdout:   getEnvOrDefault("OTEL_ENABLE_STDOUT", "false") == "true",
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// NoOpTelemetryService is a no-operation telemetry service for graceful degradation
type NoOpTelemetryService struct {
	logger *logrus.Logger
}

// NewNoOpTelemetryService creates a new no-op telemetry service
func NewNoOpTelemetryService() *NoOpTelemetryService {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	logger.SetLevel(logrus.InfoLevel)

	return &NoOpTelemetryService{
		logger: logger,
	}
}

// GetTracer returns a no-op tracer
func (n *NoOpTelemetryService) GetTracer() trace.Tracer {
	return otel.Tracer("noop")
}

// GetMeter returns a no-op meter
func (n *NoOpTelemetryService) GetMeter() metric.Meter {
	return otel.Meter("noop")
}

// GetLogger returns the logger
func (n *NoOpTelemetryService) GetLogger() *logrus.Logger {
	return n.logger
}

// RecordHTTPRequest is a no-op
func (n *NoOpTelemetryService) RecordHTTPRequest(ctx context.Context, method, route, statusCode string, duration float64) {
	// No-op
}

// IncActiveHTTPRequests is a no-op
func (n *NoOpTelemetryService) IncActiveHTTPRequests(ctx context.Context) {
	// No-op
}

// DecActiveHTTPRequests is a no-op
func (n *NoOpTelemetryService) DecActiveHTTPRequests(ctx context.Context) {
	// No-op
}

// RecordDBQuery is a no-op
func (n *NoOpTelemetryService) RecordDBQuery(ctx context.Context, operation string, duration float64) {
	// No-op
}

// SetActiveDBConnections is a no-op
func (n *NoOpTelemetryService) SetActiveDBConnections(ctx context.Context, count int64) {
	// No-op
}

// Shutdown is a no-op
func (n *NoOpTelemetryService) Shutdown(ctx context.Context) error {
	return nil
}
