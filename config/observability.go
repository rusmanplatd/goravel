package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("observability", map[string]any{
		// Observability Configuration
		//
		// This file contains configuration for the observability stack including
		// OpenTelemetry tracing, metrics, and logging with LGTM stack integration.

		// Service Information
		"service": map[string]any{
			"name":        config.Env("OTEL_SERVICE_NAME", "goravel-app"),
			"version":     config.Env("OTEL_SERVICE_VERSION", "1.0.0"),
			"environment": config.Env("APP_ENV", "development"),
		},

		// OpenTelemetry Configuration
		"otel": map[string]any{
			// OTLP Exporter Configuration
			"otlp": map[string]any{
				"endpoint": config.Env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://tempo:4318"),
				"insecure": config.Env("OTEL_EXPORTER_OTLP_INSECURE", true),
				"timeout":  config.Env("OTEL_EXPORTER_OTLP_TIMEOUT", 30),
			},

			// Tracing Configuration
			"tracing": map[string]any{
				"enabled":     config.Env("OTEL_TRACING_ENABLED", true),
				"sample_rate": config.Env("OTEL_TRACING_SAMPLE_RATE", 1.0),
			},

			// Metrics Configuration
			"metrics": map[string]any{
				"enabled":         config.Env("OTEL_METRICS_ENABLED", true),
				"export_interval": config.Env("OTEL_METRICS_EXPORT_INTERVAL", 30),
				"export_timeout":  config.Env("OTEL_METRICS_EXPORT_TIMEOUT", 30),
			},

			// Development Options
			"development": map[string]any{
				"enable_stdout": config.Env("OTEL_ENABLE_STDOUT", false),
				"pretty_print":  config.Env("OTEL_PRETTY_PRINT", true),
			},
		},

		// Loki Configuration (Logging)
		"loki": map[string]any{
			"enabled":  config.Env("LOKI_ENABLED", true),
			"endpoint": config.Env("LOKI_ENDPOINT", "http://loki:3100"),
			"timeout":  config.Env("LOKI_TIMEOUT", 30),
			"labels": map[string]any{
				"service":     config.Env("OTEL_SERVICE_NAME", "goravel-app"),
				"environment": config.Env("APP_ENV", "development"),
			},
		},

		// Tempo Configuration (Tracing)
		"tempo": map[string]any{
			"enabled":  config.Env("TEMPO_ENABLED", true),
			"endpoint": config.Env("TEMPO_ENDPOINT", "http://tempo:4317"),
			"timeout":  config.Env("TEMPO_TIMEOUT", 30),
		},

		// Mimir Configuration (Metrics)
		"mimir": map[string]any{
			"enabled":  config.Env("MIMIR_ENABLED", true),
			"endpoint": config.Env("MIMIR_ENDPOINT", "http://mimir:9009/api/v1/push"),
			"timeout":  config.Env("MIMIR_TIMEOUT", 30),
		},

		// Grafana Configuration
		"grafana": map[string]any{
			"enabled":  config.Env("GRAFANA_ENABLED", true),
			"endpoint": config.Env("GRAFANA_ENDPOINT", "http://grafana:7030"),
			"username": config.Env("GRAFANA_USERNAME", "admin"),
			"password": config.Env("GRAFANA_PASSWORD", "admin"),
		},

		// Instrumentation Configuration
		"instrumentation": map[string]any{
			// HTTP Instrumentation
			"http": map[string]any{
				"enabled":              config.Env("OTEL_HTTP_ENABLED", true),
				"capture_headers":      config.Env("OTEL_HTTP_CAPTURE_HEADERS", false),
				"capture_body":         config.Env("OTEL_HTTP_CAPTURE_BODY", false),
				"capture_query_params": config.Env("OTEL_HTTP_CAPTURE_QUERY_PARAMS", true),
			},

			// Database Instrumentation
			"database": map[string]any{
				"enabled":              config.Env("OTEL_DB_ENABLED", true),
				"capture_queries":      config.Env("OTEL_DB_CAPTURE_QUERIES", true),
				"slow_query_threshold": config.Env("OTEL_DB_SLOW_QUERY_THRESHOLD", 100), // milliseconds
			},

			// gRPC Instrumentation
			"grpc": map[string]any{
				"enabled": config.Env("OTEL_GRPC_ENABLED", true),
			},

			// Custom Metrics
			"custom_metrics": map[string]any{
				"enabled": config.Env("OTEL_CUSTOM_METRICS_ENABLED", true),
			},
		},

		// Logging Configuration
		"logging": map[string]any{
			"structured":         config.Env("LOG_STRUCTURED", true),
			"format":             config.Env("LOG_FORMAT", "json"), // json, text
			"level":              config.Env("LOG_LEVEL", "info"),
			"include_caller":     config.Env("LOG_INCLUDE_CALLER", false),
			"include_trace_info": config.Env("LOG_INCLUDE_TRACE_INFO", true),
		},

		// Resource Configuration
		"resource": map[string]any{
			"attributes": map[string]any{
				"deployment.environment": config.Env("APP_ENV", "development"),
				"service.namespace":      config.Env("SERVICE_NAMESPACE", "goravel"),
				"service.instance.id":    config.Env("SERVICE_INSTANCE_ID", ""),
				"host.name":              config.Env("HOSTNAME", ""),
			},
		},

		// Sampling Configuration
		"sampling": map[string]any{
			"traces": map[string]any{
				"type": config.Env("OTEL_TRACES_SAMPLER", "always_on"), // always_on, always_off, traceidratio, parentbased_always_on, parentbased_always_off, parentbased_traceidratio
				"arg":  config.Env("OTEL_TRACES_SAMPLER_ARG", 1.0),
			},
		},

		// Security Configuration
		"security": map[string]any{
			"sanitize_headers": config.Env("OTEL_SANITIZE_HEADERS", true),
			"sanitize_body":    config.Env("OTEL_SANITIZE_BODY", true),
			"sensitive_headers": []string{
				"authorization",
				"cookie",
				"x-api-key",
				"x-auth-token",
				"x-csrf-token",
				"x-forwarded-for",
			},
		},

		// Health Check Configuration
		"health_checks": map[string]any{
			"enabled":           config.Env("OTEL_HEALTH_CHECKS_ENABLED", true),
			"check_interval":    config.Env("OTEL_HEALTH_CHECK_INTERVAL", 30), // seconds
			"timeout":           config.Env("OTEL_HEALTH_CHECK_TIMEOUT", 5),   // seconds
			"failure_threshold": config.Env("OTEL_HEALTH_FAILURE_THRESHOLD", 3),
		},

		// Performance Configuration
		"performance": map[string]any{
			"batch_size":       config.Env("OTEL_BATCH_SIZE", 512),
			"batch_timeout":    config.Env("OTEL_BATCH_TIMEOUT", 5), // seconds
			"max_queue_size":   config.Env("OTEL_MAX_QUEUE_SIZE", 2048),
			"max_export_batch": config.Env("OTEL_MAX_EXPORT_BATCH", 512),
		},

		// Error Handling Configuration
		"error_handling": map[string]any{
			"retry_enabled":    config.Env("OTEL_RETRY_ENABLED", true),
			"retry_max_count":  config.Env("OTEL_RETRY_MAX_COUNT", 3),
			"retry_backoff":    config.Env("OTEL_RETRY_BACKOFF", 1000), // milliseconds
			"fallback_enabled": config.Env("OTEL_FALLBACK_ENABLED", true),
		},
	})
}
