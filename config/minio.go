package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("minio", map[string]any{
		// MinIO Configuration for Goravel
		//
		// This configuration integrates with the observability stack's MinIO instance
		// for S3-compatible object storage.

		// Connection Settings
		"endpoint":   config.Env("MINIO_ENDPOINT", "localhost:9000"),
		"access_key": config.Env("MINIO_ACCESS_KEY", "miniouserroot"),
		"secret_key": config.Env("MINIO_SECRET_KEY", "miniouserrootpassword"),
		"use_ssl":    config.Env("MINIO_USE_SSL", false),
		"region":     config.Env("MINIO_REGION", "ap-southeast-1"),

		// Default Bucket Configuration
		"bucket":   config.Env("MINIO_BUCKET", "goravelstorage"),
		"location": config.Env("MINIO_LOCATION", "ap-southeast-1"),

		// Application Buckets
		"buckets": map[string]any{
			"default":   config.Env("MINIO_BUCKET", "goravelstorage"),
			"logs":      config.Env("MINIO_LOGS_BUCKET", "goravel-logs"),
			"traces":    config.Env("MINIO_TRACES_BUCKET", "goravel-traces"),
			"metrics":   config.Env("MINIO_METRICS_BUCKET", "goravel-metrics"),
			"uploads":   config.Env("MINIO_UPLOADS_BUCKET", "goravelstorage"),
			"avatars":   config.Env("MINIO_AVATARS_BUCKET", "goravelstorage"),
			"documents": config.Env("MINIO_DOCUMENTS_BUCKET", "goravelstorage"),
		},

		// Path Configuration
		"paths": map[string]any{
			"uploads":   config.Env("MINIO_UPLOADS_PATH", "uploads"),
			"avatars":   config.Env("MINIO_AVATARS_PATH", "avatars"),
			"documents": config.Env("MINIO_DOCUMENTS_PATH", "documents"),
			"logs":      config.Env("MINIO_LOGS_PATH", "logs"),
			"traces":    config.Env("MINIO_TRACES_PATH", "traces"),
			"metrics":   config.Env("MINIO_METRICS_PATH", "metrics"),
		},

		// Security Settings
		"public_read_buckets": []string{
			config.Env("MINIO_BUCKET", "goravelstorage").(string),
		},

		// Advanced Settings
		"timeout":        config.Env("MINIO_TIMEOUT", 30), // seconds
		"retry_attempts": config.Env("MINIO_RETRY_ATTEMPTS", 3),
		"part_size":      config.Env("MINIO_PART_SIZE", 64*1024*1024), // 64MB

		// Development Settings
		"auto_create_buckets": config.Env("MINIO_AUTO_CREATE_BUCKETS", true),
		"enable_logging":      config.Env("MINIO_ENABLE_LOGGING", true),

		// Observability Integration
		"observability": map[string]any{
			"enabled":         config.Env("MINIO_OBSERVABILITY_ENABLED", true),
			"metrics_enabled": config.Env("MINIO_METRICS_ENABLED", true),
			"tracing_enabled": config.Env("MINIO_TRACING_ENABLED", true),
			"log_operations":  config.Env("MINIO_LOG_OPERATIONS", true),
		},
	})
}
