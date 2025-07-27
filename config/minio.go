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
		"endpoint":   VaultConfig("secret/services/minio", "endpoint", "localhost:9000").(string),
		"access_key": VaultConfig("secret/services/minio", "access_key", "miniouserroot").(string),
		"secret_key": VaultConfig("secret/services/minio", "secret_key", "miniouserrootpassword").(string),
		"use_ssl":    VaultConfig("secret/services/minio", "use_ssl", false).(bool),
		"region":     VaultConfig("secret/services/minio", "region", "ap-southeast-1").(string),

		// Default Bucket Configuration
		"bucket":   VaultConfig("secret/services/minio", "bucket", "goravelstorage").(string),
		"location": VaultConfig("secret/services/minio", "location", "ap-southeast-1").(string),

		// Application Buckets
		"buckets": map[string]any{
			"default":   VaultConfig("secret/services/minio", "bucket", "goravelstorage").(string),
			"logs":      VaultConfig("secret/services/minio", "logs_bucket", "goravel-logs").(string),
			"traces":    VaultConfig("secret/services/minio", "traces_bucket", "goravel-traces").(string),
			"metrics":   VaultConfig("secret/services/minio", "metrics_bucket", "goravel-metrics").(string),
			"uploads":   VaultConfig("secret/services/minio", "uploads_bucket", "goravelstorage").(string),
			"avatars":   VaultConfig("secret/services/minio", "avatars_bucket", "goravelstorage").(string),
			"documents": VaultConfig("secret/services/minio", "documents_bucket", "goravelstorage").(string),
		},

		// Path Configuration
		"paths": map[string]any{
			"uploads":   VaultConfig("secret/services/minio", "uploads_path", "uploads").(string),
			"avatars":   VaultConfig("secret/services/minio", "avatars_path", "avatars").(string),
			"documents": VaultConfig("secret/services/minio", "documents_path", "documents").(string),
			"logs":      VaultConfig("secret/services/minio", "logs_path", "logs").(string),
			"traces":    VaultConfig("secret/services/minio", "traces_path", "traces").(string),
			"metrics":   VaultConfig("secret/services/minio", "metrics_path", "metrics").(string),
		},

		// Security Settings
		"public_read_buckets": VaultStringSlice("secret/services/minio", "public_read_buckets", []string{
			"goravelstorage",
		}),

		// Advanced Settings
		"timeout":        VaultConfig("secret/services/minio", "timeout", 30).(int), // seconds
		"retry_attempts": VaultConfig("secret/services/minio", "retry_attempts", 3).(int),
		"part_size":      VaultConfig("secret/services/minio", "part_size", 64*1024*1024).(int), // 64MB

		// Development Settings
		"auto_create_buckets": VaultConfig("secret/services/minio", "auto_create_buckets", true).(bool),
		"enable_logging":      VaultConfig("secret/services/minio", "enable_logging", true).(bool),

		// Observability Integration
		"observability": map[string]any{
			"enabled":         VaultConfig("secret/services/minio", "observability_enabled", true).(bool),
			"metrics_enabled": VaultConfig("secret/services/minio", "metrics_enabled", true).(bool),
			"tracing_enabled": VaultConfig("secret/services/minio", "tracing_enabled", true).(bool),
			"log_operations":  VaultConfig("secret/services/minio", "log_operations", true).(bool),
		},
	})
}
