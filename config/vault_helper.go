package config

import (
	"fmt"
	"strconv"
	"strings"

	"goravel/app/services"

	"github.com/goravel/framework/facades"
)

// VaultConfig retrieves configuration values from HashiCorp Vault
// This replaces config.Env() calls throughout the application
func VaultConfig(path string, key string, defaultValue interface{}) interface{} {
	// Get Vault service from container
	vaultService, err := facades.App().Make("vault")
	if err != nil {
		facades.Log().Error("Failed to get Vault service", map[string]interface{}{
			"error": err.Error(),
			"path":  path,
			"key":   key,
		})
		return defaultValue
	}

	// Handle nil vault service (disabled in development)
	if vaultService == nil {
		facades.Log().Warning("Vault service not available, using default value", map[string]interface{}{
			"path":         path,
			"key":          key,
			"defaultValue": defaultValue,
		})
		return defaultValue
	}

	// Cast to VaultService
	vs, ok := vaultService.(*services.VaultService)
	if !ok {
		facades.Log().Error("Invalid Vault service type", map[string]interface{}{
			"type": fmt.Sprintf("%T", vaultService),
			"path": path,
			"key":  key,
		})
		return defaultValue
	}

	// Get secret from Vault
	secret, err := vs.GetSecret(path)
	if err != nil {
		facades.Log().Error("Failed to retrieve secret from Vault", map[string]interface{}{
			"error": err.Error(),
			"path":  path,
			"key":   key,
		})
		return defaultValue
	}

	// Extract the specific key from secret data
	value, exists := secret.Data[key]
	if !exists {
		facades.Log().Warning("Key not found in Vault secret", map[string]interface{}{
			"path": path,
			"key":  key,
		})
		return defaultValue
	}

	// Convert value to expected type based on defaultValue
	return convertToType(value, defaultValue)
}

// convertToType converts the value from Vault to the expected type
func convertToType(value interface{}, defaultValue interface{}) interface{} {
	if value == nil {
		return defaultValue
	}

	switch defaultValue.(type) {
	case string:
		if str, ok := value.(string); ok {
			return str
		}
		return fmt.Sprintf("%v", value)

	case int:
		switch v := value.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
		return defaultValue

	case int64:
		switch v := value.(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				return i
			}
		}
		return defaultValue

	case float64:
		switch v := value.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
		return defaultValue

	case bool:
		switch v := value.(type) {
		case bool:
			return v
		case string:
			switch strings.ToLower(v) {
			case "true", "1", "yes", "on":
				return true
			case "false", "0", "no", "off":
				return false
			}
		case int:
			return v != 0
		case int64:
			return v != 0
		}
		return defaultValue

	default:
		return value
	}
}

// VaultStringSlice retrieves a string slice from Vault
func VaultStringSlice(path string, key string, defaultValue []string) []string {
	value := VaultConfig(path, key, defaultValue)

	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			result[i] = fmt.Sprintf("%v", item)
		}
		return result
	case string:
		// Handle comma-separated string
		if v == "" {
			return defaultValue
		}
		return strings.Split(v, ",")
	default:
		return defaultValue
	}
}

// VaultMap retrieves a map from Vault
func VaultMap(path string, key string, defaultValue map[string]interface{}) map[string]interface{} {
	value := VaultConfig(path, key, defaultValue)

	if m, ok := value.(map[string]interface{}); ok {
		return m
	}

	return defaultValue
}
