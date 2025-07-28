package v1

import (
	"goravel/app/services"
	"time"

	"strconv"

	"github.com/goravel/framework/contracts/http"
)

// VaultController handles Vault monitoring and management endpoints
type VaultController struct {
	e2eeService *services.E2EEService
}

// NewVaultController creates a new Vault controller
func NewVaultController() *VaultController {
	return &VaultController{
		e2eeService: services.NewE2EEService(),
	}
}

// Health returns Vault health status
// @Summary Get Vault health status
// @Description Returns the current health status of the HashiCorp Vault connection
// @Tags vault
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Vault health status"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/health [get]
func (vc *VaultController) Health(ctx http.Context) http.Response {
	healthStatus := vc.e2eeService.GetVaultStorage().GetHealthStatus()

	// Determine HTTP status based on Vault health
	status := http.StatusOK
	if healthStatus["status"] == "unhealthy" || healthStatus["status"] == "sealed" {
		status = http.StatusServiceUnavailable
	}

	return ctx.Response().Status(status).Json(map[string]interface{}{
		"vault_health": healthStatus,
		"timestamp":    time.Now().Unix(),
	})
}

// Metrics returns Vault performance metrics
// @Summary Get Vault performance metrics
// @Description Returns performance metrics for the Vault connection including request counts and response times
// @Tags vault
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Vault metrics"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/metrics [get]
func (vc *VaultController) Metrics(ctx http.Context) http.Response {
	vaultStorage := vc.e2eeService.GetVaultStorage()
	monitor := vaultStorage.GetMonitor()

	if monitor == nil {
		return ctx.Response().Status(http.StatusServiceUnavailable).Json(map[string]interface{}{
			"error": "Vault monitoring not available",
			"type":  "mock_or_unavailable",
		})
	}

	metrics := monitor.GetMetrics()
	cacheStats := vaultStorage.GetCache().GetStats()

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"vault_metrics": map[string]interface{}{
			"connection": map[string]interface{}{
				"status":                metrics.ConnectionStatus,
				"last_health_check":     metrics.LastHealthCheck,
				"health_check_duration": metrics.HealthCheckDuration.String(),
			},
			"requests": map[string]interface{}{
				"total":                 metrics.TotalRequests,
				"successful":            metrics.SuccessfulRequests,
				"failed":                metrics.FailedRequests,
				"average_response_time": metrics.AverageResponseTime.String(),
			},
			"token": map[string]interface{}{
				"ttl_seconds": metrics.TokenTTL,
				"renewable":   metrics.TokenRenewable,
			},
			"errors": map[string]interface{}{
				"last_error":      metrics.LastError,
				"last_error_time": metrics.LastErrorTime,
			},
		},
		"cache_metrics": cacheStats,
		"timestamp":     time.Now().Unix(),
	})
}

// ClearCache clears the Vault key cache
// @Summary Clear Vault key cache
// @Description Clears all cached encryption keys from memory
// @Tags vault
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Cache cleared successfully"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/cache/clear [post]
func (vc *VaultController) ClearCache(ctx http.Context) http.Response {
	vaultStorage := vc.e2eeService.GetVaultStorage()

	// Get cache stats before clearing
	cacheStats := vaultStorage.GetCache().GetStats()

	// Clear the cache
	vaultStorage.ClearCache()

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"message":       "Vault cache cleared successfully",
		"cleared_stats": cacheStats,
		"timestamp":     time.Now().Unix(),
	})
}

// RenewToken attempts to renew the Vault token
// @Summary Renew Vault token
// @Description Renews the current Vault authentication token if renewable
// @Tags vault
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Token renewed successfully"
// @Failure 400 {object} map[string]interface{} "Token not renewable"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/token/renew [post]
func (vc *VaultController) RenewToken(ctx http.Context) http.Response {
	vaultStorage := vc.e2eeService.GetVaultStorage()
	monitor := vaultStorage.GetMonitor()

	if monitor == nil {
		return ctx.Response().Status(http.StatusServiceUnavailable).Json(map[string]interface{}{
			"error": "Vault monitoring not available",
			"type":  "mock_or_unavailable",
		})
	}

	// Attempt to renew token with 1 hour increment
	err := monitor.RenewToken(3600)
	if err != nil {
		return ctx.Response().Status(http.StatusBadRequest).Json(map[string]interface{}{
			"error":   "Failed to renew token",
			"details": err.Error(),
		})
	}

	// Get updated metrics
	metrics := monitor.GetMetrics()

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"message": "Token renewed successfully",
		"token_info": map[string]interface{}{
			"ttl_seconds": metrics.TokenTTL,
			"renewable":   metrics.TokenRenewable,
		},
		"timestamp": time.Now().Unix(),
	})
}

// Status returns overall Vault integration status
// @Summary Get Vault integration status
// @Description Returns comprehensive status information about the Vault integration
// @Tags vault
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Vault integration status"
// @Router /api/v1/vault/status [get]
func (vc *VaultController) Status(ctx http.Context) http.Response {
	vaultStorage := vc.e2eeService.GetVaultStorage()

	status := map[string]interface{}{
		"integration": "hashicorp_vault",
		"version":     "1.0.0",
		"features": []string{
			"key_management",
			"health_monitoring",
			"performance_caching",
			"metrics_collection",
			"token_renewal",
		},
	}

	// Add health information
	healthStatus := vaultStorage.GetHealthStatus()
	status["health"] = healthStatus

	// Add cache information if available
	if cache := vaultStorage.GetCache(); cache != nil {
		status["cache"] = map[string]interface{}{
			"enabled": true,
			"ttl":     cache.GetTTL().String(),
			"stats":   cache.GetStats(),
		}
	} else {
		status["cache"] = map[string]interface{}{
			"enabled": false,
		}
	}

	// Add monitoring information
	if monitor := vaultStorage.GetMonitor(); monitor != nil {
		status["monitoring"] = map[string]interface{}{
			"enabled":           true,
			"connection_status": monitor.GetConnectionStatus(),
			"is_healthy":        monitor.IsHealthy(),
		}
	} else {
		status["monitoring"] = map[string]interface{}{
			"enabled": false,
		}
	}

	return ctx.Response().Json(http.StatusOK, status)
}

// CreateKeyVersion creates a new version of a key
// @Summary Create new key version
// @Description Creates a new version of an encryption key with description and audit trail
// @Tags vault
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param request body map[string]string true "Version creation request"
// @Success 200 {object} map[string]interface{} "Key version created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/keys/{user_id}/versions [post]
func (vc *VaultController) CreateKeyVersion(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "user_id is required",
		})
	}

	var request struct {
		Description string `json:"description"`
		CreatedBy   string `json:"created_by"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "Invalid request format",
		})
	}

	vaultStorage := vc.e2eeService.GetVaultStorage()
	version, err := vaultStorage.CreateMasterKeyVersion(userID, request.Description, request.CreatedBy)
	if err != nil {
		return ctx.Response().Status(http.StatusInternalServerError).Json( map[string]interface{}{
			"error":   "Failed to create key version",
			"details": err.Error(),
		})
	}

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"message": "Key version created successfully",
		"version": map[string]interface{}{
			"version":     version.Version,
			"created_at":  version.CreatedAt,
			"created_by":  version.CreatedBy,
			"description": version.Description,
			"active":      version.Active,
			"key_hash":    version.KeyHash,
		},
		"timestamp": time.Now().Unix(),
	})
}

// ListKeyVersions lists all versions of a key
// @Summary List key versions
// @Description Returns all versions of an encryption key with metadata
// @Tags vault
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{} "Key versions list"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/keys/{user_id}/versions [get]
func (vc *VaultController) ListKeyVersions(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "user_id is required",
		})
	}

	vaultStorage := vc.e2eeService.GetVaultStorage()
	versions, err := vaultStorage.ListMasterKeyVersions(userID)
	if err != nil {
		return ctx.Response().Status(http.StatusInternalServerError).Json( map[string]interface{}{
			"error":   "Failed to list key versions",
			"details": err.Error(),
		})
	}

	// Format versions for response
	versionsList := make([]map[string]interface{}, len(versions))
	for i, v := range versions {
		versionsList[i] = map[string]interface{}{
			"version":     v.Version,
			"created_at":  v.CreatedAt,
			"created_by":  v.CreatedBy,
			"description": v.Description,
			"active":      v.Active,
			"key_hash":    v.KeyHash,
		}
	}

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"user_id":   userID,
		"versions":  versionsList,
		"total":     len(versions),
		"timestamp": time.Now().Unix(),
	})
}

// RollbackKey rolls back a key to a previous version
// @Summary Rollback key version
// @Description Rolls back an encryption key to a previous version
// @Tags vault
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param request body map[string]interface{} true "Rollback request"
// @Success 200 {object} map[string]interface{} "Key rolled back successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/keys/{user_id}/rollback [post]
func (vc *VaultController) RollbackKey(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "user_id is required",
		})
	}

	var request struct {
		TargetVersion int    `json:"target_version"`
		RollbackBy    string `json:"rollback_by"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "Invalid request format",
		})
	}

	if request.TargetVersion <= 0 {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "target_version must be greater than 0",
		})
	}

	vaultStorage := vc.e2eeService.GetVaultStorage()
	err := vaultStorage.RollbackMasterKey(userID, request.TargetVersion, request.RollbackBy)
	if err != nil {
		return ctx.Response().Status(http.StatusInternalServerError).Json( map[string]interface{}{
			"error":   "Failed to rollback key",
			"details": err.Error(),
		})
	}

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"message":        "Key rolled back successfully",
		"user_id":        userID,
		"target_version": request.TargetVersion,
		"rollback_by":    request.RollbackBy,
		"timestamp":      time.Now().Unix(),
	})
}

// DeleteKeyVersion soft-deletes a specific key version
// @Summary Delete key version
// @Description Soft-deletes a specific version of an encryption key
// @Tags vault
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param version path int true "Version number"
// @Param request body map[string]string true "Delete request"
// @Success 200 {object} map[string]interface{} "Key version deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/keys/{user_id}/versions/{version} [delete]
func (vc *VaultController) DeleteKeyVersion(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	versionStr := ctx.Request().Input("version")

	if userID == "" || versionStr == "" {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "user_id and version are required",
		})
	}

	version, err := strconv.Atoi(versionStr)
	if err != nil || version <= 0 {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "version must be a positive integer",
		})
	}

	var request struct {
		DeletedBy string `json:"deleted_by"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "Invalid request format",
		})
	}

	vaultStorage := vc.e2eeService.GetVaultStorage()
	err = vaultStorage.DeleteMasterKeyVersion(userID, version, request.DeletedBy)
	if err != nil {
		return ctx.Response().Status(http.StatusInternalServerError).Json( map[string]interface{}{
			"error":   "Failed to delete key version",
			"details": err.Error(),
		})
	}

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"message":    "Key version deleted successfully",
		"user_id":    userID,
		"version":    version,
		"deleted_by": request.DeletedBy,
		"timestamp":  time.Now().Unix(),
	})
}

// GetKeyHistory returns the complete version history for a key
// @Summary Get key version history
// @Description Returns the complete version history for an encryption key
// @Tags vault
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{} "Key version history"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/vault/keys/{user_id}/history [get]
func (vc *VaultController) GetKeyHistory(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return ctx.Response().Status(http.StatusBadRequest).Json( map[string]interface{}{
			"error": "user_id is required",
		})
	}

	vaultStorage := vc.e2eeService.GetVaultStorage()
	history, err := vaultStorage.GetMasterKeyHistory(userID)
	if err != nil {
		return ctx.Response().Status(http.StatusInternalServerError).Json( map[string]interface{}{
			"error":   "Failed to get key history",
			"details": err.Error(),
		})
	}

	// Format versions for response (without key data)
	versionsList := make([]map[string]interface{}, len(history.Versions))
	for i, v := range history.Versions {
		versionsList[i] = map[string]interface{}{
			"version":     v.Version,
			"created_at":  v.CreatedAt,
			"created_by":  v.CreatedBy,
			"description": v.Description,
			"active":      v.Active,
			"key_hash":    v.KeyHash,
		}
	}

	return ctx.Response().Json(http.StatusOK, map[string]interface{}{
		"key_id":          history.KeyID,
		"current_version": history.CurrentVersion,
		"total_versions":  history.TotalVersions,
		"last_rotation":   history.LastRotation,
		"rotation_policy": history.RotationPolicy,
		"versions":        versionsList,
		"timestamp":       time.Now().Unix(),
	})
}
