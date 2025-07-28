package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// VaultMonitor provides monitoring and health checking for Vault
type VaultMonitor struct {
	client          *api.Client
	healthCheckDone chan bool
	metrics         *VaultMetrics
	mu              sync.RWMutex
}

// VaultMetrics holds performance and health metrics
type VaultMetrics struct {
	ConnectionStatus    string        `json:"connection_status"`
	LastHealthCheck     time.Time     `json:"last_health_check"`
	HealthCheckDuration time.Duration `json:"health_check_duration"`
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	LastError           string        `json:"last_error,omitempty"`
	LastErrorTime       time.Time     `json:"last_error_time,omitempty"`
	TokenTTL            int           `json:"token_ttl,omitempty"`
	TokenRenewable      bool          `json:"token_renewable"`
}

// NewVaultMonitor creates a new Vault monitor
func NewVaultMonitor(client *api.Client) *VaultMonitor {
	monitor := &VaultMonitor{
		client:          client,
		healthCheckDone: make(chan bool),
		metrics: &VaultMetrics{
			ConnectionStatus: "unknown",
			LastHealthCheck:  time.Now(),
		},
	}

	// Start health monitoring in background
	go monitor.startHealthMonitoring()

	return monitor
}

// startHealthMonitoring runs continuous health checks
func (vm *VaultMonitor) startHealthMonitoring() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	// Initial health check
	vm.performHealthCheck()

	for {
		select {
		case <-ticker.C:
			vm.performHealthCheck()
		case <-vm.healthCheckDone:
			safeLog("info", "Vault health monitoring stopped", nil)
			return
		}
	}
}

// performHealthCheck executes a health check against Vault
func (vm *VaultMonitor) performHealthCheck() {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	start := time.Now()

	// Perform health check
	health, err := vm.client.Sys().Health()
	duration := time.Since(start)

	vm.metrics.LastHealthCheck = time.Now()
	vm.metrics.HealthCheckDuration = duration
	vm.metrics.TotalRequests++

	if err != nil {
		vm.metrics.ConnectionStatus = "unhealthy"
		vm.metrics.FailedRequests++
		vm.metrics.LastError = err.Error()
		vm.metrics.LastErrorTime = time.Now()

		safeLog("error", "Vault health check failed", map[string]interface{}{
			"error":    err.Error(),
			"duration": duration.String(),
		})
		return
	}

	vm.metrics.SuccessfulRequests++

	if health.Sealed {
		vm.metrics.ConnectionStatus = "sealed"
		safeLog("warning", "Vault is sealed", map[string]interface{}{
			"cluster_name": health.ClusterName,
			"version":      health.Version,
		})
	} else if health.Standby {
		vm.metrics.ConnectionStatus = "standby"
		safeLog("info", "Connected to Vault standby node", map[string]interface{}{
			"cluster_name": health.ClusterName,
			"version":      health.Version,
		})
	} else {
		vm.metrics.ConnectionStatus = "healthy"
	}

	// Check token status
	vm.checkTokenStatus()

	// Update average response time
	if vm.metrics.SuccessfulRequests > 0 {
		vm.metrics.AverageResponseTime = time.Duration(
			(int64(vm.metrics.AverageResponseTime) + int64(duration)) / 2,
		)
	} else {
		vm.metrics.AverageResponseTime = duration
	}

	safeLog("debug", "Vault health check completed", map[string]interface{}{
		"status":       vm.metrics.ConnectionStatus,
		"duration":     duration.String(),
		"cluster_name": health.ClusterName,
		"version":      health.Version,
	})
}

// checkTokenStatus verifies the current token status
func (vm *VaultMonitor) checkTokenStatus() {
	tokenInfo, err := vm.client.Auth().Token().LookupSelf()
	if err != nil {
		vm.metrics.LastError = "Token lookup failed: " + err.Error()
		vm.metrics.LastErrorTime = time.Now()
		return
	}

	if tokenInfo != nil && tokenInfo.Data != nil {
		if ttl, ok := tokenInfo.Data["ttl"].(int); ok {
			vm.metrics.TokenTTL = ttl
		}
		if renewable, ok := tokenInfo.Data["renewable"].(bool); ok {
			vm.metrics.TokenRenewable = renewable
		}

		// Warn if token is expiring soon (less than 1 hour)
		if vm.metrics.TokenTTL > 0 && vm.metrics.TokenTTL < 3600 {
			safeLog("warning", "Vault token expiring soon", map[string]interface{}{
				"ttl_seconds": vm.metrics.TokenTTL,
				"renewable":   vm.metrics.TokenRenewable,
			})
		}
	}
}

// GetMetrics returns current Vault metrics
func (vm *VaultMonitor) GetMetrics() *VaultMetrics {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *vm.metrics
	return &metrics
}

// IsHealthy returns true if Vault is healthy
func (vm *VaultMonitor) IsHealthy() bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return vm.metrics.ConnectionStatus == "healthy"
}

// RecordRequest records a request for metrics
func (vm *VaultMonitor) RecordRequest(duration time.Duration, success bool) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.metrics.TotalRequests++
	if success {
		vm.metrics.SuccessfulRequests++
	} else {
		vm.metrics.FailedRequests++
	}

	// Update average response time
	if vm.metrics.SuccessfulRequests > 0 {
		vm.metrics.AverageResponseTime = time.Duration(
			(int64(vm.metrics.AverageResponseTime) + int64(duration)) / 2,
		)
	}
}

// RecordError records an error for metrics
func (vm *VaultMonitor) RecordError(err error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.metrics.LastError = err.Error()
	vm.metrics.LastErrorTime = time.Now()
	vm.metrics.FailedRequests++
}

// Stop stops the health monitoring
func (vm *VaultMonitor) Stop() {
	close(vm.healthCheckDone)
}

// RenewToken attempts to renew the current token if renewable
func (vm *VaultMonitor) RenewToken(increment int) error {
	if !vm.metrics.TokenRenewable {
		return fmt.Errorf("token is not renewable")
	}

	start := time.Now()
	secret, err := vm.client.Auth().Token().RenewSelf(increment)
	duration := time.Since(start)

	vm.RecordRequest(duration, err == nil)

	if err != nil {
		vm.RecordError(err)
		safeLog("error", "Failed to renew Vault token", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if secret != nil && secret.Auth != nil {
		vm.mu.Lock()
		vm.metrics.TokenTTL = secret.Auth.LeaseDuration
		vm.mu.Unlock()

		safeLog("info", "Vault token renewed successfully", map[string]interface{}{
			"new_ttl": secret.Auth.LeaseDuration,
		})
	}

	return nil
}

// GetConnectionStatus returns the current connection status
func (vm *VaultMonitor) GetConnectionStatus() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.metrics.ConnectionStatus
}

// WaitForHealthy waits for Vault to become healthy with timeout
func (vm *VaultMonitor) WaitForHealthy(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Vault to become healthy")
		case <-ticker.C:
			if vm.IsHealthy() {
				return nil
			}
		}
	}
}

// GetHealthSummary returns a human-readable health summary
func (vm *VaultMonitor) GetHealthSummary() map[string]interface{} {
	metrics := vm.GetMetrics()

	successRate := float64(0)
	if metrics.TotalRequests > 0 {
		successRate = float64(metrics.SuccessfulRequests) / float64(metrics.TotalRequests) * 100
	}

	return map[string]interface{}{
		"status":            metrics.ConnectionStatus,
		"last_check":        metrics.LastHealthCheck.Format(time.RFC3339),
		"total_requests":    metrics.TotalRequests,
		"success_rate":      fmt.Sprintf("%.2f%%", successRate),
		"avg_response_time": metrics.AverageResponseTime.String(),
		"token_ttl_seconds": metrics.TokenTTL,
		"token_renewable":   metrics.TokenRenewable,
		"last_error":        metrics.LastError,
		"last_error_time":   metrics.LastErrorTime.Format(time.RFC3339),
	}
}
