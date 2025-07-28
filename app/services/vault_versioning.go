package services

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/vault/api"
)

// VaultVersioning provides key versioning capabilities
type VaultVersioning struct {
	client     *api.Client
	secretPath string
	monitor    *VaultMonitor
}

// KeyVersion represents a versioned key
type KeyVersion struct {
	Version     int       `json:"version"`
	Key         []byte    `json:"-"` // Never serialize the actual key
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	Description string    `json:"description,omitempty"`
	Active      bool      `json:"active"`
	KeyHash     string    `json:"key_hash"` // SHA256 hash for verification
}

// KeyVersionHistory contains version history for a key
type KeyVersionHistory struct {
	KeyID          string        `json:"key_id"`
	CurrentVersion int           `json:"current_version"`
	TotalVersions  int           `json:"total_versions"`
	Versions       []*KeyVersion `json:"versions"`
	LastRotation   time.Time     `json:"last_rotation"`
	RotationPolicy string        `json:"rotation_policy,omitempty"`
}

// NewVaultVersioning creates a new versioning service
func NewVaultVersioning(client *api.Client, secretPath string, monitor *VaultMonitor) *VaultVersioning {
	return &VaultVersioning{
		client:     client,
		secretPath: secretPath,
		monitor:    monitor,
	}
}

// CreateKeyVersion creates a new version of a key
func (vv *VaultVersioning) CreateKeyVersion(keyID string, key []byte, description, createdBy string) (*KeyVersion, error) {
	start := time.Now()

	// Get current version history
	history, err := vv.GetKeyHistory(keyID)
	if err != nil && err.Error() != "key history not found" {
		return nil, fmt.Errorf("failed to get key history: %v", err)
	}

	// Determine next version number
	nextVersion := 1
	if history != nil && len(history.Versions) > 0 {
		nextVersion = history.CurrentVersion + 1
	}

	// Create new version
	version := &KeyVersion{
		Version:     nextVersion,
		Key:         key,
		CreatedAt:   time.Now(),
		CreatedBy:   createdBy,
		Description: description,
		Active:      true,
		KeyHash:     vv.calculateKeyHash(key),
	}

	// Deactivate previous versions
	if history != nil {
		for _, v := range history.Versions {
			v.Active = false
		}
		history.Versions = append(history.Versions, version)
	} else {
		history = &KeyVersionHistory{
			KeyID:          keyID,
			CurrentVersion: nextVersion,
			Versions:       []*KeyVersion{version},
			LastRotation:   time.Now(),
		}
	}

	// Update totals
	history.CurrentVersion = nextVersion
	history.TotalVersions = len(history.Versions)
	history.LastRotation = time.Now()

	// Store in Vault
	err = vv.storeKeyHistory(keyID, history)
	duration := time.Since(start)

	// Record metrics
	if vv.monitor != nil {
		vv.monitor.RecordRequest(duration, err == nil)
		if err != nil {
			vv.monitor.RecordError(err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to store key version: %v", err)
	}

	safeLog("info", "Created new key version", map[string]interface{}{
		"key_id":      keyID,
		"version":     nextVersion,
		"created_by":  createdBy,
		"description": description,
		"duration":    duration.String(),
	})

	return version, nil
}

// GetKeyVersion retrieves a specific version of a key
func (vv *VaultVersioning) GetKeyVersion(keyID string, version int) (*KeyVersion, error) {
	start := time.Now()

	history, err := vv.GetKeyHistory(keyID)
	duration := time.Since(start)

	// Record metrics
	if vv.monitor != nil {
		vv.monitor.RecordRequest(duration, err == nil)
		if err != nil {
			vv.monitor.RecordError(err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get key history: %v", err)
	}

	// Find the requested version
	for _, v := range history.Versions {
		if v.Version == version {
			safeLog("debug", "Retrieved key version", map[string]interface{}{
				"key_id":   keyID,
				"version":  version,
				"duration": duration.String(),
			})
			return v, nil
		}
	}

	return nil, fmt.Errorf("key version %d not found for key %s", version, keyID)
}

// GetCurrentKeyVersion retrieves the current active version of a key
func (vv *VaultVersioning) GetCurrentKeyVersion(keyID string) (*KeyVersion, error) {
	start := time.Now()

	history, err := vv.GetKeyHistory(keyID)
	duration := time.Since(start)

	// Record metrics
	if vv.monitor != nil {
		vv.monitor.RecordRequest(duration, err == nil)
		if err != nil {
			vv.monitor.RecordError(err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get key history: %v", err)
	}

	// Find the current active version
	for _, v := range history.Versions {
		if v.Active {
			safeLog("debug", "Retrieved current key version", map[string]interface{}{
				"key_id":   keyID,
				"version":  v.Version,
				"duration": duration.String(),
			})
			return v, nil
		}
	}

	return nil, fmt.Errorf("no active version found for key %s", keyID)
}

// GetKeyHistory retrieves the complete version history for a key
func (vv *VaultVersioning) GetKeyHistory(keyID string) (*KeyVersionHistory, error) {
	versionPath := fmt.Sprintf("%s/versions/%s", vv.secretPath, keyID)

	secret, err := vv.client.Logical().Read(versionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key history from Vault: %v", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("key history not found")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid key history format")
	}

	// Parse the history
	history := &KeyVersionHistory{
		KeyID: keyID,
	}

	if currentVersion, ok := data["current_version"].(float64); ok {
		history.CurrentVersion = int(currentVersion)
	}

	if totalVersions, ok := data["total_versions"].(float64); ok {
		history.TotalVersions = int(totalVersions)
	}

	if lastRotation, ok := data["last_rotation"].(string); ok {
		if t, err := time.Parse(time.RFC3339, lastRotation); err == nil {
			history.LastRotation = t
		}
	}

	if rotationPolicy, ok := data["rotation_policy"].(string); ok {
		history.RotationPolicy = rotationPolicy
	}

	// Parse versions
	if versionsData, ok := data["versions"].([]interface{}); ok {
		for _, versionData := range versionsData {
			if versionMap, ok := versionData.(map[string]interface{}); ok {
				version := &KeyVersion{}

				if v, ok := versionMap["version"].(float64); ok {
					version.Version = int(v)
				}

				if keyData, ok := versionMap["key_data"].(string); ok {
					if decodedKey, err := base64.StdEncoding.DecodeString(keyData); err == nil {
						version.Key = decodedKey
					}
				}

				if createdAt, ok := versionMap["created_at"].(string); ok {
					if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
						version.CreatedAt = t
					}
				}

				if createdBy, ok := versionMap["created_by"].(string); ok {
					version.CreatedBy = createdBy
				}

				if description, ok := versionMap["description"].(string); ok {
					version.Description = description
				}

				if active, ok := versionMap["active"].(bool); ok {
					version.Active = active
				}

				if keyHash, ok := versionMap["key_hash"].(string); ok {
					version.KeyHash = keyHash
				}

				history.Versions = append(history.Versions, version)
			}
		}
	}

	// Sort versions by version number
	sort.Slice(history.Versions, func(i, j int) bool {
		return history.Versions[i].Version < history.Versions[j].Version
	})

	return history, nil
}

// RollbackToVersion rolls back to a specific version of a key
func (vv *VaultVersioning) RollbackToVersion(keyID string, targetVersion int, rollbackBy string) error {
	start := time.Now()

	history, err := vv.GetKeyHistory(keyID)
	if err != nil {
		return fmt.Errorf("failed to get key history: %v", err)
	}

	// Find the target version
	var targetVersionObj *KeyVersion
	for _, v := range history.Versions {
		if v.Version == targetVersion {
			targetVersionObj = v
			break
		}
	}

	if targetVersionObj == nil {
		return fmt.Errorf("version %d not found for key %s", targetVersion, keyID)
	}

	// Deactivate all versions and activate the target
	for _, v := range history.Versions {
		v.Active = (v.Version == targetVersion)
	}

	// Update history
	history.CurrentVersion = targetVersion
	history.LastRotation = time.Now()

	// Store updated history
	err = vv.storeKeyHistory(keyID, history)
	duration := time.Since(start)

	// Record metrics
	if vv.monitor != nil {
		vv.monitor.RecordRequest(duration, err == nil)
		if err != nil {
			vv.monitor.RecordError(err)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to rollback key version: %v", err)
	}

	safeLog("info", "Rolled back key to previous version", map[string]interface{}{
		"key_id":         keyID,
		"target_version": targetVersion,
		"rollback_by":    rollbackBy,
		"duration":       duration.String(),
	})

	return nil
}

// DeleteKeyVersion marks a specific version as deleted (soft delete)
func (vv *VaultVersioning) DeleteKeyVersion(keyID string, version int, deletedBy string) error {
	start := time.Now()

	history, err := vv.GetKeyHistory(keyID)
	if err != nil {
		return fmt.Errorf("failed to get key history: %v", err)
	}

	// Cannot delete the current active version
	if history.CurrentVersion == version {
		return fmt.Errorf("cannot delete active version %d", version)
	}

	// Find and mark the version as deleted
	versionFound := false
	for _, v := range history.Versions {
		if v.Version == version {
			// Clear the key data but keep metadata
			v.Key = nil
			v.Description = fmt.Sprintf("[DELETED by %s] %s", deletedBy, v.Description)
			versionFound = true
			break
		}
	}

	if !versionFound {
		return fmt.Errorf("version %d not found for key %s", version, keyID)
	}

	// Store updated history
	err = vv.storeKeyHistory(keyID, history)
	duration := time.Since(start)

	// Record metrics
	if vv.monitor != nil {
		vv.monitor.RecordRequest(duration, err == nil)
		if err != nil {
			vv.monitor.RecordError(err)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to delete key version: %v", err)
	}

	safeLog("info", "Deleted key version", map[string]interface{}{
		"key_id":     keyID,
		"version":    version,
		"deleted_by": deletedBy,
		"duration":   duration.String(),
	})

	return nil
}

// ListKeyVersions returns a summary of all versions for a key
func (vv *VaultVersioning) ListKeyVersions(keyID string) ([]*KeyVersion, error) {
	history, err := vv.GetKeyHistory(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key history: %v", err)
	}

	// Return copies without the actual key data for security
	versions := make([]*KeyVersion, len(history.Versions))
	for i, v := range history.Versions {
		versions[i] = &KeyVersion{
			Version:     v.Version,
			Key:         nil, // Never expose key data in listings
			CreatedAt:   v.CreatedAt,
			CreatedBy:   v.CreatedBy,
			Description: v.Description,
			Active:      v.Active,
			KeyHash:     v.KeyHash,
		}
	}

	return versions, nil
}

// storeKeyHistory stores the key version history in Vault
func (vv *VaultVersioning) storeKeyHistory(keyID string, history *KeyVersionHistory) error {
	versionPath := fmt.Sprintf("%s/versions/%s", vv.secretPath, keyID)

	// Prepare versions for storage
	versionsData := make([]map[string]interface{}, len(history.Versions))
	for i, v := range history.Versions {
		versionData := map[string]interface{}{
			"version":     v.Version,
			"created_at":  v.CreatedAt.Format(time.RFC3339),
			"created_by":  v.CreatedBy,
			"description": v.Description,
			"active":      v.Active,
			"key_hash":    v.KeyHash,
		}

		// Only store key data if it exists (not deleted)
		if v.Key != nil {
			versionData["key_data"] = base64.StdEncoding.EncodeToString(v.Key)
		}

		versionsData[i] = versionData
	}

	// Prepare data for Vault storage
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"current_version": history.CurrentVersion,
			"total_versions":  history.TotalVersions,
			"last_rotation":   history.LastRotation.Format(time.RFC3339),
			"rotation_policy": history.RotationPolicy,
			"versions":        versionsData,
		},
	}

	// Store in Vault
	_, err := vv.client.Logical().Write(versionPath, data)
	if err != nil {
		return fmt.Errorf("failed to write key history to Vault: %v", err)
	}

	return nil
}

// calculateKeyHash creates a SHA256 hash of the key for verification
func (vv *VaultVersioning) calculateKeyHash(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// GetVersioningStats returns statistics about key versioning
func (vv *VaultVersioning) GetVersioningStats() (map[string]interface{}, error) {
	// This would typically scan all keys to gather statistics
	// For now, return basic information
	return map[string]interface{}{
		"versioning_enabled": true,
		"supported_operations": []string{
			"create_version",
			"get_version",
			"rollback",
			"delete_version",
			"list_versions",
		},
		"features": []string{
			"soft_delete",
			"rollback_support",
			"audit_trail",
			"key_hash_verification",
		},
	}, nil
}
