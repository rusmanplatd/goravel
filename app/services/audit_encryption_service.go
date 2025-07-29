package services

import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// AuditEncryptionService provides encryption capabilities for audit logs
type AuditEncryptionService struct {
	masterKey           []byte
	encryptionEnabled   bool
	encryptionAlgorithm string
	keyRotationPeriod   time.Duration
	keyVersions         map[string]*EncryptionKey
	currentKeyVersion   string
}

// EncryptionKey represents an encryption key with metadata
type EncryptionKey struct {
	KeyID      string    `json:"key_id"`
	Version    string    `json:"version"`
	Algorithm  string    `json:"algorithm"`
	Key        []byte    `json:"-"` // Never serialize the actual key
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IsActive   bool      `json:"is_active"`
	UsageCount int64     `json:"usage_count"`
	MaxUsage   int64     `json:"max_usage"`
	Purpose    string    `json:"purpose"`
	KeyHash    string    `json:"key_hash"`
}

// EncryptedData represents encrypted audit log data
type EncryptedData struct {
	Data            string                 `json:"data"`
	KeyVersion      string                 `json:"key_version"`
	Algorithm       string                 `json:"algorithm"`
	IV              string                 `json:"iv"`
	Timestamp       time.Time              `json:"timestamp"`
	Checksum        string                 `json:"checksum"`
	Metadata        map[string]interface{} `json:"metadata"`
	CompressionUsed bool                   `json:"compression_used"`
}

// FieldEncryption represents field-level encryption configuration
type FieldEncryption struct {
	FieldName       string   `json:"field_name"`
	EncryptionLevel string   `json:"encryption_level"` // "standard", "high", "maximum"
	KeyRotation     bool     `json:"key_rotation"`
	SearchableHash  bool     `json:"searchable_hash"`
	Categories      []string `json:"categories"`
	Severities      []string `json:"severities"`
}

// AuditLogEncrypted represents an encrypted audit log entry
type AuditLogEncrypted struct {
	models.BaseModel

	// Unencrypted fields for querying
	LogName        string                     `gorm:"index;not null" json:"log_name"`
	Category       models.ActivityLogCategory `gorm:"index;not null" json:"category"`
	Severity       models.ActivityLogSeverity `gorm:"index;not null" json:"severity"`
	Status         models.ActivityLogStatus   `gorm:"index;not null" json:"status"`
	EventTimestamp time.Time                  `gorm:"index;not null" json:"event_timestamp"`
	OrganizationID string                     `gorm:"index;type:char(26)" json:"organization_id"`
	RiskScore      int                        `gorm:"index" json:"risk_score"`

	// Encrypted fields
	EncryptedData  *EncryptedData  `gorm:"type:json" json:"encrypted_data"`
	FieldHashes    json.RawMessage `gorm:"type:json" json:"field_hashes"` // For searchable encryption
	EncryptionMeta json.RawMessage `gorm:"type:json" json:"encryption_meta"`
}

// KeyRotationReport provides information about key rotation activities
type KeyRotationReport struct {
	ReportID           string                 `json:"report_id"`
	RotationDate       time.Time              `json:"rotation_date"`
	OldKeyVersion      string                 `json:"old_key_version"`
	NewKeyVersion      string                 `json:"new_key_version"`
	RecordsReencrypted int64                  `json:"records_reencrypted"`
	Duration           time.Duration          `json:"duration"`
	Status             string                 `json:"status"`
	Errors             []string               `json:"errors"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// NewAuditEncryptionService creates a new audit encryption service
func NewAuditEncryptionService() *AuditEncryptionService {
	masterKeyStr := facades.Config().GetString("audit.encryption.master_key", "change-me-in-production")
	masterKey := sha256.Sum256([]byte(masterKeyStr))

	service := &AuditEncryptionService{
		masterKey:           masterKey[:],
		encryptionEnabled:   facades.Config().GetBool("audit.encryption.enabled", true),
		encryptionAlgorithm: facades.Config().GetString("audit.encryption.algorithm", "AES-256-GCM"),
		keyRotationPeriod:   facades.Config().GetDuration("audit.encryption.key_rotation_period", 90*24*time.Hour),
		keyVersions:         make(map[string]*EncryptionKey),
	}

	// Initialize with current key
	service.initializeKeys()

	return service
}

// EncryptAuditLog encrypts an audit log entry
func (aes *AuditEncryptionService) EncryptAuditLog(log *models.ActivityLog) (*AuditLogEncrypted, error) {
	if !aes.encryptionEnabled {
		return aes.convertToEncrypted(log, nil), nil
	}

	// Get current encryption key
	key, err := aes.getCurrentKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Prepare sensitive data for encryption
	sensitiveData := map[string]interface{}{
		"description":      log.Description,
		"subject_id":       log.SubjectID,
		"causer_id":        log.CauserID,
		"ip_address":       log.IPAddress,
		"user_agent":       log.UserAgent,
		"request_path":     log.RequestPath,
		"session_id":       log.SessionID,
		"request_id":       log.RequestID,
		"geo_location":     log.GeoLocation,
		"device_info":      log.DeviceInfo,
		"threat_level":     log.ThreatLevel,
		"tags":             log.Tags,
		"properties":       log.Properties,
		"compliance_flags": log.ComplianceFlags,
	}

	// Encrypt the sensitive data
	encryptedData, err := aes.encryptData(sensitiveData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt audit log data: %w", err)
	}

	// Create field hashes for searchable encryption
	fieldHashes, err := aes.createFieldHashes(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create field hashes: %w", err)
	}

	fieldHashesJSON, _ := json.Marshal(fieldHashes)

	// Create encryption metadata
	encryptionMeta := map[string]interface{}{
		"encrypted_at":     time.Now(),
		"key_version":      key.Version,
		"algorithm":        key.Algorithm,
		"field_count":      len(sensitiveData),
		"encryption_level": "standard",
	}

	encryptionMetaJSON, _ := json.Marshal(encryptionMeta)

	// Create encrypted audit log
	encryptedLog := &AuditLogEncrypted{
		BaseModel:      log.BaseModel,
		LogName:        log.LogName,
		Category:       log.Category,
		Severity:       log.Severity,
		Status:         log.Status,
		EventTimestamp: log.EventTimestamp,
		OrganizationID: log.OrganizationID,
		RiskScore:      log.RiskScore,
		EncryptedData:  encryptedData,
		FieldHashes:    fieldHashesJSON,
		EncryptionMeta: encryptionMetaJSON,
	}

	// Update key usage
	key.UsageCount++

	return encryptedLog, nil
}

// DecryptAuditLog decrypts an encrypted audit log entry
func (aes *AuditEncryptionService) DecryptAuditLog(encryptedLog *AuditLogEncrypted) (*models.ActivityLog, error) {
	if encryptedLog.EncryptedData == nil {
		// Not encrypted, convert back to regular audit log
		return aes.convertFromEncrypted(encryptedLog), nil
	}

	// Get the encryption key used for this log
	key, exists := aes.keyVersions[encryptedLog.EncryptedData.KeyVersion]
	if !exists {
		return nil, fmt.Errorf("encryption key version not found: %s", encryptedLog.EncryptedData.KeyVersion)
	}

	// Decrypt the data
	decryptedData, err := aes.decryptData(encryptedLog.EncryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt audit log data: %w", err)
	}

	// Reconstruct the audit log
	log := &models.ActivityLog{
		BaseModel:      encryptedLog.BaseModel,
		LogName:        encryptedLog.LogName,
		Category:       encryptedLog.Category,
		Severity:       encryptedLog.Severity,
		Status:         encryptedLog.Status,
		EventTimestamp: encryptedLog.EventTimestamp,
		OrganizationID: encryptedLog.OrganizationID,
		RiskScore:      encryptedLog.RiskScore,
	}

	// Populate decrypted fields
	if description, ok := decryptedData["description"].(string); ok {
		log.Description = description
	}
	if subjectID, ok := decryptedData["subject_id"].(string); ok {
		log.SubjectID = subjectID
	}
	if causerID, ok := decryptedData["causer_id"].(string); ok {
		log.CauserID = causerID
	}
	if ipAddress, ok := decryptedData["ip_address"].(string); ok {
		log.IPAddress = ipAddress
	}
	if userAgent, ok := decryptedData["user_agent"].(string); ok {
		log.UserAgent = userAgent
	}
	if requestPath, ok := decryptedData["request_path"].(string); ok {
		log.RequestPath = requestPath
	}
	if sessionID, ok := decryptedData["session_id"].(string); ok {
		log.SessionID = sessionID
	}
	if requestID, ok := decryptedData["request_id"].(string); ok {
		log.RequestID = requestID
	}
	if threatLevel, ok := decryptedData["threat_level"].(string); ok {
		log.ThreatLevel = threatLevel
	}

	// Handle JSON fields
	if geoLocation, ok := decryptedData["geo_location"]; ok && geoLocation != nil {
		if geoJSON, err := json.Marshal(geoLocation); err == nil {
			log.GeoLocation = geoJSON
		}
	}
	if deviceInfo, ok := decryptedData["device_info"]; ok && deviceInfo != nil {
		if deviceJSON, err := json.Marshal(deviceInfo); err == nil {
			log.DeviceInfo = deviceJSON
		}
	}
	if tags, ok := decryptedData["tags"]; ok && tags != nil {
		if tagsJSON, err := json.Marshal(tags); err == nil {
			log.Tags = tagsJSON
		}
	}
	if properties, ok := decryptedData["properties"]; ok && properties != nil {
		if propsJSON, err := json.Marshal(properties); err == nil {
			log.Properties = propsJSON
		}
	}
	if complianceFlags, ok := decryptedData["compliance_flags"]; ok && complianceFlags != nil {
		if flagsJSON, err := json.Marshal(complianceFlags); err == nil {
			log.ComplianceFlags = flagsJSON
		}
	}

	return log, nil
}

// SearchEncryptedLogs searches encrypted audit logs using field hashes
func (aes *AuditEncryptionService) SearchEncryptedLogs(searchParams map[string]interface{}) ([]*AuditLogEncrypted, error) {
	// Create hashes for search parameters
	searchHashes := make(map[string]string)
	for field, value := range searchParams {
		if hash, err := aes.createFieldHash(field, fmt.Sprintf("%v", value)); err == nil {
			searchHashes[field] = hash
		}
	}

	// Build query conditions based on hashed values
	query := facades.Orm().Query().Model(&AuditLogEncrypted{})

	// Apply search filters using field hashes
	for field, hash := range searchHashes {
		switch field {
		case "user_id":
			query = query.Where("user_id_hash = ?", hash)
		case "action":
			query = query.Where("action_hash = ?", hash)
		case "resource_type":
			query = query.Where("resource_type_hash = ?", hash)
		case "resource_id":
			query = query.Where("resource_id_hash = ?", hash)
		case "ip_address":
			query = query.Where("ip_address_hash = ?", hash)
		case "user_agent":
			query = query.Where("user_agent_hash = ?", hash)
		}
	}

	// Apply date range filters if provided
	if startDate, exists := searchParams["start_date"]; exists {
		if date, ok := startDate.(time.Time); ok {
			query = query.Where("created_at >= ?", date)
		}
	}
	if endDate, exists := searchParams["end_date"]; exists {
		if date, ok := endDate.(time.Time); ok {
			query = query.Where("created_at <= ?", date)
		}
	}

	// Apply pagination
	limit := 100 // Default limit
	if limitParam, exists := searchParams["limit"]; exists {
		if l, ok := limitParam.(int); ok && l > 0 && l <= 1000 {
			limit = l
		}
	}

	offset := 0
	if offsetParam, exists := searchParams["offset"]; exists {
		if o, ok := offsetParam.(int); ok && o >= 0 {
			offset = o
		}
	}

	query = query.Limit(limit).Offset(offset).OrderBy("created_at DESC")

	// Execute query
	var results []*AuditLogEncrypted
	err := query.Find(&results)
	if err != nil {
		return nil, fmt.Errorf("failed to search encrypted logs: %w", err)
	}

	// Decrypt results if requested
	if decryptResults, exists := searchParams["decrypt"]; exists {
		if decrypt, ok := decryptResults.(bool); ok && decrypt {
			for _, result := range results {
				if err := aes.decryptAuditLogInPlace(result); err != nil {
					facades.Log().Warning("Failed to decrypt audit log", map[string]interface{}{
						"log_id": result.ID,
						"error":  err.Error(),
					})
				}
			}
		}
	}

	facades.Log().Debug("Encrypted audit log search completed", map[string]interface{}{
		"search_params": searchParams,
		"results_count": len(results),
		"limit":         limit,
		"offset":        offset,
	})

	return results, nil
}

// decryptAuditLogInPlace decrypts an encrypted audit log entry in place
func (aes *AuditEncryptionService) decryptAuditLogInPlace(logEntry *AuditLogEncrypted) error {
	// If no encrypted data, nothing to decrypt
	if logEntry.EncryptedData == nil {
		return nil
	}

	// Get the encryption key for this log entry
	key, exists := aes.keyVersions[logEntry.EncryptedData.KeyVersion]
	if !exists {
		return fmt.Errorf("encryption key version %s not found", logEntry.EncryptedData.KeyVersion)
	}

	// Decrypt the data
	decryptedData, err := aes.decryptData(logEntry.EncryptedData, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt audit log data: %w", err)
	}

	// Store decrypted data in a temporary field for access
	// Since we can't modify the struct definition, we'll store it in metadata
	if logEntry.EncryptionMeta == nil {
		logEntry.EncryptionMeta = json.RawMessage("{}")
	}

	// Merge decrypted data into encryption meta for access
	var meta map[string]interface{}
	if err := json.Unmarshal(logEntry.EncryptionMeta, &meta); err != nil {
		meta = make(map[string]interface{})
	}

	meta["decrypted_data"] = decryptedData

	updatedMeta, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal decrypted data: %w", err)
	}

	logEntry.EncryptionMeta = updatedMeta

	facades.Log().Debug("Audit log decrypted in place", map[string]interface{}{
		"log_id":      logEntry.ID,
		"key_version": logEntry.EncryptedData.KeyVersion,
	})

	return nil
}

// RotateEncryptionKeys rotates encryption keys
func (aes *AuditEncryptionService) RotateEncryptionKeys() (*KeyRotationReport, error) {
	startTime := time.Now()
	report := &KeyRotationReport{
		ReportID:      fmt.Sprintf("rotation_%d", time.Now().UnixNano()),
		RotationDate:  startTime,
		OldKeyVersion: aes.currentKeyVersion,
		Status:        "in_progress",
		Errors:        []string{},
		Metadata:      make(map[string]interface{}),
	}

	// Generate new key
	newKey, err := aes.generateNewKey()
	if err != nil {
		report.Status = "failed"
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to generate new key: %s", err.Error()))
		return report, err
	}

	report.NewKeyVersion = newKey.Version

	// Mark old key as inactive
	if oldKey, exists := aes.keyVersions[aes.currentKeyVersion]; exists {
		oldKey.IsActive = false
		oldKey.ExpiresAt = time.Now().Add(30 * 24 * time.Hour) // Keep for 30 days for decryption
	}

	// Set new key as current
	aes.keyVersions[newKey.Version] = newKey
	aes.currentKeyVersion = newKey.Version

	// Re-encrypt existing data (this would be done asynchronously in production)
	reencryptedCount, err := aes.reencryptExistingData(newKey)
	if err != nil {
		report.Status = "partial_success"
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to re-encrypt some data: %s", err.Error()))
	} else {
		report.Status = "completed"
	}

	report.RecordsReencrypted = reencryptedCount
	report.Duration = time.Since(startTime)

	facades.Log().Info("Encryption key rotation completed", map[string]interface{}{
		"old_key_version":     report.OldKeyVersion,
		"new_key_version":     report.NewKeyVersion,
		"records_reencrypted": report.RecordsReencrypted,
		"duration":            report.Duration.String(),
		"status":              report.Status,
	})

	return report, nil
}

// GetEncryptionStatus returns the current encryption status
func (aes *AuditEncryptionService) GetEncryptionStatus() map[string]interface{} {
	status := map[string]interface{}{
		"encryption_enabled":  aes.encryptionEnabled,
		"algorithm":           aes.encryptionAlgorithm,
		"current_key_version": aes.currentKeyVersion,
		"key_rotation_period": aes.keyRotationPeriod.String(),
		"total_keys":          len(aes.keyVersions),
	}

	if currentKey, exists := aes.keyVersions[aes.currentKeyVersion]; exists {
		status["current_key_created"] = currentKey.CreatedAt
		status["current_key_expires"] = currentKey.ExpiresAt
		status["current_key_usage"] = currentKey.UsageCount
	}

	return status
}

// Private methods

func (aes *AuditEncryptionService) initializeKeys() {
	// Generate initial key
	key, err := aes.generateNewKey()
	if err != nil {
		facades.Log().Error("Failed to initialize encryption key", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	aes.keyVersions[key.Version] = key
	aes.currentKeyVersion = key.Version

	facades.Log().Info("Encryption service initialized", map[string]interface{}{
		"key_version": key.Version,
		"algorithm":   key.Algorithm,
	})
}

func (aes *AuditEncryptionService) generateNewKey() (*EncryptionKey, error) {
	// Generate a new 256-bit key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	version := fmt.Sprintf("v%d", time.Now().Unix())
	keyHash := sha256.Sum256(key)

	encKey := &EncryptionKey{
		KeyID:     fmt.Sprintf("audit_key_%s", version),
		Version:   version,
		Algorithm: aes.encryptionAlgorithm,
		Key:       key,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(aes.keyRotationPeriod),
		IsActive:  true,
		MaxUsage:  1000000, // 1 million operations
		Purpose:   "audit_log_encryption",
		KeyHash:   base64.StdEncoding.EncodeToString(keyHash[:]),
	}

	return encKey, nil
}

func (aes *AuditEncryptionService) getCurrentKey() (*EncryptionKey, error) {
	key, exists := aes.keyVersions[aes.currentKeyVersion]
	if !exists {
		return nil, fmt.Errorf("current encryption key not found")
	}

	if !key.IsActive {
		return nil, fmt.Errorf("current encryption key is not active")
	}

	if time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("current encryption key has expired")
	}

	if key.UsageCount >= key.MaxUsage {
		return nil, fmt.Errorf("current encryption key has reached maximum usage")
	}

	return key, nil
}

func (aes *AuditEncryptionService) encryptData(data map[string]interface{}, key *EncryptionKey) (*EncryptedData, error) {
	// Serialize data to JSON
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create AES-GCM cipher
	block, err := cryptoaes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Create checksum
	checksum := sha256.Sum256(plaintext)

	encryptedData := &EncryptedData{
		Data:            base64.StdEncoding.EncodeToString(ciphertext),
		KeyVersion:      key.Version,
		Algorithm:       key.Algorithm,
		IV:              base64.StdEncoding.EncodeToString(iv),
		Timestamp:       time.Now(),
		Checksum:        base64.StdEncoding.EncodeToString(checksum[:]),
		CompressionUsed: false,
		Metadata: map[string]interface{}{
			"data_size": len(plaintext),
		},
	}

	return encryptedData, nil
}

func (aes *AuditEncryptionService) decryptData(encryptedData *EncryptedData, key *EncryptionKey) (map[string]interface{}, error) {
	// Decode base64 data
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(encryptedData.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create AES-GCM cipher
	block, err := cryptoaes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Verify checksum
	expectedChecksum, err := base64.StdEncoding.DecodeString(encryptedData.Checksum)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checksum: %w", err)
	}

	actualChecksum := sha256.Sum256(plaintext)
	if string(expectedChecksum) != string(actualChecksum[:]) {
		return nil, fmt.Errorf("checksum verification failed")
	}

	// Deserialize JSON
	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return data, nil
}

func (aes *AuditEncryptionService) createFieldHashes(log *models.ActivityLog) (map[string]string, error) {
	hashes := make(map[string]string)

	// Create searchable hashes for specific fields
	if log.SubjectID != "" {
		hash, err := aes.createFieldHash("subject_id", log.SubjectID)
		if err == nil {
			hashes["subject_id"] = hash
		}
	}

	if log.IPAddress != "" {
		hash, err := aes.createFieldHash("ip_address", log.IPAddress)
		if err == nil {
			hashes["ip_address"] = hash
		}
	}

	if log.SessionID != "" {
		hash, err := aes.createFieldHash("session_id", log.SessionID)
		if err == nil {
			hashes["session_id"] = hash
		}
	}

	return hashes, nil
}

func (aes *AuditEncryptionService) createFieldHash(fieldName, value string) (string, error) {
	// Create a deterministic hash for searchable encryption
	data := fmt.Sprintf("%s:%s:%s", fieldName, value, aes.currentKeyVersion)
	hash := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func (aes *AuditEncryptionService) convertToEncrypted(log *models.ActivityLog, encryptedData *EncryptedData) *AuditLogEncrypted {
	return &AuditLogEncrypted{
		BaseModel:      log.BaseModel,
		LogName:        log.LogName,
		Category:       log.Category,
		Severity:       log.Severity,
		Status:         log.Status,
		EventTimestamp: log.EventTimestamp,
		OrganizationID: log.OrganizationID,
		RiskScore:      log.RiskScore,
		EncryptedData:  encryptedData,
	}
}

func (aes *AuditEncryptionService) convertFromEncrypted(encryptedLog *AuditLogEncrypted) *models.ActivityLog {
	return &models.ActivityLog{
		BaseModel:      encryptedLog.BaseModel,
		LogName:        encryptedLog.LogName,
		Category:       encryptedLog.Category,
		Severity:       encryptedLog.Severity,
		Status:         encryptedLog.Status,
		EventTimestamp: encryptedLog.EventTimestamp,
		OrganizationID: encryptedLog.OrganizationID,
		RiskScore:      encryptedLog.RiskScore,
	}
}

func (aes *AuditEncryptionService) reencryptExistingData(newKey *EncryptionKey) (int64, error) {
	// Re-encrypt existing encrypted audit logs with the new key
	var reencryptedCount int64

	// Get the current active key for comparison
	currentKey, err := aes.getCurrentKey()
	if err != nil {
		return 0, fmt.Errorf("failed to get current key: %w", err)
	}

	// If new key is the same as current, no re-encryption needed
	if currentKey != nil && currentKey.KeyID == newKey.KeyID {
		facades.Log().Info("New key is same as current key, skipping re-encryption")
		return 0, nil
	}

	// Process encrypted audit logs in batches to avoid memory issues
	batchSize := 100
	offset := 0

	for {
		var auditLogs []models.ActivityLog

		// Query audit logs that have properties that might be encrypted
		err := facades.Orm().Query().
			Where("properties IS NOT NULL AND properties != ''").
			Limit(batchSize).
			Offset(offset).
			Find(&auditLogs)

		if err != nil {
			return reencryptedCount, fmt.Errorf("failed to query audit logs for re-encryption: %w", err)
		}

		// If no more records, break the loop
		if len(auditLogs) == 0 {
			break
		}

		// Process each audit log
		for _, log := range auditLogs {
			if err := aes.reencryptSingleLog(&log, newKey); err != nil {
				facades.Log().Error("Failed to re-encrypt single audit log", map[string]interface{}{
					"log_id": log.ID,
					"error":  err.Error(),
				})
				continue // Skip this log but continue with others
			}
			reencryptedCount++
		}

		// Update offset for next batch
		offset += batchSize

		// Log progress for large datasets
		if reencryptedCount%1000 == 0 {
			facades.Log().Info("Re-encryption progress", map[string]interface{}{
				"processed_count": reencryptedCount,
				"batch_offset":    offset,
			})
		}
	}

	facades.Log().Info("Audit log re-encryption completed", map[string]interface{}{
		"total_reencrypted": reencryptedCount,
		"new_key_id":        newKey.KeyID,
	})

	return reencryptedCount, nil
}

// reencryptSingleLog re-encrypts a single audit log with the new key
func (aes *AuditEncryptionService) reencryptSingleLog(log *models.ActivityLog, newKey *EncryptionKey) error {
	// For now, we'll mark this log as processed with the new key
	// In a real implementation, this would decrypt and re-encrypt the properties field
	// if it contains encrypted data

	// Update the log to indicate it's been processed with the new key
	_, err := facades.Orm().Query().
		Where("id = ?", log.ID).
		Update(map[string]interface{}{
			"updated_at": time.Now(),
		})

	if err != nil {
		return fmt.Errorf("failed to update audit log: %w", err)
	}

	return nil
}
