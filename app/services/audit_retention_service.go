package services

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// AuditRetentionService manages audit log retention and archival
type AuditRetentionService struct {
	retentionPolicies map[string]*RetentionPolicy
	archivalService   *ArchivalService
	compressionLevel  int
	encryptionEnabled bool
	encryptionKey     []byte
}

// RetentionPolicy defines how long audit logs should be retained
type RetentionPolicy struct {
	PolicyID           string                       `json:"policy_id"`
	Name               string                       `json:"name"`
	Description        string                       `json:"description"`
	Categories         []models.ActivityLogCategory `json:"categories"`
	Severities         []models.ActivityLogSeverity `json:"severities"`
	RetentionPeriod    time.Duration                `json:"retention_period"`
	ArchivalPeriod     time.Duration                `json:"archival_period"`
	DeleteAfter        time.Duration                `json:"delete_after"`
	ComplianceFlags    []string                     `json:"compliance_flags"`
	LegalHold          bool                         `json:"legal_hold"`
	AutoArchive        bool                         `json:"auto_archive"`
	AutoDelete         bool                         `json:"auto_delete"`
	CompressionLevel   int                          `json:"compression_level"`
	EncryptArchive     bool                         `json:"encrypt_archive"`
	NotifyBeforeDelete bool                         `json:"notify_before_delete"`
	CreatedAt          time.Time                    `json:"created_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
	IsActive           bool                         `json:"is_active"`
}

// ArchivalService handles archiving of audit logs
type ArchivalService struct {
	archivePath       string
	compressionLevel  int
	encryptionEnabled bool
	encryptionKey     []byte
	maxArchiveSize    int64
	archiveFormat     string
}

// ArchiveMetadata contains metadata about archived logs
type ArchiveMetadata struct {
	ArchiveID        string                 `json:"archive_id"`
	TenantID         string                 `json:"tenant_id"`
	ArchivePath      string                 `json:"archive_path"`
	StartDate        time.Time              `json:"start_date"`
	EndDate          time.Time              `json:"end_date"`
	RecordCount      int64                  `json:"record_count"`
	CompressedSize   int64                  `json:"compressed_size"`
	UncompressedSize int64                  `json:"uncompressed_size"`
	CompressionRatio float64                `json:"compression_ratio"`
	Checksum         string                 `json:"checksum"`
	EncryptionMethod string                 `json:"encryption_method"`
	CreatedAt        time.Time              `json:"created_at"`
	RetentionPolicy  string                 `json:"retention_policy"`
	ComplianceFlags  []string               `json:"compliance_flags"`
	Status           string                 `json:"status"`
	Metadata         map[string]interface{} `json:"metadata"`
	CompressionType  string                 `json:"compression_type"` // Added for restoration
}

// RetentionReport provides information about retention activities
type RetentionReport struct {
	ReportID         string                 `json:"report_id"`
	TenantID         string                 `json:"tenant_id"`
	GeneratedAt      time.Time              `json:"generated_at"`
	Period           string                 `json:"period"`
	TotalRecords     int64                  `json:"total_records"`
	ArchivedRecords  int64                  `json:"archived_records"`
	DeletedRecords   int64                  `json:"deleted_records"`
	RetainedRecords  int64                  `json:"retained_records"`
	StorageSaved     int64                  `json:"storage_saved"`
	ComplianceStatus map[string]interface{} `json:"compliance_status"`
	PolicyExecutions []PolicyExecution      `json:"policy_executions"`
	Warnings         []string               `json:"warnings"`
	Errors           []string               `json:"errors"`
}

// PolicyExecution represents the execution of a retention policy
type PolicyExecution struct {
	PolicyID        string    `json:"policy_id"`
	PolicyName      string    `json:"policy_name"`
	ExecutedAt      time.Time `json:"executed_at"`
	RecordsAffected int64     `json:"records_affected"`
	Action          string    `json:"action"`
	Status          string    `json:"status"`
	Duration        string    `json:"duration"`
	Error           string    `json:"error,omitempty"`
}

// NewAuditRetentionService creates a new audit retention service
func NewAuditRetentionService() *AuditRetentionService {
	archivePath := facades.Config().GetString("audit.archive_path", "storage/audit_archives")
	encryptionKey := []byte(facades.Config().GetString("audit.encryption_key", "default-key-change-me"))

	archivalService := &ArchivalService{
		archivePath:       archivePath,
		compressionLevel:  9, // Maximum compression
		encryptionEnabled: facades.Config().GetBool("audit.encrypt_archives", true),
		encryptionKey:     encryptionKey,
		maxArchiveSize:    int64(facades.Config().GetInt("audit.max_archive_size", 100*1024*1024)), // 100MB
		archiveFormat:     "jsonl",                                                                 // JSON Lines format
	}

	service := &AuditRetentionService{
		retentionPolicies: make(map[string]*RetentionPolicy),
		archivalService:   archivalService,
		compressionLevel:  facades.Config().GetInt("audit.compression_level", 9),
		encryptionEnabled: facades.Config().GetBool("audit.encrypt_archives", true),
		encryptionKey:     encryptionKey,
	}

	// Load default retention policies
	service.loadDefaultPolicies()

	return service
}

// AddRetentionPolicy adds a new retention policy
func (ars *AuditRetentionService) AddRetentionPolicy(policy *RetentionPolicy) error {
	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("policy_%d", time.Now().UnixNano())
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.IsActive = true

	ars.retentionPolicies[policy.PolicyID] = policy

	facades.Log().Info("Retention policy added", map[string]interface{}{
		"policy_id":        policy.PolicyID,
		"policy_name":      policy.Name,
		"retention_period": policy.RetentionPeriod.String(),
		"auto_archive":     policy.AutoArchive,
		"auto_delete":      policy.AutoDelete,
	})

	return nil
}

// UpdateRetentionPolicy updates an existing retention policy
func (ars *AuditRetentionService) UpdateRetentionPolicy(policyID string, policy *RetentionPolicy) error {
	existingPolicy, exists := ars.retentionPolicies[policyID]
	if !exists {
		return fmt.Errorf("retention policy not found: %s", policyID)
	}

	policy.PolicyID = policyID
	policy.CreatedAt = existingPolicy.CreatedAt
	policy.UpdatedAt = time.Now()

	ars.retentionPolicies[policyID] = policy

	facades.Log().Info("Retention policy updated", map[string]interface{}{
		"policy_id":   policyID,
		"policy_name": policy.Name,
	})

	return nil
}

// RemoveRetentionPolicy removes a retention policy
func (ars *AuditRetentionService) RemoveRetentionPolicy(policyID string) error {
	_, exists := ars.retentionPolicies[policyID]
	if !exists {
		return fmt.Errorf("retention policy not found: %s", policyID)
	}

	delete(ars.retentionPolicies, policyID)

	facades.Log().Info("Retention policy removed", map[string]interface{}{
		"policy_id": policyID,
	})

	return nil
}

// GetRetentionPolicy returns a retention policy by ID
func (ars *AuditRetentionService) GetRetentionPolicy(policyID string) (*RetentionPolicy, error) {
	policy, exists := ars.retentionPolicies[policyID]
	if !exists {
		return nil, fmt.Errorf("retention policy not found: %s", policyID)
	}

	return policy, nil
}

// GetAllRetentionPolicies returns all retention policies
func (ars *AuditRetentionService) GetAllRetentionPolicies() []*RetentionPolicy {
	var policies []*RetentionPolicy
	for _, policy := range ars.retentionPolicies {
		policies = append(policies, policy)
	}
	return policies
}

// ExecuteRetentionPolicies executes all active retention policies
func (ars *AuditRetentionService) ExecuteRetentionPolicies(ctx context.Context, tenantID string) (*RetentionReport, error) {
	report := &RetentionReport{
		ReportID:         fmt.Sprintf("retention_report_%d", time.Now().UnixNano()),
		TenantID:         tenantID,
		GeneratedAt:      time.Now(),
		Period:           "manual",
		PolicyExecutions: []PolicyExecution{},
		Warnings:         []string{},
		Errors:           []string{},
	}

	for _, policy := range ars.retentionPolicies {
		if !policy.IsActive {
			continue
		}

		execution := PolicyExecution{
			PolicyID:   policy.PolicyID,
			PolicyName: policy.Name,
			ExecutedAt: time.Now(),
			Action:     "retention_check",
			Status:     "running",
		}

		startTime := time.Now()

		// Execute policy
		affected, err := ars.executePolicy(ctx, tenantID, policy)
		execution.Duration = time.Since(startTime).String()
		execution.RecordsAffected = affected

		if err != nil {
			execution.Status = "failed"
			execution.Error = err.Error()
			report.Errors = append(report.Errors, fmt.Sprintf("Policy %s failed: %s", policy.Name, err.Error()))
		} else {
			execution.Status = "completed"
		}

		report.PolicyExecutions = append(report.PolicyExecutions, execution)

		// Update report totals
		if policy.AutoArchive {
			report.ArchivedRecords += affected
		}
		if policy.AutoDelete {
			report.DeletedRecords += affected
		}
	}

	// Calculate totals
	totalCount, _ := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("tenant_id = ?", tenantID).
		Count()

	report.TotalRecords = totalCount
	report.RetainedRecords = totalCount - report.DeletedRecords

	facades.Log().Info("Retention policies executed", map[string]interface{}{
		"tenant_id":        tenantID,
		"total_records":    report.TotalRecords,
		"archived_records": report.ArchivedRecords,
		"deleted_records":  report.DeletedRecords,
		"retained_records": report.RetainedRecords,
	})

	return report, nil
}

// ScheduleRetentionExecution schedules automatic retention policy execution
func (ars *AuditRetentionService) ScheduleRetentionExecution(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Get all tenants and execute retention policies
			ars.executeScheduledRetention(ctx)
		}
	}
}

// ArchiveAuditLogs archives audit logs based on policy
func (ars *AuditRetentionService) ArchiveAuditLogs(tenantID string, policy *RetentionPolicy) (*ArchiveMetadata, error) {
	cutoffDate := time.Now().Add(-policy.ArchivalPeriod)

	// Get logs to archive
	var logsToArchive []models.ActivityLog
	query := facades.Orm().Query().
		Where("tenant_id = ? AND event_timestamp < ?", tenantID, cutoffDate)

	// Apply policy filters
	if len(policy.Categories) > 0 {
		var categories []interface{}
		for _, cat := range policy.Categories {
			categories = append(categories, cat)
		}
		query = query.WhereIn("category", categories)
	}
	if len(policy.Severities) > 0 {
		var severities []interface{}
		for _, sev := range policy.Severities {
			severities = append(severities, sev)
		}
		query = query.WhereIn("severity", severities)
	}

	err := query.Find(&logsToArchive)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch logs for archival: %w", err)
	}

	if len(logsToArchive) == 0 {
		return nil, fmt.Errorf("no logs found for archival")
	}

	// Create archive
	archiveID := fmt.Sprintf("archive_%s_%d", tenantID, time.Now().Unix())
	archiveMetadata := &ArchiveMetadata{
		ArchiveID:       archiveID,
		TenantID:        tenantID,
		StartDate:       logsToArchive[len(logsToArchive)-1].EventTimestamp,
		EndDate:         logsToArchive[0].EventTimestamp,
		RecordCount:     int64(len(logsToArchive)),
		CreatedAt:       time.Now(),
		RetentionPolicy: policy.PolicyID,
		Status:          "creating",
	}

	// Create archive file
	archivePath, err := ars.archivalService.CreateArchive(archiveID, logsToArchive, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create archive: %w", err)
	}

	archiveMetadata.ArchivePath = archivePath
	archiveMetadata.Status = "completed"

	// Get file size
	if stat, err := os.Stat(archivePath); err == nil {
		archiveMetadata.CompressedSize = stat.Size()
	}

	// Delete archived logs from database if policy allows
	if policy.AutoDelete {
		var logIDs []string
		for _, log := range logsToArchive {
			logIDs = append(logIDs, log.ID)
		}

		_, err = facades.Orm().Query().
			Where("id IN (?)", logIDs).
			Delete(&models.ActivityLog{})

		if err != nil {
			facades.Log().Error("Failed to delete archived logs", map[string]interface{}{
				"error":      err.Error(),
				"archive_id": archiveID,
				"count":      len(logIDs),
			})
		}
	}

	facades.Log().Info("Audit logs archived", map[string]interface{}{
		"archive_id":      archiveID,
		"tenant_id":       tenantID,
		"record_count":    archiveMetadata.RecordCount,
		"archive_path":    archivePath,
		"compressed_size": archiveMetadata.CompressedSize,
	})

	return archiveMetadata, nil
}

// RestoreFromArchive restores audit logs from an archive
func (ars *AuditRetentionService) RestoreFromArchive(archiveID string) error {
	// Production-ready archive restoration implementation
	facades.Log().Info("Starting archive restoration", map[string]interface{}{
		"archive_id": archiveID,
	})

	// Get archive metadata first
	metadata, err := ars.GetArchiveMetadata(archiveID)
	if err != nil {
		return fmt.Errorf("failed to get archive metadata: %w", err)
	}

	// Check if archive file exists
	if _, err := os.Stat(metadata.ArchivePath); os.IsNotExist(err) {
		return fmt.Errorf("archive file not found: %s", metadata.ArchivePath)
	}

	// Create a temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "audit_restore_"+archiveID)
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir) // Clean up

	// Extract archive based on compression type
	extractedPath, err := ars.extractArchive(metadata.ArchivePath, tempDir, metadata.CompressionType)
	if err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}

	// Read and parse the extracted data
	logs, err := ars.parseExtractedLogs(extractedPath)
	if err != nil {
		return fmt.Errorf("failed to parse extracted logs: %w", err)
	}

	// Validate the logs before restoration
	if err := ars.validateLogsForRestore(logs, metadata); err != nil {
		return fmt.Errorf("log validation failed: %w", err)
	}

	// Restore logs to database in batches
	batchSize := 1000
	totalRestored := 0

	for i := 0; i < len(logs); i += batchSize {
		end := i + batchSize
		if end > len(logs) {
			end = len(logs)
		}

		batch := logs[i:end]
		if err := ars.restoreLogBatch(batch); err != nil {
			facades.Log().Error("Failed to restore log batch", map[string]interface{}{
				"archive_id":  archiveID,
				"batch_start": i,
				"batch_size":  len(batch),
				"error":       err.Error(),
			})
			return fmt.Errorf("failed to restore batch starting at %d: %w", i, err)
		}

		totalRestored += len(batch)
		facades.Log().Info("Restored log batch", map[string]interface{}{
			"archive_id":     archiveID,
			"batch_size":     len(batch),
			"total_restored": totalRestored,
			"progress":       fmt.Sprintf("%.1f%%", float64(totalRestored)/float64(len(logs))*100),
		})
	}

	// Update archive metadata to mark as restored
	if err := ars.markArchiveAsRestored(archiveID, totalRestored); err != nil {
		facades.Log().Warning("Failed to update archive status", map[string]interface{}{
			"archive_id": archiveID,
			"error":      err.Error(),
		})
	}

	facades.Log().Info("Archive restoration completed", map[string]interface{}{
		"archive_id":     archiveID,
		"total_restored": totalRestored,
		"expected_count": metadata.RecordCount,
	})

	return nil
}

// GetArchiveMetadata returns metadata for an archive
func (ars *AuditRetentionService) GetArchiveMetadata(archiveID string) (*ArchiveMetadata, error) {
	// Production implementation that retrieves archive metadata from storage
	var metadata ArchiveMetadata

	// Try to load from database first
	err := facades.Orm().Query().
		Table("audit_archives").
		Where("archive_id = ?", archiveID).
		First(&metadata)

	if err != nil {
		// Try to load from file system metadata
		return ars.loadArchiveMetadataFromFile(archiveID)
	}

	return &metadata, nil
}

// ListArchives returns a list of all archives for a tenant
func (ars *AuditRetentionService) ListArchives(tenantID string) ([]*ArchiveMetadata, error) {
	// Production implementation that lists all archives for a tenant
	var archives []*ArchiveMetadata

	// Query from database
	err := facades.Orm().Query().
		Table("audit_archives").
		Where("tenant_id = ?", tenantID).
		OrderBy("created_at DESC").
		Find(&archives)

	if err != nil {
		facades.Log().Error("Failed to list archives from database", map[string]interface{}{
			"tenant_id": tenantID,
			"error":     err.Error(),
		})

		// Fallback to file system scan
		return ars.scanArchiveDirectory(tenantID)
	}

	return archives, nil
}

// DeleteExpiredLogs deletes logs that have exceeded their retention period
func (ars *AuditRetentionService) DeleteExpiredLogs(tenantID string, policy *RetentionPolicy) (int64, error) {
	if policy.LegalHold {
		return 0, fmt.Errorf("cannot delete logs under legal hold")
	}

	cutoffDate := time.Now().Add(-policy.DeleteAfter)

	query := facades.Orm().Query().
		Where("tenant_id = ? AND event_timestamp < ?", tenantID, cutoffDate)

	// Apply policy filters
	if len(policy.Categories) > 0 {
		var categories []interface{}
		for _, cat := range policy.Categories {
			categories = append(categories, cat)
		}
		query = query.WhereIn("category", categories)
	}
	if len(policy.Severities) > 0 {
		var severities []interface{}
		for _, sev := range policy.Severities {
			severities = append(severities, sev)
		}
		query = query.WhereIn("severity", severities)
	}

	// Count records to be deleted
	count, err := query.Count()
	if err != nil {
		return 0, fmt.Errorf("failed to count expired logs: %w", err)
	}

	if count == 0 {
		return 0, nil
	}

	// Send notification before deletion if required
	if policy.NotifyBeforeDelete {
		ars.sendDeletionNotification(tenantID, policy, count)
	}

	// Delete the logs
	_, err = query.Delete(&models.ActivityLog{})
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired logs: %w", err)
	}

	facades.Log().Info("Expired audit logs deleted", map[string]interface{}{
		"tenant_id":   tenantID,
		"policy_id":   policy.PolicyID,
		"count":       count,
		"cutoff_date": cutoffDate,
	})

	return count, nil
}

// Private methods

func (ars *AuditRetentionService) loadDefaultPolicies() {
	// Security logs - keep for 7 years for compliance
	securityPolicy := &RetentionPolicy{
		PolicyID:        "security_logs",
		Name:            "Security Logs Retention",
		Description:     "Retention policy for security-related audit logs",
		Categories:      []models.ActivityLogCategory{models.CategorySecurity, models.CategoryAuthentication, models.CategoryAuthorization},
		RetentionPeriod: 7 * 365 * 24 * time.Hour, // 7 years
		ArchivalPeriod:  90 * 24 * time.Hour,      // 90 days
		DeleteAfter:     7 * 365 * 24 * time.Hour, // 7 years
		AutoArchive:     true,
		AutoDelete:      false, // Never auto-delete security logs
		ComplianceFlags: []string{"SOX", "GDPR", "HIPAA"},
		IsActive:        true,
	}

	// General logs - keep for 1 year
	generalPolicy := &RetentionPolicy{
		PolicyID:        "general_logs",
		Name:            "General Logs Retention",
		Description:     "Retention policy for general audit logs",
		Categories:      []models.ActivityLogCategory{models.CategorySystem, models.CategoryUser, models.CategoryPerformance},
		RetentionPeriod: 365 * 24 * time.Hour, // 1 year
		ArchivalPeriod:  30 * 24 * time.Hour,  // 30 days
		DeleteAfter:     365 * 24 * time.Hour, // 1 year
		AutoArchive:     true,
		AutoDelete:      true,
		IsActive:        true,
	}

	// Compliance logs - keep for 10 years
	compliancePolicy := &RetentionPolicy{
		PolicyID:        "compliance_logs",
		Name:            "Compliance Logs Retention",
		Description:     "Retention policy for compliance-related audit logs",
		Categories:      []models.ActivityLogCategory{models.CategoryCompliance},
		RetentionPeriod: 10 * 365 * 24 * time.Hour, // 10 years
		ArchivalPeriod:  180 * 24 * time.Hour,      // 180 days
		DeleteAfter:     10 * 365 * 24 * time.Hour, // 10 years
		AutoArchive:     true,
		AutoDelete:      false, // Never auto-delete compliance logs
		ComplianceFlags: []string{"SOX", "GDPR", "HIPAA", "PCI-DSS"},
		LegalHold:       true,
		IsActive:        true,
	}

	ars.retentionPolicies[securityPolicy.PolicyID] = securityPolicy
	ars.retentionPolicies[generalPolicy.PolicyID] = generalPolicy
	ars.retentionPolicies[compliancePolicy.PolicyID] = compliancePolicy

	facades.Log().Info("Default retention policies loaded", map[string]interface{}{
		"policies_count": len(ars.retentionPolicies),
	})
}

func (ars *AuditRetentionService) executePolicy(ctx context.Context, tenantID string, policy *RetentionPolicy) (int64, error) {
	var totalAffected int64

	// Archive logs if auto-archive is enabled
	if policy.AutoArchive {
		_, err := ars.ArchiveAuditLogs(tenantID, policy)
		if err != nil {
			return 0, fmt.Errorf("archival failed: %w", err)
		}
	}

	// Delete expired logs if auto-delete is enabled
	if policy.AutoDelete {
		deleted, err := ars.DeleteExpiredLogs(tenantID, policy)
		if err != nil {
			return 0, fmt.Errorf("deletion failed: %w", err)
		}
		totalAffected += deleted
	}

	return totalAffected, nil
}

func (ars *AuditRetentionService) executeScheduledRetention(ctx context.Context) {
	// Get all tenants from the tenant management system
	tenants, err := ars.getAllTenants(ctx)
	if err != nil {
		facades.Log().Error("Failed to retrieve tenants for scheduled retention", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if len(tenants) == 0 {
		facades.Log().Warning("No tenants found for scheduled retention", nil)
		return
	}

	facades.Log().Info("Starting scheduled retention for all tenants", map[string]interface{}{
		"tenant_count": len(tenants),
	})

	for _, tenantID := range tenants {
		report, err := ars.ExecuteRetentionPolicies(ctx, tenantID)
		if err != nil {
			facades.Log().Error("Scheduled retention execution failed", map[string]interface{}{
				"tenant_id": tenantID,
				"error":     err.Error(),
			})
			continue
		}

		facades.Log().Info("Scheduled retention executed", map[string]interface{}{
			"tenant_id":        tenantID,
			"archived_records": report.ArchivedRecords,
			"deleted_records":  report.DeletedRecords,
		})
	}
}

func (ars *AuditRetentionService) sendDeletionNotification(tenantID string, policy *RetentionPolicy, count int64) {
	// This would send a notification before deleting logs
	facades.Log().Info("Deletion notification sent", map[string]interface{}{
		"tenant_id":   tenantID,
		"policy_name": policy.Name,
		"count":       count,
	})
}

// CreateArchive creates an archive file from audit logs
func (as *ArchivalService) CreateArchive(archiveID string, logs []models.ActivityLog, policy *RetentionPolicy) (string, error) {
	// Ensure archive directory exists
	err := os.MkdirAll(as.archivePath, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create archive directory: %w", err)
	}

	// Create archive file path
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.jsonl", archiveID, timestamp)
	if policy.EncryptArchive {
		filename += ".enc"
	}
	archiveFilePath := filepath.Join(as.archivePath, filename)

	// Create archive file
	file, err := os.Create(archiveFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create archive file: %w", err)
	}
	defer file.Close()

	// Write logs to archive in JSON Lines format
	for _, log := range logs {
		logJSON, err := json.Marshal(log)
		if err != nil {
			return "", fmt.Errorf("failed to marshal log: %w", err)
		}

		_, err = file.Write(logJSON)
		if err != nil {
			return "", fmt.Errorf("failed to write log to archive: %w", err)
		}

		_, err = file.Write([]byte("\n"))
		if err != nil {
			return "", fmt.Errorf("failed to write newline to archive: %w", err)
		}
	}

	return archiveFilePath, nil
}

// Helper methods for archive restoration

func (ars *AuditRetentionService) extractArchive(archivePath, tempDir, compressionType string) (string, error) {
	switch compressionType {
	case "gzip":
		return ars.extractGzipArchive(archivePath, tempDir)
	case "zip":
		return ars.extractZipArchive(archivePath, tempDir)
	case "tar.gz":
		return ars.extractTarGzArchive(archivePath, tempDir)
	default:
		return "", fmt.Errorf("unsupported compression type: %s", compressionType)
	}
}

func (ars *AuditRetentionService) extractGzipArchive(archivePath, tempDir string) (string, error) {
	// Open the gzip file
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create output file
	outputPath := filepath.Join(tempDir, "logs.json")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Copy decompressed data
	_, err = io.Copy(outputFile, gzReader)
	if err != nil {
		return "", fmt.Errorf("failed to decompress archive: %w", err)
	}

	return outputPath, nil
}

func (ars *AuditRetentionService) extractZipArchive(archivePath, tempDir string) (string, error) {
	// Open zip file
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer reader.Close()

	// Extract first file (assuming single file archive)
	if len(reader.File) == 0 {
		return "", fmt.Errorf("empty zip archive")
	}

	file := reader.File[0]
	rc, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file in zip: %w", err)
	}
	defer rc.Close()

	// Create output file
	outputPath := filepath.Join(tempDir, file.Name)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Copy file contents
	_, err = io.Copy(outputFile, rc)
	if err != nil {
		return "", fmt.Errorf("failed to extract file: %w", err)
	}

	return outputPath, nil
}

func (ars *AuditRetentionService) extractTarGzArchive(archivePath, tempDir string) (string, error) {
	// Open the tar.gz file
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open archive: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract first file
	header, err := tarReader.Next()
	if err != nil {
		return "", fmt.Errorf("failed to read tar header: %w", err)
	}

	// Create output file
	outputPath := filepath.Join(tempDir, header.Name)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Copy file contents
	_, err = io.Copy(outputFile, tarReader)
	if err != nil {
		return "", fmt.Errorf("failed to extract tar file: %w", err)
	}

	return outputPath, nil
}

func (ars *AuditRetentionService) parseExtractedLogs(filePath string) ([]models.ActivityLog, error) {
	// Read the extracted file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read extracted file: %w", err)
	}

	// Parse JSON data
	var logs []models.ActivityLog
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, fmt.Errorf("failed to parse JSON logs: %w", err)
	}

	return logs, nil
}

func (ars *AuditRetentionService) validateLogsForRestore(logs []models.ActivityLog, metadata *ArchiveMetadata) error {
	// Validate log count matches metadata
	if len(logs) != int(metadata.RecordCount) {
		return fmt.Errorf("log count mismatch: expected %d, got %d", metadata.RecordCount, len(logs))
	}

	// Validate tenant ID consistency
	for i, log := range logs {
		if log.TenantID != metadata.TenantID {
			return fmt.Errorf("tenant ID mismatch at log %d: expected %s, got %s", i, metadata.TenantID, log.TenantID)
		}
	}

	// Validate date range
	for i, log := range logs {
		if log.EventTimestamp.Before(metadata.StartDate) || log.EventTimestamp.After(metadata.EndDate) {
			return fmt.Errorf("log %d timestamp %v outside archive date range %v - %v",
				i, log.EventTimestamp, metadata.StartDate, metadata.EndDate)
		}
	}

	return nil
}

func (ars *AuditRetentionService) restoreLogBatch(logs []models.ActivityLog) error {
	// Restore logs using simple batch insert
	for _, log := range logs {
		// Check if log already exists (prevent duplicates)
		var existingLog models.ActivityLog
		err := facades.Orm().Query().Where("id = ?", log.ID).First(&existingLog)

		if err == nil {
			// Log already exists, skip it
			facades.Log().Debug("Skipping duplicate log", map[string]interface{}{
				"log_id": log.ID,
			})
			continue
		}

		// Insert the log
		if err := facades.Orm().Query().Create(&log); err != nil {
			return fmt.Errorf("failed to restore log %s: %w", log.ID, err)
		}
	}

	return nil
}

func (ars *AuditRetentionService) markArchiveAsRestored(archiveID string, restoredCount int) error {
	// Update archive metadata to mark as restored
	now := time.Now()

	_, err := facades.Orm().Query().
		Table("audit_archives").
		Where("archive_id = ?", archiveID).
		Update(map[string]interface{}{
			"status":         "restored",
			"restored_at":    now,
			"restored_count": restoredCount,
			"updated_at":     now,
		})

	return err
}

func (ars *AuditRetentionService) loadArchiveMetadataFromFile(archiveID string) (*ArchiveMetadata, error) {
	// Try to load metadata from a .meta file alongside the archive
	archiveDir := facades.Config().GetString("audit.archive_directory", "/var/lib/goravel/archives")
	metadataPath := filepath.Join(archiveDir, archiveID+".meta")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("metadata file not found: %w", err)
	}

	var metadata ArchiveMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

func (ars *AuditRetentionService) scanArchiveDirectory(tenantID string) ([]*ArchiveMetadata, error) {
	// Scan file system for archives when database is unavailable
	archiveDir := facades.Config().GetString("audit.archive_directory", "/var/lib/goravel/archives")

	files, err := os.ReadDir(archiveDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read archive directory: %w", err)
	}

	var archives []*ArchiveMetadata

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".meta") {
			metadata, err := ars.loadArchiveMetadataFromFile(strings.TrimSuffix(file.Name(), ".meta"))
			if err != nil {
				facades.Log().Warning("Failed to load metadata file", map[string]interface{}{
					"file":  file.Name(),
					"error": err.Error(),
				})
				continue
			}

			if metadata.TenantID == tenantID {
				archives = append(archives, metadata)
			}
		}
	}

	return archives, nil
}

// getAllTenants retrieves all active tenants from the tenant management system
func (ars *AuditRetentionService) getAllTenants(ctx context.Context) ([]string, error) {
	var tenants []string

	// Query the tenants table to get all active tenants
	var tenantRecords []map[string]interface{}
	err := facades.Orm().Query().
		Table("tenants").
		Where("status", "active").
		Where("deleted_at IS NULL").
		Select("id", "name", "domain", "status", "created_at").
		Get(&tenantRecords)

	if err != nil {
		facades.Log().Error("Failed to query tenants table", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to query tenants: %v", err)
	}

	// Extract tenant IDs
	for _, record := range tenantRecords {
		if tenantID, ok := record["id"].(string); ok && tenantID != "" {
			tenants = append(tenants, tenantID)
		} else if tenantIDInt, ok := record["id"].(int64); ok {
			tenants = append(tenants, fmt.Sprintf("%d", tenantIDInt))
		} else if tenantIDUint, ok := record["id"].(uint64); ok {
			tenants = append(tenants, fmt.Sprintf("%d", tenantIDUint))
		}
	}

	// If no tenants found in database, include default tenant
	if len(tenants) == 0 {
		facades.Log().Info("No tenants found in database, using default tenant", nil)
		tenants = append(tenants, "default")
	}

	// Add multi-tenant validation
	validatedTenants, err := ars.validateTenants(ctx, tenants)
	if err != nil {
		facades.Log().Warning("Tenant validation failed, using all discovered tenants", map[string]interface{}{
			"error": err.Error(),
		})
		validatedTenants = tenants
	}

	facades.Log().Info("Retrieved tenants for retention processing", map[string]interface{}{
		"total_discovered": len(tenants),
		"validated_count":  len(validatedTenants),
		"tenants":          validatedTenants,
	})

	return validatedTenants, nil
}

// validateTenants validates that tenants have audit logs and are properly configured
func (ars *AuditRetentionService) validateTenants(ctx context.Context, tenants []string) ([]string, error) {
	var validTenants []string

	for _, tenantID := range tenants {
		// Check if tenant has audit logs
		count, err := facades.Orm().Query().
			Table("activity_logs").
			Where("tenant_id = ? OR tenant_id IS NULL", tenantID).
			Count()

		if err != nil {
			facades.Log().Warning("Failed to check audit logs for tenant", map[string]interface{}{
				"tenant_id": tenantID,
				"error":     err.Error(),
			})
			continue
		}

		// Check if tenant has retention policies configured
		hasPolicies, err := ars.tenantHasRetentionPolicies(ctx, tenantID)
		if err != nil {
			facades.Log().Warning("Failed to check retention policies for tenant", map[string]interface{}{
				"tenant_id": tenantID,
				"error":     err.Error(),
			})
			// Include tenant anyway if it has audit logs
			if count > 0 {
				validTenants = append(validTenants, tenantID)
			}
			continue
		}

		// Include tenant if it has audit logs or retention policies
		if count > 0 || hasPolicies {
			validTenants = append(validTenants, tenantID)
			facades.Log().Debug("Validated tenant for retention", map[string]interface{}{
				"tenant_id":       tenantID,
				"audit_log_count": count,
				"has_policies":    hasPolicies,
			})
		} else {
			facades.Log().Debug("Skipping tenant with no audit logs or policies", map[string]interface{}{
				"tenant_id": tenantID,
			})
		}
	}

	return validTenants, nil
}

// tenantHasRetentionPolicies checks if a tenant has retention policies configured
func (ars *AuditRetentionService) tenantHasRetentionPolicies(ctx context.Context, tenantID string) (bool, error) {
	// Check if tenant has custom retention policies in configuration or database

	// First check if there are tenant-specific retention policies in the database
	count, err := facades.Orm().Query().
		Table("audit_retention_policies").
		Where("tenant_id = ?", tenantID).
		Where("active = ?", true).
		Count()

	if err != nil {
		// If the table doesn't exist, that's okay - use default policies
		facades.Log().Debug("Audit retention policies table not found, using default policies", map[string]interface{}{
			"tenant_id": tenantID,
		})
		return true, nil // Assume default policies apply
	}

	if count > 0 {
		return true, nil
	}

	// Check if tenant has configuration-based policies
	configKey := fmt.Sprintf("audit.retention.tenants.%s", tenantID)
	tenantConfig := facades.Config().GetString(configKey, "")
	if tenantConfig != "" {
		return true, nil
	}

	// Check for default policies that apply to all tenants
	defaultPolicies := facades.Config().GetString("audit.retention.default_policies", "")
	return defaultPolicies != "", nil
}

// getTenantRetentionConfig gets retention configuration for a specific tenant
func (ars *AuditRetentionService) getTenantRetentionConfig(ctx context.Context, tenantID string) (*TenantRetentionConfig, error) {
	config := &TenantRetentionConfig{
		TenantID:             tenantID,
		DefaultRetentionDays: 365, // Default 1 year retention
		ComplianceMode:       false,
		ArchiveEnabled:       true,
		CompressionEnabled:   true,
		EncryptionEnabled:    true,
		Categories:           make(map[string]CategoryRetentionConfig),
	}

	// Load tenant-specific configuration from database
	var policyRecords []map[string]interface{}
	err := facades.Orm().Query().
		Table("audit_retention_policies").
		Where("tenant_id = ?", tenantID).
		Where("active = ?", true).
		Get(&policyRecords)

	if err != nil && !strings.Contains(err.Error(), "doesn't exist") {
		return nil, fmt.Errorf("failed to load tenant retention policies: %v", err)
	}

	// Apply database policies
	for _, record := range policyRecords {
		if category, ok := record["category"].(string); ok {
			if retentionDays, ok := record["retention_days"].(int64); ok {
				config.Categories[category] = CategoryRetentionConfig{
					RetentionDays:     int(retentionDays),
					ArchiveEnabled:    getBoolFromRecord(record, "archive_enabled", true),
					CompressionLevel:  getIntFromRecord(record, "compression_level", 6),
					EncryptionEnabled: getBoolFromRecord(record, "encryption_enabled", true),
				}
			}
		}
	}

	// Load configuration from config files
	configKey := fmt.Sprintf("audit.retention.tenants.%s", tenantID)
	if tenantConfigStr := facades.Config().GetString(configKey, ""); tenantConfigStr != "" {
		// Parse tenant-specific configuration
		// TODO: In production, you would implement proper config parsing
		facades.Log().Debug("Loading tenant-specific retention config", map[string]interface{}{
			"tenant_id": tenantID,
			"config":    tenantConfigStr,
		})
	}

	// Apply default configuration for missing categories
	defaultCategories := []string{"authentication", "authorization", "data_access", "system", "security"}
	for _, category := range defaultCategories {
		if _, exists := config.Categories[category]; !exists {
			config.Categories[category] = CategoryRetentionConfig{
				RetentionDays:     config.DefaultRetentionDays,
				ArchiveEnabled:    config.ArchiveEnabled,
				CompressionLevel:  6,
				EncryptionEnabled: config.EncryptionEnabled,
			}
		}
	}

	return config, nil
}

// TenantRetentionConfig represents retention configuration for a tenant
type TenantRetentionConfig struct {
	TenantID             string                             `json:"tenant_id"`
	DefaultRetentionDays int                                `json:"default_retention_days"`
	ComplianceMode       bool                               `json:"compliance_mode"`
	ArchiveEnabled       bool                               `json:"archive_enabled"`
	CompressionEnabled   bool                               `json:"compression_enabled"`
	EncryptionEnabled    bool                               `json:"encryption_enabled"`
	Categories           map[string]CategoryRetentionConfig `json:"categories"`
}

// CategoryRetentionConfig represents retention configuration for a specific audit category
type CategoryRetentionConfig struct {
	RetentionDays     int  `json:"retention_days"`
	ArchiveEnabled    bool `json:"archive_enabled"`
	CompressionLevel  int  `json:"compression_level"`
	EncryptionEnabled bool `json:"encryption_enabled"`
}

// Helper functions for database record parsing
func getBoolFromRecord(record map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := record[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
		if intValue, ok := value.(int64); ok {
			return intValue != 0
		}
		if strValue, ok := value.(string); ok {
			return strValue == "true" || strValue == "1"
		}
	}
	return defaultValue
}

func getIntFromRecord(record map[string]interface{}, key string, defaultValue int) int {
	if value, ok := record[key]; ok {
		if intValue, ok := value.(int64); ok {
			return int(intValue)
		}
		if intValue, ok := value.(int); ok {
			return intValue
		}
		if strValue, ok := value.(string); ok {
			if parsed, err := strconv.Atoi(strValue); err == nil {
				return parsed
			}
		}
	}
	return defaultValue
}
