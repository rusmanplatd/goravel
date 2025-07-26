package querybuilder

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
)

// BulkOperation represents a bulk operation configuration
type BulkOperation struct {
	query      orm.Query
	batchSize  int
	timeout    time.Duration
	onConflict ConflictResolution
	validateFn func(interface{}) error
	beforeFn   func([]interface{}) error
	afterFn    func([]interface{}) error
	progressFn func(processed, total int)
}

// ConflictResolution defines how to handle conflicts during bulk operations
type ConflictResolution string

const (
	ConflictIgnore  ConflictResolution = "ignore"
	ConflictReplace ConflictResolution = "replace"
	ConflictUpdate  ConflictResolution = "update"
	ConflictError   ConflictResolution = "error"
)

// BulkResult represents the result of a bulk operation
type BulkResult struct {
	TotalRecords      int           `json:"total_records"`
	ProcessedRecords  int           `json:"processed_records"`
	SuccessfulRecords int           `json:"successful_records"`
	FailedRecords     int           `json:"failed_records"`
	Errors            []BulkError   `json:"errors,omitempty"`
	Duration          time.Duration `json:"duration"`
	BatchCount        int           `json:"batch_count"`
}

// BulkError represents an error that occurred during bulk operations
type BulkError struct {
	Index      int         `json:"index"`
	Record     interface{} `json:"record,omitempty"`
	Error      string      `json:"error"`
	BatchIndex int         `json:"batch_index"`
}

// UpsertConfig represents configuration for upsert operations
type UpsertConfig struct {
	ConflictColumns []string               `json:"conflict_columns"`
	UpdateColumns   []string               `json:"update_columns,omitempty"`
	UpdateValues    map[string]interface{} `json:"update_values,omitempty"`
}

// NewBulkOperation creates a new bulk operation
func NewBulkOperation(query orm.Query) *BulkOperation {
	return &BulkOperation{
		query:      query,
		batchSize:  1000,
		timeout:    30 * time.Second,
		onConflict: ConflictError,
	}
}

// ForBulk creates a new bulk operation for the given model
func ForBulk(subject interface{}) *BulkOperation {
	var query orm.Query

	switch v := subject.(type) {
	case orm.Query:
		query = v
	case string:
		query = facades.Orm().Query().Model(subject)
	default:
		query = facades.Orm().Query().Model(subject)
	}

	return NewBulkOperation(query)
}

// Configuration methods

// WithBatchSize sets the batch size for bulk operations
func (bo *BulkOperation) WithBatchSize(size int) *BulkOperation {
	if size <= 0 {
		size = 1000
	}
	bo.batchSize = size
	return bo
}

// WithTimeout sets the timeout for bulk operations
func (bo *BulkOperation) WithTimeout(timeout time.Duration) *BulkOperation {
	bo.timeout = timeout
	return bo
}

// WithConflictResolution sets how to handle conflicts
func (bo *BulkOperation) WithConflictResolution(resolution ConflictResolution) *BulkOperation {
	bo.onConflict = resolution
	return bo
}

// WithValidation sets a validation function to run on each record
func (bo *BulkOperation) WithValidation(fn func(interface{}) error) *BulkOperation {
	bo.validateFn = fn
	return bo
}

// WithBeforeHook sets a function to run before each batch
func (bo *BulkOperation) WithBeforeHook(fn func([]interface{}) error) *BulkOperation {
	bo.beforeFn = fn
	return bo
}

// WithAfterHook sets a function to run after each batch
func (bo *BulkOperation) WithAfterHook(fn func([]interface{}) error) *BulkOperation {
	bo.afterFn = fn
	return bo
}

// WithProgress sets a progress callback function
func (bo *BulkOperation) WithProgress(fn func(processed, total int)) *BulkOperation {
	bo.progressFn = fn
	return bo
}

// Bulk Insert Operations

// BulkInsert performs bulk insert operations with proper error handling and progress tracking
func (bo *BulkOperation) BulkInsert(records interface{}) (*BulkResult, error) {
	startTime := time.Now()

	recordsSlice, err := bo.toSlice(records)
	if err != nil {
		return nil, fmt.Errorf("invalid records format: %v", err)
	}

	totalRecords := len(recordsSlice)
	result := &BulkResult{
		TotalRecords: totalRecords,
		Errors:       make([]BulkError, 0),
	}

	// Validate records if validation function is provided
	if bo.validateFn != nil {
		for i, record := range recordsSlice {
			if err := bo.validateFn(record); err != nil {
				result.Errors = append(result.Errors, BulkError{
					Index:  i,
					Record: record,
					Error:  fmt.Sprintf("validation failed: %v", err),
				})
				result.FailedRecords++
				continue
			}
		}
	}

	// Execute before hook if provided
	if bo.beforeFn != nil {
		if err := bo.beforeFn(recordsSlice); err != nil {
			return nil, fmt.Errorf("before hook failed: %v", err)
		}
	}

	// Process records in batches
	batchCount := 0
	for i := 0; i < totalRecords; i += bo.batchSize {
		end := i + bo.batchSize
		if end > totalRecords {
			end = totalRecords
		}

		batch := recordsSlice[i:end]
		batchCount++

		if err := bo.insertBatch(batch, batchCount, result); err != nil {
			facades.Log().Error(fmt.Sprintf("Batch %d failed: %v", batchCount, err))
			// Continue with next batch instead of failing completely
		}

		result.ProcessedRecords += len(batch)

		// Report progress
		if bo.progressFn != nil {
			bo.progressFn(result.ProcessedRecords, totalRecords)
		}
	}

	// Execute after hook if provided
	if bo.afterFn != nil {
		if err := bo.afterFn(recordsSlice); err != nil {
			facades.Log().Warning(fmt.Sprintf("After hook failed: %v", err))
		}
	}

	result.BatchCount = batchCount
	result.Duration = time.Since(startTime)
	result.SuccessfulRecords = result.ProcessedRecords - result.FailedRecords

	return result, nil
}

// insertBatch processes a single batch of records with improved error handling
func (bo *BulkOperation) insertBatch(batch []interface{}, batchIndex int, result *BulkResult) error {
	// Create a transaction for the batch if supported
	tx, err := bo.query.Begin()
	if err != nil || tx == nil {
		// Fallback to individual inserts if transactions not supported
		return bo.insertBatchIndividual(batch, batchIndex, result)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			facades.Log().Error(fmt.Sprintf("Batch %d panicked: %v", batchIndex, r))
		}
	}()

	// Insert all records in the batch
	for i, record := range batch {
		if err := tx.Create(record); err != nil {
			tx.Rollback()

			// Handle conflict resolution
			switch bo.onConflict {
			case ConflictIgnore:
				facades.Log().Info(fmt.Sprintf("Ignoring conflict for record %d in batch %d", i, batchIndex))
				continue
			case ConflictReplace:
				// Try to update instead
				if updateErr := tx.Save(record); updateErr != nil {
					result.Errors = append(result.Errors, BulkError{
						Index:      i,
						Record:     record,
						Error:      fmt.Sprintf("insert and update failed: %v, %v", err, updateErr),
						BatchIndex: batchIndex,
					})
					result.FailedRecords++
				}
				continue
			default:
				result.Errors = append(result.Errors, BulkError{
					Index:      i,
					Record:     record,
					Error:      err.Error(),
					BatchIndex: batchIndex,
				})
				result.FailedRecords++
				return fmt.Errorf("batch insert failed: %v", err)
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch %d: %v", batchIndex, err)
	}

	return nil
}

// insertBatchIndividual processes records individually when transactions aren't available
func (bo *BulkOperation) insertBatchIndividual(batch []interface{}, batchIndex int, result *BulkResult) error {
	for i, record := range batch {
		if err := bo.query.Create(record); err != nil {
			result.Errors = append(result.Errors, BulkError{
				Index:      i,
				Record:     record,
				Error:      err.Error(),
				BatchIndex: batchIndex,
			})
			result.FailedRecords++

			// Continue with next record based on conflict resolution
			if bo.onConflict == ConflictError {
				return fmt.Errorf("individual insert failed: %v", err)
			}
		}
	}
	return nil
}

// Bulk Update Operations

// BulkUpdate performs bulk update operations with improved error handling
func (bo *BulkOperation) BulkUpdate(updates map[string]interface{}, conditions map[string]interface{}) (*BulkResult, error) {
	startTime := time.Now()

	result := &BulkResult{
		TotalRecords: 1, // Single update operation
		Errors:       make([]BulkError, 0),
	}

	// Build update query
	query := bo.query
	for field, value := range conditions {
		query = query.Where(fmt.Sprintf("%s = ?", field), value)
	}

	// Execute update
	affected, err := query.Update(updates)
	if err != nil {
		result.Errors = append(result.Errors, BulkError{
			Index: 0,
			Error: fmt.Sprintf("bulk update failed: %v", err),
		})
		result.FailedRecords = 1
	} else {
		// Handle the db.Result type properly
		affectedCount := int64(0)
		if affected != nil {
			affectedCount = affected.RowsAffected
		}
		result.SuccessfulRecords = int(affectedCount)
		result.ProcessedRecords = int(affectedCount)
	}

	result.Duration = time.Since(startTime)
	result.BatchCount = 1

	return result, nil
}

// BulkUpdateByRecords performs bulk update using individual records
func (bo *BulkOperation) BulkUpdateByRecords(records interface{}, updateFields []string) (*BulkResult, error) {
	startTime := time.Now()

	recordsSlice, err := bo.toSlice(records)
	if err != nil {
		return nil, fmt.Errorf("invalid records format: %v", err)
	}

	totalRecords := len(recordsSlice)
	result := &BulkResult{
		TotalRecords: totalRecords,
		Errors:       make([]BulkError, 0),
	}

	// Process in batches
	batchCount := 0
	for i := 0; i < totalRecords; i += bo.batchSize {
		end := i + bo.batchSize
		if end > totalRecords {
			end = totalRecords
		}

		batch := recordsSlice[i:end]
		batchCount++

		// Update each record in the batch
		for j, record := range batch {
			err := bo.updateRecord(record, updateFields)
			if err != nil {
				result.Errors = append(result.Errors, BulkError{
					Index:      i + j,
					Record:     record,
					Error:      fmt.Sprintf("update failed: %v", err),
					BatchIndex: batchCount,
				})
				result.FailedRecords++
			} else {
				result.SuccessfulRecords++
			}
		}

		result.ProcessedRecords += len(batch)

		// Report progress
		if bo.progressFn != nil {
			bo.progressFn(result.ProcessedRecords, totalRecords)
		}
	}

	result.BatchCount = batchCount
	result.Duration = time.Since(startTime)

	return result, nil
}

// updateRecord updates a single record
func (bo *BulkOperation) updateRecord(record interface{}, updateFields []string) error {
	// Extract ID from record for WHERE clause
	recordValue := reflect.ValueOf(record)
	if recordValue.Kind() == reflect.Ptr {
		recordValue = recordValue.Elem()
	}

	idField := recordValue.FieldByName("ID")
	if !idField.IsValid() {
		return fmt.Errorf("record must have an ID field")
	}

	id := idField.Interface()

	// Build update values
	updates := make(map[string]interface{})
	for _, field := range updateFields {
		fieldValue := recordValue.FieldByName(field)
		if fieldValue.IsValid() {
			updates[bo.toSnakeCase(field)] = fieldValue.Interface()
		}
	}

	if len(updates) == 0 {
		return fmt.Errorf("no valid update fields found")
	}

	// Perform update
	_, err := bo.query.Where("id = ?", id).Update(updates)
	return err
}

// Bulk Delete Operations

// BulkDelete performs bulk delete operations with improved error handling
func (bo *BulkOperation) BulkDelete(conditions map[string]interface{}) (*BulkResult, error) {
	startTime := time.Now()

	result := &BulkResult{
		TotalRecords: 1, // Single delete operation
		Errors:       make([]BulkError, 0),
	}

	// Build delete query
	query := bo.query
	for field, value := range conditions {
		query = query.Where(fmt.Sprintf("%s = ?", field), value)
	}

	// Execute delete
	affected, err := query.Delete(nil)
	if err != nil {
		result.Errors = append(result.Errors, BulkError{
			Index: 0,
			Error: fmt.Sprintf("bulk delete failed: %v", err),
		})
		result.FailedRecords = 1
	} else {
		// Handle the db.Result type properly
		affectedCount := int64(0)
		if affected != nil {
			affectedCount = affected.RowsAffected
		}
		result.SuccessfulRecords = int(affectedCount)
		result.ProcessedRecords = int(affectedCount)
	}

	result.Duration = time.Since(startTime)
	result.BatchCount = 1

	return result, nil
}

// BulkDeleteByIDs performs bulk delete by IDs
func (bo *BulkOperation) BulkDeleteByIDs(ids []interface{}) (*BulkResult, error) {
	startTime := time.Now()

	if len(ids) == 0 {
		return &BulkResult{
			TotalRecords: 0,
			Duration:     time.Since(startTime),
		}, nil
	}

	result := &BulkResult{
		TotalRecords: len(ids),
		Errors:       make([]BulkError, 0),
	}

	// Process in batches
	batchCount := 0
	for i := 0; i < len(ids); i += bo.batchSize {
		end := i + bo.batchSize
		if end > len(ids) {
			end = len(ids)
		}

		batch := ids[i:end]
		batchCount++

		// Delete batch
		batchResult, err := bo.query.Where("id IN ?", batch).Delete()
		if err != nil {
			result.Errors = append(result.Errors, BulkError{
				Index:      i,
				Error:      fmt.Sprintf("batch delete failed: %v", err),
				BatchIndex: batchCount,
			})
			result.FailedRecords += len(batch)
		} else {
			result.SuccessfulRecords += int(batchResult.RowsAffected)
		}

		result.ProcessedRecords += len(batch)

		// Report progress
		if bo.progressFn != nil {
			bo.progressFn(result.ProcessedRecords, len(ids))
		}
	}

	result.BatchCount = batchCount
	result.Duration = time.Since(startTime)

	return result, nil
}

// Upsert Operations

// BulkUpsert performs bulk upsert operations with improved error handling
func (bo *BulkOperation) BulkUpsert(records interface{}, config UpsertConfig) (*BulkResult, error) {
	startTime := time.Now()

	recordsSlice, err := bo.toSlice(records)
	if err != nil {
		return nil, fmt.Errorf("invalid records format: %v", err)
	}

	totalRecords := len(recordsSlice)
	result := &BulkResult{
		TotalRecords: totalRecords,
		Errors:       make([]BulkError, 0),
	}

	// Process records in batches
	batchCount := 0
	for i := 0; i < totalRecords; i += bo.batchSize {
		end := i + bo.batchSize
		if end > totalRecords {
			end = totalRecords
		}

		batch := recordsSlice[i:end]
		batchCount++

		for j, record := range batch {
			if err := bo.upsertRecord(record, config); err != nil {
				result.Errors = append(result.Errors, BulkError{
					Index:      i + j,
					Record:     record,
					Error:      err.Error(),
					BatchIndex: batchCount,
				})
				result.FailedRecords++
			} else {
				result.SuccessfulRecords++
			}
		}

		result.ProcessedRecords += len(batch)

		// Report progress
		if bo.progressFn != nil {
			bo.progressFn(result.ProcessedRecords, totalRecords)
		}
	}

	result.BatchCount = batchCount
	result.Duration = time.Since(startTime)

	return result, nil
}

// upsertRecord handles individual record upsert with improved logic
func (bo *BulkOperation) upsertRecord(record interface{}, config UpsertConfig) error {
	// Try insert first
	if err := bo.query.Create(record); err != nil {
		// If insert fails, try update
		updateQuery := bo.query

		// Build where clause based on conflict columns
		recordValue := reflect.ValueOf(record)
		if recordValue.Kind() == reflect.Ptr {
			recordValue = recordValue.Elem()
		}

		for _, column := range config.ConflictColumns {
			fieldName := bo.toCamelCase(column)
			field := recordValue.FieldByName(fieldName)
			if field.IsValid() {
				updateQuery = updateQuery.Where(fmt.Sprintf("%s = ?", column), field.Interface())
			}
		}

		// Build update data
		updateData := make(map[string]interface{})

		// Add specified update columns
		for _, column := range config.UpdateColumns {
			fieldName := bo.toCamelCase(column)
			field := recordValue.FieldByName(fieldName)
			if field.IsValid() {
				updateData[column] = field.Interface()
			}
		}

		// Add custom update values
		for key, value := range config.UpdateValues {
			updateData[key] = value
		}

		if _, err := updateQuery.Update(updateData); err != nil {
			return fmt.Errorf("upsert failed - insert error: %v, update error: %v", err, err)
		}
	}

	return nil
}

// Utility methods

// toSlice converts interface{} to []interface{}
func (bo *BulkOperation) toSlice(data interface{}) ([]interface{}, error) {
	value := reflect.ValueOf(data)
	if value.Kind() != reflect.Slice {
		return nil, fmt.Errorf("data must be a slice")
	}

	result := make([]interface{}, value.Len())
	for i := 0; i < value.Len(); i++ {
		result[i] = value.Index(i).Interface()
	}

	return result, nil
}

// toSnakeCase converts CamelCase to snake_case
func (bo *BulkOperation) toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// toCamelCase converts snake_case to CamelCase
func (bo *BulkOperation) toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, "")
}

// Bulk operations

// BulkInsertWithValidation performs bulk insert with validation and progress tracking
func (bo *BulkOperation) BulkInsertWithValidation(records []interface{}) (*BulkResult, error) {
	return bo.BulkInsert(records)
}

// Helper functions for creating upsert configurations

// NewUpsertConfig creates a new upsert configuration
func NewUpsertConfig(conflictColumns ...string) UpsertConfig {
	return UpsertConfig{
		ConflictColumns: conflictColumns,
		UpdateColumns:   make([]string, 0),
		UpdateValues:    make(map[string]interface{}),
	}
}

// WithUpdateColumns adds columns to update on conflict
func (uc UpsertConfig) WithUpdateColumns(columns ...string) UpsertConfig {
	uc.UpdateColumns = append(uc.UpdateColumns, columns...)
	return uc
}

// WithUpdateValues adds custom values to update on conflict
func (uc UpsertConfig) WithUpdateValues(values map[string]interface{}) UpsertConfig {
	if uc.UpdateValues == nil {
		uc.UpdateValues = make(map[string]interface{})
	}
	for key, value := range values {
		uc.UpdateValues[key] = value
	}
	return uc
}
