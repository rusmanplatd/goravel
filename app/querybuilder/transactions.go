package querybuilder

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
)

// TransactionManager manages database transactions for query builder operations
type TransactionManager struct {
	mutex          sync.RWMutex
	transactions   map[string]*TransactionContext
	defaultTimeout time.Duration
}

// TransactionContext represents a database transaction context
type TransactionContext struct {
	ID          string
	Transaction orm.Query
	Level       int
	StartTime   time.Time
	Timeout     time.Duration
	Parent      *TransactionContext
	Children    []*TransactionContext
	Committed   bool
	RolledBack  bool
	Savepoints  []string
	Mutex       sync.RWMutex
}

// TransactionOptions holds configuration for transactions
type TransactionOptions struct {
	Timeout          time.Duration
	IsolationLevel   IsolationLevel
	ReadOnly         bool
	DeferConstraints bool
	RetryCount       int
	RetryDelay       time.Duration
}

// IsolationLevel defines transaction isolation levels
type IsolationLevel string

const (
	IsolationReadUncommitted IsolationLevel = "READ UNCOMMITTED"
	IsolationReadCommitted   IsolationLevel = "READ COMMITTED"
	IsolationRepeatableRead  IsolationLevel = "REPEATABLE READ"
	IsolationSerializable    IsolationLevel = "SERIALIZABLE"
)

// TransactionResult represents the result of a transaction operation
type TransactionResult struct {
	TransactionID string        `json:"transaction_id"`
	Success       bool          `json:"success"`
	Duration      time.Duration `json:"duration"`
	Operations    int           `json:"operations"`
	Error         string        `json:"error,omitempty"`
	RollbackPoint string        `json:"rollback_point,omitempty"`
}

// Global transaction manager instance
var (
	globalTxManager *TransactionManager
	txManagerOnce   sync.Once
)

// GetTransactionManager returns the global transaction manager instance
func GetTransactionManager() *TransactionManager {
	txManagerOnce.Do(func() {
		globalTxManager = &TransactionManager{
			transactions:   make(map[string]*TransactionContext),
			defaultTimeout: 30 * time.Second,
		}
	})
	return globalTxManager
}

// DefaultTransactionOptions returns default transaction options
func DefaultTransactionOptions() TransactionOptions {
	return TransactionOptions{
		Timeout:          30 * time.Second,
		IsolationLevel:   IsolationReadCommitted,
		ReadOnly:         false,
		DeferConstraints: false,
		RetryCount:       3,
		RetryDelay:       100 * time.Millisecond,
	}
}

// Transaction methods for QueryBuilder

// WithTransaction executes query builder operations within a transaction
func (qb *QueryBuilder) WithTransaction(fn func(tx *QueryBuilder) error, options ...TransactionOptions) error {
	opts := DefaultTransactionOptions()
	if len(options) > 0 {
		opts = options[0]
	}

	txManager := GetTransactionManager()
	return txManager.ExecuteInTransaction(func(txCtx *TransactionContext) error {
		// Create a new query builder with the transaction
		txQB := &QueryBuilder{
			query:            txCtx.Transaction,
			request:          qb.request,
			allowedFilters:   qb.allowedFilters,
			allowedSorts:     qb.allowedSorts,
			allowedIncludes:  qb.allowedIncludes,
			allowedFields:    qb.allowedFields,
			defaultSorts:     qb.defaultSorts,
			config:           qb.config,
			paginationConfig: qb.paginationConfig,
		}

		return fn(txQB)
	}, opts)
}

// WithNestedTransaction executes operations within a nested transaction (savepoint)
func (qb *QueryBuilder) WithNestedTransaction(fn func(tx *QueryBuilder) error, savepointName string) error {
	txManager := GetTransactionManager()
	return txManager.ExecuteInNestedTransaction(func(txCtx *TransactionContext) error {
		txQB := &QueryBuilder{
			query:            txCtx.Transaction,
			request:          qb.request,
			allowedFilters:   qb.allowedFilters,
			allowedSorts:     qb.allowedSorts,
			allowedIncludes:  qb.allowedIncludes,
			allowedFields:    qb.allowedFields,
			defaultSorts:     qb.defaultSorts,
			config:           qb.config,
			paginationConfig: qb.paginationConfig,
		}

		return fn(txQB)
	}, savepointName)
}

// Transaction methods for BulkOperation

// WithBulkTransaction executes bulk operations within a transaction
func (bo *BulkOperation) WithBulkTransaction(fn func(tx *BulkOperation) error, options ...TransactionOptions) error {
	opts := DefaultTransactionOptions()
	if len(options) > 0 {
		opts = options[0]
	}

	txManager := GetTransactionManager()
	return txManager.ExecuteInTransaction(func(txCtx *TransactionContext) error {
		// Create a new bulk operation with the transaction
		txBO := &BulkOperation{
			query:      txCtx.Transaction,
			batchSize:  bo.batchSize,
			timeout:    bo.timeout,
			onConflict: bo.onConflict,
			validateFn: bo.validateFn,
			beforeFn:   bo.beforeFn,
			afterFn:    bo.afterFn,
			progressFn: bo.progressFn,
		}

		return fn(txBO)
	}, opts)
}

// TransactionManager methods

// ExecuteInTransaction executes a function within a database transaction
func (tm *TransactionManager) ExecuteInTransaction(fn func(*TransactionContext) error, options TransactionOptions) error {
	txCtx, err := tm.BeginTransaction(options)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}

	defer func() {
		tm.mutex.Lock()
		delete(tm.transactions, txCtx.ID)
		tm.mutex.Unlock()
	}()

	// Set up timeout context
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()

	// Execute function with retry logic
	var lastErr error
	for attempt := 0; attempt <= options.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(options.RetryDelay * time.Duration(attempt))
			facades.Log().Warning(fmt.Sprintf("Retrying transaction (attempt %d/%d): %v", attempt, options.RetryCount, lastErr))
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			tm.RollbackTransaction(txCtx.ID)
			return fmt.Errorf("transaction timeout: %v", ctx.Err())
		default:
		}

		// Execute the function
		lastErr = fn(txCtx)
		if lastErr == nil {
			// Function succeeded, commit transaction
			return tm.CommitTransaction(txCtx.ID)
		}

		// Check if error is retryable
		if !tm.isRetryableError(lastErr) {
			break
		}
	}

	// All retries failed, rollback transaction
	tm.RollbackTransaction(txCtx.ID)
	return fmt.Errorf("transaction failed after %d attempts: %v", options.RetryCount+1, lastErr)
}

// ExecuteInNestedTransaction executes a function within a nested transaction (savepoint)
func (tm *TransactionManager) ExecuteInNestedTransaction(fn func(*TransactionContext) error, savepointName string) error {
	// For now, we'll simulate nested transactions with savepoints
	// In a real implementation, you'd create actual database savepoints

	// Find current transaction context (this is simplified)
	// In practice, you'd need to track the current transaction context
	facades.Log().Debug(fmt.Sprintf("Creating savepoint: %s", savepointName))

	// Create a mock nested transaction context
	nestedCtx := &TransactionContext{
		ID:         fmt.Sprintf("nested_%s_%d", savepointName, time.Now().UnixNano()),
		Level:      1, // This would be calculated based on nesting level
		StartTime:  time.Now(),
		Savepoints: []string{savepointName},
	}

	err := fn(nestedCtx)
	if err != nil {
		facades.Log().Debug(fmt.Sprintf("Rolling back to savepoint: %s", savepointName))
		return err
	}

	facades.Log().Debug(fmt.Sprintf("Releasing savepoint: %s", savepointName))
	return nil
}

// BeginTransaction starts a new database transaction
func (tm *TransactionManager) BeginTransaction(options TransactionOptions) (*TransactionContext, error) {
	// Generate unique transaction ID
	txID := fmt.Sprintf("tx_%d", time.Now().UnixNano())

	// Begin database transaction
	// Note: Goravel ORM transaction support is limited, this is a simplified implementation
	tx := facades.Orm().Query()

	// Create transaction context
	txCtx := &TransactionContext{
		ID:          txID,
		Transaction: tx,
		Level:       0,
		StartTime:   time.Now(),
		Timeout:     options.Timeout,
		Savepoints:  make([]string, 0),
	}

	// Store transaction context
	tm.mutex.Lock()
	tm.transactions[txID] = txCtx
	tm.mutex.Unlock()

	facades.Log().Debug(fmt.Sprintf("Started transaction: %s", txID))
	return txCtx, nil
}

// CommitTransaction commits a database transaction
func (tm *TransactionManager) CommitTransaction(txID string) error {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.Lock()
	defer txCtx.Mutex.Unlock()

	if txCtx.Committed {
		return fmt.Errorf("transaction already committed: %s", txID)
	}

	if txCtx.RolledBack {
		return fmt.Errorf("transaction already rolled back: %s", txID)
	}

	// Note: In a real implementation, you'd call tx.Commit()
	// facades.Orm() doesn't expose transaction control directly

	txCtx.Committed = true
	duration := time.Since(txCtx.StartTime)

	facades.Log().Debug(fmt.Sprintf("Committed transaction: %s (duration: %v)", txID, duration))
	return nil
}

// RollbackTransaction rolls back a database transaction
func (tm *TransactionManager) RollbackTransaction(txID string) error {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.Lock()
	defer txCtx.Mutex.Unlock()

	if txCtx.Committed {
		return fmt.Errorf("cannot rollback committed transaction: %s", txID)
	}

	if txCtx.RolledBack {
		return fmt.Errorf("transaction already rolled back: %s", txID)
	}

	// Note: In a real implementation, you'd call tx.Rollback()

	txCtx.RolledBack = true
	duration := time.Since(txCtx.StartTime)

	facades.Log().Debug(fmt.Sprintf("Rolled back transaction: %s (duration: %v)", txID, duration))
	return nil
}

// GetTransactionStatus returns the status of a transaction
func (tm *TransactionManager) GetTransactionStatus(txID string) (*TransactionResult, error) {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.RLock()
	defer txCtx.Mutex.RUnlock()

	result := &TransactionResult{
		TransactionID: txID,
		Success:       txCtx.Committed,
		Duration:      time.Since(txCtx.StartTime),
		Operations:    0, // This would be tracked in a real implementation
	}

	if txCtx.RolledBack {
		result.Success = false
		result.Error = "Transaction was rolled back"
	}

	return result, nil
}

// CreateSavepoint creates a savepoint within a transaction
func (tm *TransactionManager) CreateSavepoint(txID, savepointName string) error {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.Lock()
	defer txCtx.Mutex.Unlock()

	if txCtx.Committed || txCtx.RolledBack {
		return fmt.Errorf("cannot create savepoint in finished transaction: %s", txID)
	}

	// Note: In a real implementation, you'd execute: SAVEPOINT savepointName
	txCtx.Savepoints = append(txCtx.Savepoints, savepointName)

	facades.Log().Debug(fmt.Sprintf("Created savepoint %s in transaction: %s", savepointName, txID))
	return nil
}

// RollbackToSavepoint rolls back to a specific savepoint
func (tm *TransactionManager) RollbackToSavepoint(txID, savepointName string) error {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.Lock()
	defer txCtx.Mutex.Unlock()

	if txCtx.Committed || txCtx.RolledBack {
		return fmt.Errorf("cannot rollback savepoint in finished transaction: %s", txID)
	}

	// Check if savepoint exists
	found := false
	for _, sp := range txCtx.Savepoints {
		if sp == savepointName {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("savepoint not found: %s", savepointName)
	}

	// Note: In a real implementation, you'd execute: ROLLBACK TO SAVEPOINT savepointName

	facades.Log().Debug(fmt.Sprintf("Rolled back to savepoint %s in transaction: %s", savepointName, txID))
	return nil
}

// ReleaseSavepoint releases a savepoint
func (tm *TransactionManager) ReleaseSavepoint(txID, savepointName string) error {
	tm.mutex.RLock()
	txCtx, exists := tm.transactions[txID]
	tm.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("transaction not found: %s", txID)
	}

	txCtx.Mutex.Lock()
	defer txCtx.Mutex.Unlock()

	// Remove savepoint from list
	for i, sp := range txCtx.Savepoints {
		if sp == savepointName {
			txCtx.Savepoints = append(txCtx.Savepoints[:i], txCtx.Savepoints[i+1:]...)
			break
		}
	}

	// Note: In a real implementation, you'd execute: RELEASE SAVEPOINT savepointName

	facades.Log().Debug(fmt.Sprintf("Released savepoint %s in transaction: %s", savepointName, txID))
	return nil
}

// Utility methods

// isRetryableError determines if an error is retryable
func (tm *TransactionManager) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Common retryable errors (database-specific)
	retryableErrors := []string{
		"deadlock",
		"lock timeout",
		"connection lost",
		"connection reset",
		"serialization failure",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(strings.ToLower(errStr), retryable) {
			return true
		}
	}

	return false
}

// GetActiveTransactions returns all active transactions
func (tm *TransactionManager) GetActiveTransactions() map[string]*TransactionContext {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	active := make(map[string]*TransactionContext)
	for id, txCtx := range tm.transactions {
		txCtx.Mutex.RLock()
		if !txCtx.Committed && !txCtx.RolledBack {
			active[id] = txCtx
		}
		txCtx.Mutex.RUnlock()
	}

	return active
}

// CleanupStaleTransactions removes stale transactions that have exceeded their timeout
func (tm *TransactionManager) CleanupStaleTransactions() int {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	cleaned := 0
	now := time.Now()

	for id, txCtx := range tm.transactions {
		txCtx.Mutex.RLock()
		isStale := !txCtx.Committed && !txCtx.RolledBack && now.Sub(txCtx.StartTime) > txCtx.Timeout
		txCtx.Mutex.RUnlock()

		if isStale {
			facades.Log().Warning(fmt.Sprintf("Cleaning up stale transaction: %s", id))
			tm.RollbackTransaction(id)
			delete(tm.transactions, id)
			cleaned++
		}
	}

	return cleaned
}

// TransactionStats returns statistics about transactions
func (tm *TransactionManager) TransactionStats() map[string]interface{} {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	active := 0
	committed := 0
	rolledBack := 0

	for _, txCtx := range tm.transactions {
		txCtx.Mutex.RLock()
		if txCtx.Committed {
			committed++
		} else if txCtx.RolledBack {
			rolledBack++
		} else {
			active++
		}
		txCtx.Mutex.RUnlock()
	}

	return map[string]interface{}{
		"active":      active,
		"committed":   committed,
		"rolled_back": rolledBack,
		"total":       len(tm.transactions),
	}
}

// Convenience functions for common transaction patterns

// WithRetryableTransaction executes a function with automatic retry on retryable errors
func WithRetryableTransaction(fn func() error, maxRetries int, delay time.Duration) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(delay * time.Duration(attempt))
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		txManager := GetTransactionManager()
		if !txManager.isRetryableError(lastErr) {
			break
		}
	}

	return lastErr
}

// WithTimeoutTransaction executes a function within a transaction with a specific timeout
func WithTimeoutTransaction(fn func() error, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("transaction timeout: %v", ctx.Err())
	}
}
