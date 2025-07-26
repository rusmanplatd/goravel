package querybuilder

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
)

// QueryMetrics holds performance metrics for queries
type QueryMetrics struct {
	TotalQueries     int64
	CacheHits        int64
	CacheMisses      int64
	AverageQueryTime time.Duration
	SlowQueries      int64
	OptimizedQueries int64
	totalQueryTime   time.Duration
	mutex            sync.RWMutex
}

// QueryCache represents a simple in-memory cache for query results
type QueryCache struct {
	data   map[string]PerformanceCacheEntry
	mutex  sync.RWMutex
	maxAge time.Duration
}

// PerformanceCacheEntry represents a performance cache entry
type PerformanceCacheEntry struct {
	Data      interface{}
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PerformanceConfig holds configuration for performance monitoring
type PerformanceConfig struct {
	EnableMetrics      bool
	EnableCaching      bool
	EnableOptimization bool
	CacheMaxAge        time.Duration
	SlowQueryThreshold time.Duration
	MaxCacheSize       int
	OptimizeThreshold  time.Duration
}

// QueryOptimization holds query optimization suggestions
type QueryOptimization struct {
	QueryHash     string
	Suggestions   []string
	EstimatedGain time.Duration
	Applied       bool
}

var (
	globalMetrics     *QueryMetrics
	performanceCache  *QueryCache
	performanceConfig *PerformanceConfig
	optimizations     map[string]*QueryOptimization
	initOnce          sync.Once
	optimizationMutex sync.RWMutex
)

// InitPerformanceMonitoring initializes the performance monitoring system
func InitPerformanceMonitoring(config *PerformanceConfig) {
	initOnce.Do(func() {
		if config == nil {
			config = DefaultPerformanceConfig()
		}

		performanceConfig = config
		globalMetrics = &QueryMetrics{}
		optimizations = make(map[string]*QueryOptimization)

		if config.EnableCaching {
			performanceCache = &QueryCache{
				data:   make(map[string]PerformanceCacheEntry),
				maxAge: config.CacheMaxAge,
			}
		}
	})
}

// DefaultPerformanceConfig returns default performance configuration
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		EnableMetrics:      true,
		EnableCaching:      true,
		EnableOptimization: true,
		CacheMaxAge:        5 * time.Minute,
		SlowQueryThreshold: 1 * time.Second,
		OptimizeThreshold:  500 * time.Millisecond,
		MaxCacheSize:       1000,
	}
}

// QueryWithMetrics executes a query with performance monitoring
func (qb *QueryBuilder) QueryWithMetrics(dest interface{}) error {
	if performanceConfig == nil || !performanceConfig.EnableMetrics {
		return qb.Get(dest)
	}

	startTime := time.Now()
	queryHash := qb.generateQueryHash()

	defer func() {
		duration := time.Since(startTime)
		recordQueryMetrics(duration)

		// Check for optimization opportunities
		if performanceConfig.EnableOptimization && duration > performanceConfig.OptimizeThreshold {
			qb.analyzeForOptimization(queryHash, duration)
		}
	}()

	// Try cache first if enabled
	if performanceConfig.EnableCaching && performanceCache != nil {
		cacheKey := qb.generatePerformanceCacheKey()
		if cachedResult := performanceCache.Get(cacheKey); cachedResult != nil {
			globalMetrics.recordCacheHit()
			return copyCachedData(cachedResult.Data, dest)
		}
	}

	// Execute query
	globalMetrics.recordCacheMiss()
	err := qb.Get(dest)

	// Cache result if successful
	if err == nil && performanceConfig.EnableCaching && performanceCache != nil {
		cacheKey := qb.generatePerformanceCacheKey()
		performanceCache.Set(cacheKey, dest)
	}

	return err
}

// GetMetrics returns current performance metrics
func GetMetrics() *QueryMetrics {
	if globalMetrics == nil {
		return &QueryMetrics{}
	}

	globalMetrics.mutex.RLock()
	defer globalMetrics.mutex.RUnlock()

	return &QueryMetrics{
		TotalQueries:     globalMetrics.TotalQueries,
		CacheHits:        globalMetrics.CacheHits,
		CacheMisses:      globalMetrics.CacheMisses,
		AverageQueryTime: globalMetrics.AverageQueryTime,
		SlowQueries:      globalMetrics.SlowQueries,
		OptimizedQueries: globalMetrics.OptimizedQueries,
	}
}

// GetOptimizations returns query optimization suggestions
func GetOptimizations() map[string]*QueryOptimization {
	optimizationMutex.RLock()
	defer optimizationMutex.RUnlock()

	result := make(map[string]*QueryOptimization)
	for k, v := range optimizations {
		result[k] = v
	}
	return result
}

// ApplyOptimization applies an optimization suggestion
func (qb *QueryBuilder) ApplyOptimization(queryHash string) error {
	optimizationMutex.Lock()
	defer optimizationMutex.Unlock()

	opt, exists := optimizations[queryHash]
	if !exists {
		return fmt.Errorf("optimization not found for query hash: %s", queryHash)
	}

	// Apply optimization suggestions
	for _, suggestion := range opt.Suggestions {
		switch suggestion {
		case "add_index":
			facades.Log().Info(fmt.Sprintf("Suggestion: Add database index for query %s", queryHash))
		case "use_cursor_pagination":
			// This would be applied at query building time
			facades.Log().Info(fmt.Sprintf("Suggestion: Use cursor pagination for query %s", queryHash))
		case "limit_joins":
			facades.Log().Info(fmt.Sprintf("Suggestion: Limit joins for query %s", queryHash))
		case "add_caching":
			// Enable caching for this query pattern
			facades.Log().Info(fmt.Sprintf("Suggestion: Add caching for query %s", queryHash))
		}
	}

	opt.Applied = true
	globalMetrics.mutex.Lock()
	globalMetrics.OptimizedQueries++
	globalMetrics.mutex.Unlock()

	return nil
}

// Private helper methods

// recordQueryMetrics records metrics for a query execution
func recordQueryMetrics(duration time.Duration) {
	if globalMetrics == nil {
		return
	}

	globalMetrics.mutex.Lock()
	defer globalMetrics.mutex.Unlock()

	globalMetrics.TotalQueries++
	globalMetrics.totalQueryTime += duration
	globalMetrics.AverageQueryTime = globalMetrics.totalQueryTime / time.Duration(globalMetrics.TotalQueries)

	if performanceConfig != nil && duration > performanceConfig.SlowQueryThreshold {
		globalMetrics.SlowQueries++
	}
}

// recordCacheHit records a cache hit
func (qm *QueryMetrics) recordCacheHit() {
	qm.mutex.Lock()
	defer qm.mutex.Unlock()
	qm.CacheHits++
}

// recordCacheMiss records a cache miss
func (qm *QueryMetrics) recordCacheMiss() {
	qm.mutex.Lock()
	defer qm.mutex.Unlock()
	qm.CacheMisses++
}

// generateQueryHash generates a hash for the current query
func (qb *QueryBuilder) generateQueryHash() string {
	data := map[string]interface{}{
		"filters":    len(qb.allowedFilters),
		"sorts":      len(qb.allowedSorts),
		"includes":   len(qb.allowedIncludes),
		"aggregates": len(qb.aggregates),
		"joins":      len(qb.joins),
	}

	jsonData, _ := json.Marshal(data)
	hash := md5.Sum(jsonData)
	return fmt.Sprintf("%x", hash)
}

// generatePerformanceCacheKey generates a cache key for performance caching
func (qb *QueryBuilder) generatePerformanceCacheKey() string {
	return "perf_" + qb.generateQueryHash()
}

// analyzeForOptimization analyzes a query for optimization opportunities
func (qb *QueryBuilder) analyzeForOptimization(queryHash string, duration time.Duration) {
	optimizationMutex.Lock()
	defer optimizationMutex.Unlock()

	// Skip if already analyzed
	if _, exists := optimizations[queryHash]; exists {
		return
	}

	suggestions := make([]string, 0)
	estimatedGain := time.Duration(0)

	// Analyze query characteristics
	if len(qb.joins) > 3 {
		suggestions = append(suggestions, "limit_joins")
		estimatedGain += duration / 4
	}

	if len(qb.allowedFilters) > 10 {
		suggestions = append(suggestions, "add_index")
		estimatedGain += duration / 3
	}

	if duration > 2*time.Second {
		suggestions = append(suggestions, "use_cursor_pagination")
		estimatedGain += duration / 2
	}

	if !performanceConfig.EnableCaching {
		suggestions = append(suggestions, "add_caching")
		estimatedGain += duration / 5
	}

	if len(suggestions) > 0 {
		optimizations[queryHash] = &QueryOptimization{
			QueryHash:     queryHash,
			Suggestions:   suggestions,
			EstimatedGain: estimatedGain,
			Applied:       false,
		}
	}
}

// Cache implementation for performance monitoring

// Get retrieves a value from the performance cache
func (qc *QueryCache) Get(key string) *PerformanceCacheEntry {
	qc.mutex.RLock()
	defer qc.mutex.RUnlock()

	entry, exists := qc.data[key]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		delete(qc.data, key)
		return nil
	}

	return &entry
}

// Set stores a value in the performance cache
func (qc *QueryCache) Set(key string, value interface{}) {
	qc.mutex.Lock()
	defer qc.mutex.Unlock()

	// Remove oldest entries if cache is full
	if len(qc.data) >= performanceConfig.MaxCacheSize {
		qc.evictOldest()
	}

	qc.data[key] = PerformanceCacheEntry{
		Data:      value,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(qc.maxAge),
	}
}

// evictOldest removes the oldest cache entry
func (qc *QueryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range qc.data {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(qc.data, oldestKey)
	}
}

// ResetMetrics resets all performance metrics
func ResetMetrics() {
	if globalMetrics != nil {
		globalMetrics.mutex.Lock()
		defer globalMetrics.mutex.Unlock()

		globalMetrics.TotalQueries = 0
		globalMetrics.CacheHits = 0
		globalMetrics.CacheMisses = 0
		globalMetrics.AverageQueryTime = 0
		globalMetrics.SlowQueries = 0
		globalMetrics.OptimizedQueries = 0
		globalMetrics.totalQueryTime = 0
	}

	optimizationMutex.Lock()
	defer optimizationMutex.Unlock()
	optimizations = make(map[string]*QueryOptimization)
}
