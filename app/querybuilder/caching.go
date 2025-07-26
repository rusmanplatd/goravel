package querybuilder

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
)

// CacheStrategy defines different caching strategies
type CacheStrategy string

const (
	CacheStrategyLRU          CacheStrategy = "lru"
	CacheStrategyLFU          CacheStrategy = "lfu"
	CacheStrategyTTL          CacheStrategy = "ttl"
	CacheStrategyWriteThrough CacheStrategy = "write_through"
	CacheStrategyWriteBack    CacheStrategy = "write_back"
	CacheStrategyReadThrough  CacheStrategy = "read_through"
)

// CacheBackend defines different cache backend types
type CacheBackend string

const (
	CacheBackendMemory CacheBackend = "memory"
	CacheBackendRedis  CacheBackend = "redis"
	CacheBackendFile   CacheBackend = "file"
)

// CacheConfig holds configuration for caching
type CacheConfig struct {
	Backend              CacheBackend
	Strategy             CacheStrategy
	DefaultTTL           time.Duration
	MaxSize              int64
	MaxMemory            int64 // bytes
	KeyPrefix            string
	EnableMetrics        bool
	EnableTagging        bool
	EnableCompression    bool
	CompressionThreshold int64 // bytes

	// Redis specific
	RedisHost     string
	RedisPort     int
	RedisPassword string
	RedisDB       int

	// File cache specific
	CacheDir       string
	FilePermission int
}

// CacheEntry represents a cache entry
type CacheEntry struct {
	Key         string                 `json:"key"`
	Value       interface{}            `json:"value"`
	Tags        []string               `json:"tags,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	AccessCount int64                  `json:"access_count"`
	LastAccess  time.Time              `json:"last_access"`
	Size        int64                  `json:"size"`
	Compressed  bool                   `json:"compressed,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CacheMetrics holds cache performance metrics
type CacheMetrics struct {
	Hits           int64         `json:"hits"`
	Misses         int64         `json:"misses"`
	Sets           int64         `json:"sets"`
	Deletes        int64         `json:"deletes"`
	Evictions      int64         `json:"evictions"`
	Size           int64         `json:"size"`
	Memory         int64         `json:"memory"`
	AverageLatency time.Duration `json:"average_latency"`
	totalLatency   time.Duration
	mutex          sync.RWMutex
}

// Cache provides caching capabilities
type Cache struct {
	config   *CacheConfig
	backend  CacheBackendInterface
	metrics  *CacheMetrics
	tags     map[string][]string // tag -> keys mapping
	tagMutex sync.RWMutex
}

// CacheBackendInterface defines the interface for cache backends
type CacheBackendInterface interface {
	Get(key string) (*CacheEntry, error)
	Set(key string, entry *CacheEntry) error
	Delete(key string) error
	Exists(key string) bool
	Clear() error
	Keys(pattern string) ([]string, error)
	Size() int64
	Close() error
}

// CacheOptions holds options for cache operations
type CacheOptions struct {
	TTL        time.Duration
	Tags       []string
	Compress   bool
	Invalidate []string
}

// MemoryCacheBackend implements in-memory caching
type MemoryCacheBackend struct {
	data  map[string]*CacheEntry
	mutex sync.RWMutex
}

// RedisCacheBackend implements Redis-based caching (placeholder)
type RedisCacheBackend struct {
	config *CacheConfig
}

// FileCacheBackend implements file-based caching (placeholder)
type FileCacheBackend struct {
	config *CacheConfig
}

// Global cache instance
var (
	globalCache   *Cache
	cacheInitOnce sync.Once
)

// GetCache returns the global cache instance
func GetCache() *Cache {
	cacheInitOnce.Do(func() {
		config := DefaultCacheConfig()
		globalCache = NewCache(config)
	})
	return globalCache
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		Backend:              CacheBackendMemory,
		Strategy:             CacheStrategyLRU,
		DefaultTTL:           10 * time.Minute,
		MaxSize:              1000,
		MaxMemory:            100 * 1024 * 1024, // 100MB
		KeyPrefix:            "qb_",
		EnableMetrics:        true,
		EnableTagging:        true,
		EnableCompression:    false,
		CompressionThreshold: 1024, // 1KB
	}
}

// NewCache creates a new cache instance
func NewCache(config *CacheConfig) *Cache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	cache := &Cache{
		config:  config,
		metrics: &CacheMetrics{},
		tags:    make(map[string][]string),
	}

	// Initialize backend based on configuration
	switch config.Backend {
	case CacheBackendRedis:
		cache.backend = newRedisBackend(config)
	case CacheBackendFile:
		cache.backend = newFileBackend(config)
	default:
		cache.backend = newMemoryBackend(config)
	}

	return cache
}

// Caching methods for QueryBuilder

// WithCache enables caching for the query builder
func (qb *QueryBuilder) WithCache(config *CacheConfig) *QueryBuilder {
	if config == nil {
		config = DefaultCacheConfig()
	}
	qb.cache = NewCache(config)
	return qb
}

// GetWithCache executes the query with caching
func (qb *QueryBuilder) GetWithCache(dest interface{}, options CacheOptions) error {
	if qb.cache == nil {
		return qb.Get(dest)
	}

	// Generate cache key
	cacheKey := qb.generateCacheKey()

	// Try to get from cache first
	if cached := qb.cache.Get(cacheKey); cached != nil {
		// Copy cached data to destination
		if err := copyCachedData(cached.Value, dest); err == nil {
			qb.cache.metrics.recordHit()
			return nil
		}
	}

	// Cache miss - execute query
	qb.cache.metrics.recordMiss()
	err := qb.Get(dest)
	if err != nil {
		return err
	}

	// Store result in cache
	qb.cache.Set(cacheKey, dest, options)
	return nil
}

// Cache implementation

// Get retrieves a value from the cache
func (c *Cache) Get(key string) *CacheEntry {
	c.metrics.mutex.Lock()
	defer c.metrics.mutex.Unlock()

	entry, err := c.backend.Get(key)
	if err != nil || entry == nil {
		c.metrics.Misses++
		return nil
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		c.backend.Delete(key)
		c.metrics.Misses++
		return nil
	}

	// Update access info
	entry.AccessCount++
	entry.LastAccess = time.Now()
	c.backend.Set(key, entry) // Update the entry

	c.metrics.Hits++
	return entry
}

// Set stores a value in the cache
func (c *Cache) Set(key string, value interface{}, options CacheOptions) error {
	startTime := time.Now()
	defer func() {
		if c.config.EnableMetrics {
			c.metrics.recordLatency(time.Since(startTime))
		}
	}()

	fullKey := c.config.KeyPrefix + key
	now := time.Now()

	ttl := options.TTL
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	// Serialize value
	serialized, err := json.Marshal(value)
	if err != nil {
		return err
	}

	// Compress if enabled and threshold met
	compressed := false
	if c.config.EnableCompression && options.Compress && int64(len(serialized)) > c.config.CompressionThreshold {
		// In a real implementation, you'd compress the data here
		compressed = true
	}

	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		Tags:        options.Tags,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		AccessCount: 0,
		LastAccess:  now,
		Size:        int64(len(serialized)),
		Compressed:  compressed,
		Metadata:    make(map[string]interface{}),
	}

	// Store in backend
	err = c.backend.Set(fullKey, entry)
	if err != nil {
		return err
	}

	// Update tag mappings
	if c.config.EnableTagging && len(options.Tags) > 0 {
		c.updateTagMappings(key, options.Tags)
	}

	// Invalidate specified patterns
	for _, pattern := range options.Invalidate {
		c.InvalidateByPattern(pattern)
	}

	if c.config.EnableMetrics {
		c.metrics.recordSet()
	}

	return nil
}

// Delete removes a value from the cache
func (c *Cache) Delete(key string) error {
	fullKey := c.config.KeyPrefix + key
	err := c.backend.Delete(fullKey)

	if err == nil && c.config.EnableMetrics {
		c.metrics.recordDelete()
	}

	// Remove from tag mappings
	if c.config.EnableTagging {
		c.removeFromTagMappings(key)
	}

	return err
}

// InvalidateByPattern invalidates cache entries matching a pattern
func (c *Cache) InvalidateByPattern(pattern string) error {
	fullPattern := c.config.KeyPrefix + pattern
	keys, err := c.backend.Keys(fullPattern)
	if err != nil {
		return err
	}

	for _, key := range keys {
		c.backend.Delete(key)
	}

	if c.config.EnableMetrics {
		c.metrics.recordEvictions(int64(len(keys)))
	}

	return nil
}

// InvalidateByTags invalidates cache entries with specific tags
func (c *Cache) InvalidateByTags(tags ...string) error {
	if !c.config.EnableTagging {
		return fmt.Errorf("tagging is not enabled")
	}

	c.tagMutex.RLock()
	keysToDelete := make(map[string]bool)

	for _, tag := range tags {
		if keys, exists := c.tags[tag]; exists {
			for _, key := range keys {
				keysToDelete[key] = true
			}
		}
	}
	c.tagMutex.RUnlock()

	// Delete the keys
	for key := range keysToDelete {
		c.Delete(key)
	}

	return nil
}

// GetMetrics returns cache metrics
func (c *Cache) GetMetrics() CacheMetrics {
	c.metrics.mutex.RLock()
	defer c.metrics.mutex.RUnlock()

	return CacheMetrics{
		Hits:           c.metrics.Hits,
		Misses:         c.metrics.Misses,
		Sets:           c.metrics.Sets,
		Deletes:        c.metrics.Deletes,
		Evictions:      c.metrics.Evictions,
		Size:           c.backend.Size(),
		AverageLatency: c.metrics.AverageLatency,
	}
}

// updateTagMappings updates tag to key mappings
func (c *Cache) updateTagMappings(key string, tags []string) {
	c.tagMutex.Lock()
	defer c.tagMutex.Unlock()

	for _, tag := range tags {
		if _, exists := c.tags[tag]; !exists {
			c.tags[tag] = make([]string, 0)
		}

		// Check if key already exists for this tag
		found := false
		for _, existingKey := range c.tags[tag] {
			if existingKey == key {
				found = true
				break
			}
		}

		if !found {
			c.tags[tag] = append(c.tags[tag], key)
		}
	}
}

// removeFromTagMappings removes key from tag mappings
func (c *Cache) removeFromTagMappings(key string) {
	c.tagMutex.Lock()
	defer c.tagMutex.Unlock()

	for tag, keys := range c.tags {
		for i, k := range keys {
			if k == key {
				c.tags[tag] = append(keys[:i], keys[i+1:]...)
				break
			}
		}

		// Remove empty tag entries
		if len(c.tags[tag]) == 0 {
			delete(c.tags, tag)
		}
	}
}

// generateCacheKey generates a cache key with features
func (qb *QueryBuilder) generateCacheKey() string {
	// Create a hash of the query parameters
	data := map[string]interface{}{
		"filters":    qb.allowedFilters,
		"sorts":      qb.allowedSorts,
		"includes":   qb.allowedIncludes,
		"fields":     qb.allowedFields,
		"aggregates": qb.aggregates,
		"joins":      qb.joins,
	}

	jsonData, _ := json.Marshal(data)
	hash := md5.Sum(jsonData)
	return fmt.Sprintf("qb_%x", hash)
}

// Helper functions for caching

// copyCachedData copies cached data to the destination
func copyCachedData(source, dest interface{}) error {
	// Simple implementation using JSON marshal/unmarshal
	data, err := json.Marshal(source)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

// calculateDataSize calculates the approximate size of data
func calculateDataSize(data interface{}) int64 {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return 0
	}
	return int64(len(jsonData))
}

// CacheMetrics methods

// recordLatency records the latency of a cache operation
func (cm *CacheMetrics) recordLatency(duration time.Duration) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.totalLatency += duration
	operations := cm.Hits + cm.Misses + cm.Sets + cm.Deletes
	if operations > 0 {
		cm.AverageLatency = cm.totalLatency / time.Duration(operations)
	}
}

// recordSet records a cache set operation
func (cm *CacheMetrics) recordSet() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.Sets++
}

// recordDelete records a cache delete operation
func (cm *CacheMetrics) recordDelete() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.Deletes++
}

// recordEvictions records cache evictions
func (cm *CacheMetrics) recordEvictions(count int64) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.Evictions += count
}

// recordHit records a cache hit
func (cm *CacheMetrics) recordHit() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.Hits++
}

// recordMiss records a cache miss
func (cm *CacheMetrics) recordMiss() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.Misses++
}

// Backend implementations

// Get retrieves an entry from memory cache
func (m *MemoryCacheBackend) Get(key string) (*CacheEntry, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entry, exists := m.data[key]
	if !exists {
		return nil, nil
	}

	return entry, nil
}

// Set stores an entry in memory cache
func (m *MemoryCacheBackend) Set(key string, entry *CacheEntry) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data[key] = entry
	return nil
}

// Delete removes an entry from memory cache
func (m *MemoryCacheBackend) Delete(key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.data, key)
	return nil
}

// Exists checks if a key exists in memory cache
func (m *MemoryCacheBackend) Exists(key string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	_, exists := m.data[key]
	return exists
}

// Keys returns all keys matching a pattern
func (m *MemoryCacheBackend) Keys(pattern string) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	keys := make([]string, 0)
	for key := range m.data {
		// Simple pattern matching - in production, use proper regex
		if strings.Contains(key, strings.Replace(pattern, "*", "", -1)) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Size returns the number of entries in the cache
func (m *MemoryCacheBackend) Size() int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return int64(len(m.data))
}

// Clear removes all entries from the cache
func (m *MemoryCacheBackend) Clear() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.data = make(map[string]*CacheEntry)
	return nil
}

// Close closes the memory cache backend
func (m *MemoryCacheBackend) Close() error {
	return m.Clear()
}

// Redis backend methods (placeholder implementations)

// Get retrieves an entry from Redis cache
func (r *RedisCacheBackend) Get(key string) (*CacheEntry, error) {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return nil, nil
}

// Set stores an entry in Redis cache
func (r *RedisCacheBackend) Set(key string, entry *CacheEntry) error {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return nil
}

// Delete removes an entry from Redis cache
func (r *RedisCacheBackend) Delete(key string) error {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return nil
}

// Exists checks if a key exists in Redis cache
func (r *RedisCacheBackend) Exists(key string) bool {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return false
}

// Keys returns all keys matching a pattern from Redis
func (r *RedisCacheBackend) Keys(pattern string) ([]string, error) {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return make([]string, 0), nil
}

// Size returns the number of entries in Redis cache
func (r *RedisCacheBackend) Size() int64 {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return 0
}

// Clear removes all entries from Redis cache
func (r *RedisCacheBackend) Clear() error {
	facades.Log().Warning("Redis cache backend not fully implemented")
	return nil
}

// Close closes the Redis cache backend
func (r *RedisCacheBackend) Close() error {
	return nil
}

// File backend methods (placeholder implementations)

// Get retrieves an entry from file cache
func (f *FileCacheBackend) Get(key string) (*CacheEntry, error) {
	facades.Log().Warning("File cache backend not fully implemented")
	return nil, nil
}

// Set stores an entry in file cache
func (f *FileCacheBackend) Set(key string, entry *CacheEntry) error {
	facades.Log().Warning("File cache backend not fully implemented")
	return nil
}

// Delete removes an entry from file cache
func (f *FileCacheBackend) Delete(key string) error {
	facades.Log().Warning("File cache backend not fully implemented")
	return nil
}

// Exists checks if a key exists in file cache
func (f *FileCacheBackend) Exists(key string) bool {
	facades.Log().Warning("File cache backend not fully implemented")
	return false
}

// Keys returns all keys matching a pattern from file cache
func (f *FileCacheBackend) Keys(pattern string) ([]string, error) {
	facades.Log().Warning("File cache backend not fully implemented")
	return make([]string, 0), nil
}

// Size returns the number of entries in file cache
func (f *FileCacheBackend) Size() int64 {
	facades.Log().Warning("File cache backend not fully implemented")
	return 0
}

// Clear removes all entries from file cache
func (f *FileCacheBackend) Clear() error {
	facades.Log().Warning("File cache backend not fully implemented")
	return nil
}

// Close closes the file cache backend
func (f *FileCacheBackend) Close() error {
	return nil
}

// Constructor functions

// newMemoryBackend creates a new memory cache backend
func newMemoryBackend(config *CacheConfig) *MemoryCacheBackend {
	return &MemoryCacheBackend{
		data: make(map[string]*CacheEntry),
	}
}

// newRedisBackend creates a new Redis cache backend
func newRedisBackend(config *CacheConfig) *RedisCacheBackend {
	return &RedisCacheBackend{
		config: config,
	}
}

// newFileBackend creates a new file cache backend
func newFileBackend(config *CacheConfig) *FileCacheBackend {
	return &FileCacheBackend{
		config: config,
	}
}

// GetCacheStats returns cache statistics
func GetCacheStats() map[string]interface{} {
	if performanceCache == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return map[string]interface{}{
		"enabled": true,
		"type":    "querybuilder_cache",
	}
}
