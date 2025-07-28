package services

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// VaultCache provides caching for Vault keys and data
type VaultCache struct {
	cache map[string]*VaultCacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

// VaultCacheEntry represents a cached item
type VaultCacheEntry struct {
	Data        []byte
	ExpiresAt   time.Time
	AccessCount int64
	LastAccess  time.Time
}

// NewVaultCache creates a new cache instance
func NewVaultCache(ttl time.Duration) *VaultCache {
	cache := &VaultCache{
		cache: make(map[string]*VaultCacheEntry),
		ttl:   ttl,
	}

	// Start cleanup routine
	go cache.startCleanup()

	return cache
}

// Get retrieves data from cache
func (vc *VaultCache) Get(key string) ([]byte, bool) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	entry, exists := vc.cache[key]
	if !exists {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		// Don't delete here to avoid deadlock, cleanup will handle it
		return nil, false
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccess = time.Now()

	safeLog("debug", "Cache hit for key", map[string]interface{}{
		"key_hash":     vc.hashKey(key),
		"access_count": entry.AccessCount,
	})

	return entry.Data, true
}

// Set stores data in cache
func (vc *VaultCache) Set(key string, data []byte) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.cache[key] = &VaultCacheEntry{
		Data:        data,
		ExpiresAt:   time.Now().Add(vc.ttl),
		AccessCount: 0,
		LastAccess:  time.Now(),
	}

	safeLog("debug", "Cache set for key", map[string]interface{}{
		"key_hash": vc.hashKey(key),
		"ttl":      vc.ttl.String(),
	})
}

// Delete removes data from cache
func (vc *VaultCache) Delete(key string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	delete(vc.cache, key)

	safeLog("debug", "Cache delete for key", map[string]interface{}{
		"key_hash": vc.hashKey(key),
	})
}

// Clear removes all cached data
func (vc *VaultCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.cache = make(map[string]*VaultCacheEntry)

	safeLog("info", "Cache cleared", map[string]interface{}{
		"cleared_entries": len(vc.cache),
	})
}

// GetStats returns cache statistics
func (vc *VaultCache) GetStats() map[string]interface{} {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	totalAccesses := int64(0)
	oldestEntry := time.Now()
	newestEntry := time.Time{}

	for _, entry := range vc.cache {
		totalAccesses += entry.AccessCount
		if entry.LastAccess.Before(oldestEntry) {
			oldestEntry = entry.LastAccess
		}
		if entry.LastAccess.After(newestEntry) {
			newestEntry = entry.LastAccess
		}
	}

	return map[string]interface{}{
		"total_entries":  len(vc.cache),
		"total_accesses": totalAccesses,
		"ttl":            vc.ttl.String(),
		"oldest_access":  oldestEntry.Format(time.RFC3339),
		"newest_access":  newestEntry.Format(time.RFC3339),
	}
}

// startCleanup runs periodic cleanup of expired entries
func (vc *VaultCache) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		vc.cleanup()
	}
}

// cleanup removes expired entries
func (vc *VaultCache) cleanup() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for key, entry := range vc.cache {
		if now.After(entry.ExpiresAt) {
			delete(vc.cache, key)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		safeLog("debug", "Cache cleanup completed", map[string]interface{}{
			"expired_entries":   expiredCount,
			"remaining_entries": len(vc.cache),
		})
	}
}

// hashKey creates a hash of the key for logging (security)
func (vc *VaultCache) hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:8]) // Only first 8 bytes for logging
}

// Exists checks if a key exists in cache (without updating access stats)
func (vc *VaultCache) Exists(key string) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	entry, exists := vc.cache[key]
	if !exists {
		return false
	}

	// Check expiration
	return !time.Now().After(entry.ExpiresAt)
}

// SetTTL updates the TTL for the cache
func (vc *VaultCache) SetTTL(ttl time.Duration) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.ttl = ttl

	safeLog("info", "Cache TTL updated", map[string]interface{}{
		"new_ttl": ttl.String(),
	})
}

// GetTTL returns the current TTL
func (vc *VaultCache) GetTTL() time.Duration {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.ttl
}
