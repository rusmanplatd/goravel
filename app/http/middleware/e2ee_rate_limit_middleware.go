package middleware

import (
	"fmt"
	"sync"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// RequestCounter tracks requests per user
type RequestCounter struct {
	Count     int
	ResetTime time.Time
	mu        sync.Mutex
}

// Global rate limiter instance
var e2eeRateLimiter = &E2EERateLimiter{
	requests: make(map[string]*RequestCounter),
}

// E2EERateLimiter provides rate limiting for encryption operations
type E2EERateLimiter struct {
	requests map[string]*RequestCounter
	mu       sync.RWMutex
}

// E2EERateLimit returns a middleware function for rate limiting E2EE operations
func E2EERateLimit() http.Middleware {
	// Start cleanup goroutine once
	go e2eeRateLimiter.cleanup()

	return func(ctx http.Context) {
		// Get user ID from context (assumes auth middleware ran first)
		userID := ctx.Value("user_id")
		if userID == nil {
			ctx.Response().Json(401, http.Json{
				"error": "authentication required",
			})
			return
		}

		userIDStr := fmt.Sprintf("%v", userID)

		// Check rate limit
		if !e2eeRateLimiter.checkRateLimit(userIDStr) {
			facades.Log().Warning("E2EE rate limit exceeded", map[string]interface{}{
				"user_id": userIDStr,
				"ip":      ctx.Request().Ip(),
				"path":    ctx.Request().Path(),
			})

			ctx.Response().Json(429, http.Json{
				"error":   "rate limit exceeded",
				"message": "too many encryption operations, please try again later",
			})
			return
		}

		ctx.Request().Next()
	}
}

// checkRateLimit checks if the user has exceeded the rate limit
func (r *E2EERateLimiter) checkRateLimit(userID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	counter, exists := r.requests[userID]

	if !exists {
		// First request from this user
		r.requests[userID] = &RequestCounter{
			Count:     1,
			ResetTime: now.Add(time.Minute), // 1-minute window
		}
		return true
	}

	counter.mu.Lock()
	defer counter.mu.Unlock()

	// Check if the window has expired
	if now.After(counter.ResetTime) {
		// Reset the counter
		counter.Count = 1
		counter.ResetTime = now.Add(time.Minute)
		return true
	}

	// Check if limit is exceeded (100 requests per minute for E2EE operations)
	if counter.Count >= 100 {
		return false
	}

	// Increment counter
	counter.Count++
	return true
}

// cleanup removes expired entries from the requests map
func (r *E2EERateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now()

			for userID, counter := range r.requests {
				counter.mu.Lock()
				if now.After(counter.ResetTime.Add(time.Minute)) {
					// Entry is expired, remove it
					delete(r.requests, userID)
				}
				counter.mu.Unlock()
			}

			r.mu.Unlock()
		}
	}
}

// GetStats returns current rate limiting statistics
func (r *E2EERateLimiter) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := map[string]interface{}{
		"total_users":   len(r.requests),
		"active_limits": 0,
	}

	now := time.Now()
	activeLimits := 0

	for _, counter := range r.requests {
		counter.mu.Lock()
		if !now.After(counter.ResetTime) && counter.Count > 0 {
			activeLimits++
		}
		counter.mu.Unlock()
	}

	stats["active_limits"] = activeLimits
	return stats
}
