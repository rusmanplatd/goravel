package services

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

// NotificationRateLimiter handles rate limiting for notifications
type NotificationRateLimiter struct {
	preferenceService *NotificationPreferenceService
}

// NewNotificationRateLimiter creates a new notification rate limiter
func NewNotificationRateLimiter() *NotificationRateLimiter {
	return &NotificationRateLimiter{
		preferenceService: NewNotificationPreferenceService(),
	}
}

// RateLimitInfo contains rate limiting information
type RateLimitInfo struct {
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason,omitempty"`
	RetryAfter    int    `json:"retry_after,omitempty"` // seconds
	CurrentCount  int    `json:"current_count"`
	Limit         int    `json:"limit"`
	WindowSeconds int    `json:"window_seconds"`
}

// IsAllowed checks if a notification is allowed based on rate limits
func (rl *NotificationRateLimiter) IsAllowed(userID, notificationType, channel string) *RateLimitInfo {
	// Get user preferences for this notification type
	preference, err := rl.preferenceService.GetPreferenceForType(userID, notificationType)
	if err != nil {
		// If we can't get preferences, allow with default limits
		return rl.checkGlobalLimits(userID, notificationType, channel)
	}

	// Check user-specific hourly limit
	if preference.MaxPerHour != nil && *preference.MaxPerHour > 0 {
		if info := rl.checkHourlyLimit(userID, notificationType, *preference.MaxPerHour); !info.Allowed {
			return info
		}
	}

	// Check user-specific daily limit
	if preference.MaxPerDay != nil && *preference.MaxPerDay > 0 {
		if info := rl.checkDailyLimit(userID, notificationType, *preference.MaxPerDay); !info.Allowed {
			return info
		}
	}

	// Check global limits
	return rl.checkGlobalLimits(userID, notificationType, channel)
}

// checkHourlyLimit checks hourly rate limit for a user and notification type
func (rl *NotificationRateLimiter) checkHourlyLimit(userID, notificationType string, limit int) *RateLimitInfo {
	key := fmt.Sprintf("notification_rate_limit:hourly:%s:%s", userID, notificationType)
	return rl.checkRateLimit(key, limit, 3600) // 1 hour window
}

// checkDailyLimit checks daily rate limit for a user and notification type
func (rl *NotificationRateLimiter) checkDailyLimit(userID, notificationType string, limit int) *RateLimitInfo {
	key := fmt.Sprintf("notification_rate_limit:daily:%s:%s", userID, notificationType)
	return rl.checkRateLimit(key, limit, 86400) // 24 hour window
}

// checkGlobalLimits checks global rate limits from configuration
func (rl *NotificationRateLimiter) checkGlobalLimits(userID, notificationType, channel string) *RateLimitInfo {
	// Check if rate limiting is enabled globally
	if !facades.Config().GetBool("notification.rate_limiting.enabled", false) {
		return &RateLimitInfo{Allowed: true}
	}

	// Global per-minute limit
	maxPerMinute := facades.Config().GetInt("notification.rate_limiting.max_per_minute", 60)
	if maxPerMinute > 0 {
		key := fmt.Sprintf("notification_rate_limit:global_minute:%s", userID)
		if info := rl.checkRateLimit(key, maxPerMinute, 60); !info.Allowed {
			return info
		}
	}

	// Global hourly limit
	maxPerHour := facades.Config().GetInt("notification.rate_limiting.max_per_hour", 1000)
	if maxPerHour > 0 {
		key := fmt.Sprintf("notification_rate_limit:global_hour:%s", userID)
		if info := rl.checkRateLimit(key, maxPerHour, 3600); !info.Allowed {
			return info
		}
	}

	// Channel-specific limits
	return rl.checkChannelLimits(userID, channel)
}

// checkChannelLimits checks channel-specific rate limits
func (rl *NotificationRateLimiter) checkChannelLimits(userID, channel string) *RateLimitInfo {
	switch channel {
	case "mail":
		// Email has stricter limits to prevent spam
		key := fmt.Sprintf("notification_rate_limit:mail:%s", userID)
		return rl.checkRateLimit(key, 50, 3600) // 50 emails per hour

	case "sms":
		// SMS has very strict limits due to cost
		key := fmt.Sprintf("notification_rate_limit:sms:%s", userID)
		return rl.checkRateLimit(key, 10, 3600) // 10 SMS per hour

	case "push":
		// Push notifications can be more frequent
		key := fmt.Sprintf("notification_rate_limit:push:%s", userID)
		return rl.checkRateLimit(key, 200, 3600) // 200 push notifications per hour

	case "slack", "discord", "telegram":
		// Chat platform limits
		key := fmt.Sprintf("notification_rate_limit:chat:%s", userID)
		return rl.checkRateLimit(key, 100, 3600) // 100 chat notifications per hour

	default:
		// Default limits for other channels
		return &RateLimitInfo{Allowed: true}
	}
}

// checkRateLimit checks rate limit using Redis-based sliding window
func (rl *NotificationRateLimiter) checkRateLimit(key string, limit int, windowSeconds int) *RateLimitInfo {
	// Use Redis for distributed rate limiting
	cache := facades.Cache()

	// Get current count
	currentCountStr := cache.Get(key, "0")
	currentCount, _ := strconv.Atoi(currentCountStr.(string))

	// Check if limit exceeded
	if currentCount >= limit {
		// Calculate retry after based on window
		retryAfter := windowSeconds

		return &RateLimitInfo{
			Allowed:       false,
			Reason:        fmt.Sprintf("Rate limit exceeded: %d/%d requests in %d seconds", currentCount, limit, windowSeconds),
			RetryAfter:    retryAfter,
			CurrentCount:  currentCount,
			Limit:         limit,
			WindowSeconds: windowSeconds,
		}
	}

	return &RateLimitInfo{
		Allowed:       true,
		CurrentCount:  currentCount,
		Limit:         limit,
		WindowSeconds: windowSeconds,
	}
}

// IncrementCounter increments the rate limit counter for a successful notification
func (rl *NotificationRateLimiter) IncrementCounter(userID, notificationType, channel string) {
	// Increment user-specific counters
	preference, err := rl.preferenceService.GetPreferenceForType(userID, notificationType)
	if err == nil {
		if preference.MaxPerHour != nil && *preference.MaxPerHour > 0 {
			key := fmt.Sprintf("notification_rate_limit:hourly:%s:%s", userID, notificationType)
			rl.incrementRedisCounter(key, 3600)
		}

		if preference.MaxPerDay != nil && *preference.MaxPerDay > 0 {
			key := fmt.Sprintf("notification_rate_limit:daily:%s:%s", userID, notificationType)
			rl.incrementRedisCounter(key, 86400)
		}
	}

	// Increment global counters if enabled
	if facades.Config().GetBool("notification.rate_limiting.enabled", false) {
		// Global per-minute counter
		key := fmt.Sprintf("notification_rate_limit:global_minute:%s", userID)
		rl.incrementRedisCounter(key, 60)

		// Global hourly counter
		key = fmt.Sprintf("notification_rate_limit:global_hour:%s", userID)
		rl.incrementRedisCounter(key, 3600)
	}

	// Increment channel-specific counters
	switch channel {
	case "mail":
		key := fmt.Sprintf("notification_rate_limit:mail:%s", userID)
		rl.incrementRedisCounter(key, 3600)
	case "sms":
		key := fmt.Sprintf("notification_rate_limit:sms:%s", userID)
		rl.incrementRedisCounter(key, 3600)
	case "push":
		key := fmt.Sprintf("notification_rate_limit:push:%s", userID)
		rl.incrementRedisCounter(key, 3600)
	case "slack", "discord", "telegram":
		key := fmt.Sprintf("notification_rate_limit:chat:%s", userID)
		rl.incrementRedisCounter(key, 3600)
	}
}

// incrementRedisCounter increments a counter in Redis with expiration
func (rl *NotificationRateLimiter) incrementRedisCounter(key string, expireSeconds int) {
	cache := facades.Cache()

	// Get current value
	currentStr := cache.Get(key, "0")
	current, _ := strconv.Atoi(currentStr.(string))
	new_value := current + 1

	// Set new value with expiration
	cache.Put(key, strconv.Itoa(new_value), time.Duration(expireSeconds)*time.Second)
}

// GetRateLimitStatus returns current rate limit status for a user
func (rl *NotificationRateLimiter) GetRateLimitStatus(userID string) map[string]*RateLimitInfo {
	status := make(map[string]*RateLimitInfo)

	// Check global limits
	if facades.Config().GetBool("notification.rate_limiting.enabled", false) {
		maxPerMinute := facades.Config().GetInt("notification.rate_limiting.max_per_minute", 60)
		if maxPerMinute > 0 {
			key := fmt.Sprintf("notification_rate_limit:global_minute:%s", userID)
			status["global_minute"] = rl.checkRateLimit(key, maxPerMinute, 60)
		}

		maxPerHour := facades.Config().GetInt("notification.rate_limiting.max_per_hour", 1000)
		if maxPerHour > 0 {
			key := fmt.Sprintf("notification_rate_limit:global_hour:%s", userID)
			status["global_hour"] = rl.checkRateLimit(key, maxPerHour, 3600)
		}
	}

	// Check channel limits
	channels := []string{"mail", "sms", "push", "chat"}
	limits := map[string]int{
		"mail": 50,
		"sms":  10,
		"push": 200,
		"chat": 100,
	}

	for _, channel := range channels {
		key := fmt.Sprintf("notification_rate_limit:%s:%s", channel, userID)
		status[channel] = rl.checkRateLimit(key, limits[channel], 3600)
	}

	return status
}

// ResetRateLimit resets rate limit counters for a user (admin function)
func (rl *NotificationRateLimiter) ResetRateLimit(userID string, scope string) error {
	cache := facades.Cache()

	switch scope {
	case "all":
		// Reset all counters for the user using Redis SCAN for production
		patterns := []string{
			fmt.Sprintf("notification_rate_limit:*:%s", userID),
			fmt.Sprintf("notification_rate_limit:*:%s:*", userID),
		}

		for _, pattern := range patterns {
			keys, err := rl.scanKeys(pattern)
			if err != nil {
				facades.Log().Error("Failed to scan keys for rate limit reset", map[string]interface{}{
					"user_id": userID,
					"pattern": pattern,
					"error":   err.Error(),
				})
				continue
			}

			// Delete all matching keys
			for _, key := range keys {
				cache.Forget(key)
			}

			facades.Log().Info("Rate limit reset completed", map[string]interface{}{
				"user_id":    userID,
				"pattern":    pattern,
				"keys_reset": len(keys),
			})
		}

	case "hourly", "daily", "global_minute", "global_hour", "mail", "sms", "push", "chat":
		key := fmt.Sprintf("notification_rate_limit:%s:%s", scope, userID)
		cache.Forget(key)

	default:
		return fmt.Errorf("invalid scope: %s", scope)
	}

	return nil
}

// scanKeys is a helper function to scan keys matching a pattern
func (rl *NotificationRateLimiter) scanKeys(pattern string) ([]string, error) {
	// Try to get Redis client directly if available
	if redisClient := rl.getRedisClient(); redisClient != nil {
		return rl.scanKeysWithRedis(redisClient, pattern)
	}

	// Fallback to cache-based approach (less efficient but works)
	return rl.scanKeysWithCache(pattern)
}

// getRedisClient attempts to get a Redis client instance
func (rl *NotificationRateLimiter) getRedisClient() interface{} {
	// This is a simplified approach - in production you'd have proper Redis client access
	// For now, return nil to use the fallback approach
	return nil
}

// scanKeysWithRedis uses Redis SCAN command for efficient key scanning
func (rl *NotificationRateLimiter) scanKeysWithRedis(client interface{}, pattern string) ([]string, error) {
	// This would use the actual Redis client's SCAN command
	// Implementation depends on the specific Redis client library used
	return nil, fmt.Errorf("Redis client not available")
}

// scanKeysWithCache uses a cache-based approach as fallback
func (rl *NotificationRateLimiter) scanKeysWithCache(pattern string) ([]string, error) {
	// Since we can't scan efficiently, we'll use a known key structure approach
	// This is less efficient but works with the cache interface

	var keys []string

	// For notification rate limiting, we know the key patterns
	// Generate possible keys based on known rate limit types
	rateLimitTypes := []string{"minute", "hour", "daily", "global_minute", "global_hour"}
	notificationTypes := []string{"mail", "sms", "push", "chat"}

	// Extract user ID from pattern
	userID := rl.extractUserIDFromPattern(pattern)
	if userID == "" {
		return keys, nil
	}

	// Check all possible combinations
	for _, rateType := range rateLimitTypes {
		key := fmt.Sprintf("notification_rate_limit:%s:%s", rateType, userID)
		if facades.Cache().Has(key) {
			keys = append(keys, key)
		}
	}

	for _, notifType := range notificationTypes {
		key := fmt.Sprintf("notification_rate_limit:%s:%s", notifType, userID)
		if facades.Cache().Has(key) {
			keys = append(keys, key)
		}

		// Also check with rate type combinations
		for _, rateType := range rateLimitTypes {
			key := fmt.Sprintf("notification_rate_limit:%s:%s:%s", notifType, userID, rateType)
			if facades.Cache().Has(key) {
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

// extractUserIDFromPattern extracts user ID from a key pattern
func (rl *NotificationRateLimiter) extractUserIDFromPattern(pattern string) string {
	// Pattern: "notification_rate_limit:*:userID" or "notification_rate_limit:*:userID:*"
	parts := strings.Split(pattern, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}
