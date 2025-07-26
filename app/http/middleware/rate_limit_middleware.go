package middleware

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	MaxAttempts int
	Window      time.Duration
	Identifier  func(ctx http.Context) string
	Message     string
}

// RateLimit creates a rate limiting middleware with the given configuration
func RateLimit(config RateLimitConfig) http.Middleware {
	return func(ctx http.Context) {
		// Get identifier for this request
		identifier := config.Identifier(ctx)
		if identifier == "" {
			identifier = getClientIP(ctx)
		}

		// Check current attempts
		attempts, err := getCurrentAttempts(identifier)
		if err != nil {
			facades.Log().Error("Failed to get rate limit attempts", map[string]interface{}{
				"identifier": identifier,
				"error":      err.Error(),
			})
			// Continue on error to avoid blocking legitimate requests
			ctx.Request().Next()
			return
		}

		// Check if rate limit exceeded
		if attempts >= config.MaxAttempts {
			// Get reset time
			resetTime := getRateLimitResetTime(identifier, config.Window)

			// Set rate limit headers
			ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(config.MaxAttempts))
			ctx.Response().Header("X-RateLimit-Remaining", "0")
			ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
			ctx.Response().Header("Retry-After", strconv.FormatInt(int64(time.Until(resetTime).Seconds()), 10))

			message := config.Message
			if message == "" {
				message = "Rate limit exceeded"
			}

			ctx.Response().Status(429).Json(map[string]interface{}{
				"status":      "error",
				"message":     message,
				"code":        429,
				"retry_after": int64(time.Until(resetTime).Seconds()),
			}).Abort()
			return
		}

		// Increment attempts
		if err := incrementAttempts(identifier, config.Window); err != nil {
			facades.Log().Error("Failed to increment rate limit attempts", map[string]interface{}{
				"identifier": identifier,
				"error":      err.Error(),
			})
		}

		// Set rate limit headers
		remaining := config.MaxAttempts - attempts - 1
		if remaining < 0 {
			remaining = 0
		}
		resetTime := getRateLimitResetTime(identifier, config.Window)

		ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(config.MaxAttempts))
		ctx.Response().Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		ctx.Request().Next()
	}
}

// AuthRateLimit provides rate limiting specifically for authentication endpoints
func AuthRateLimit() http.Middleware {
	return RateLimit(RateLimitConfig{
		MaxAttempts: 5,                // 5 attempts
		Window:      15 * time.Minute, // per 15 minutes
		Identifier: func(ctx http.Context) string {
			// Use IP + email combination for more granular control
			ip := getClientIP(ctx)
			email := ctx.Request().Input("email", "")
			if email != "" {
				return fmt.Sprintf("auth:%s:%s", ip, email)
			}
			return fmt.Sprintf("auth:%s", ip)
		},
		Message: "Too many authentication attempts. Please try again later.",
	})
}

// APIRateLimit provides general API rate limiting
func APIRateLimit() http.Middleware {
	return RateLimit(RateLimitConfig{
		MaxAttempts: 100,       // 100 requests
		Window:      time.Hour, // per hour
		Identifier: func(ctx http.Context) string {
			// Use user ID if authenticated, otherwise IP
			if userID := getUserIDFromContext(ctx); userID != "" {
				return fmt.Sprintf("api:user:%s", userID)
			}
			return fmt.Sprintf("api:ip:%s", getClientIP(ctx))
		},
		Message: "API rate limit exceeded. Please slow down your requests.",
	})
}

// MFARateLimit provides rate limiting for MFA attempts
func MFARateLimit() http.Middleware {
	return RateLimit(RateLimitConfig{
		MaxAttempts: 3,               // 3 attempts
		Window:      5 * time.Minute, // per 5 minutes
		Identifier: func(ctx http.Context) string {
			ip := getClientIP(ctx)
			userID := getUserIDFromContext(ctx)
			if userID != "" {
				return fmt.Sprintf("mfa:%s:%s", ip, userID)
			}
			return fmt.Sprintf("mfa:%s", ip)
		},
		Message: "Too many MFA attempts. Please wait before trying again.",
	})
}

// WebAuthnRateLimit provides rate limiting for WebAuthn operations
func WebAuthnRateLimit() http.Middleware {
	return RateLimit(RateLimitConfig{
		MaxAttempts: 5,                // 5 attempts
		Window:      10 * time.Minute, // per 10 minutes
		Identifier: func(ctx http.Context) string {
			ip := getClientIP(ctx)
			userID := getUserIDFromContext(ctx)
			if userID != "" {
				return fmt.Sprintf("webauthn:%s:%s", ip, userID)
			}
			return fmt.Sprintf("webauthn:%s", ip)
		},
		Message: "Too many WebAuthn attempts. Please wait before trying again.",
	})
}

// Helper functions

// getCurrentAttempts gets the current number of attempts for an identifier
func getCurrentAttempts(identifier string) (int, error) {
	cacheKey := fmt.Sprintf("rate_limit:%s", identifier)
	var attempts int
	err := facades.Cache().Get(cacheKey, &attempts)
	if err != nil {
		// If key doesn't exist, return 0 attempts
		return 0, nil
	}
	return attempts, nil
}

// incrementAttempts increments the attempt counter for an identifier
func incrementAttempts(identifier string, window time.Duration) error {
	cacheKey := fmt.Sprintf("rate_limit:%s", identifier)

	var attempts int
	facades.Cache().Get(cacheKey, &attempts)
	attempts++

	return facades.Cache().Put(cacheKey, attempts, window)
}

// getRateLimitResetTime calculates when the rate limit will reset
func getRateLimitResetTime(identifier string, window time.Duration) time.Time {
	// For simplicity, we'll just add the window to current time
	// In a more sophisticated implementation, you might track the actual window start time
	return time.Now().Add(window)
}

// getClientIP extracts the client IP address from the request
func getClientIP(ctx http.Context) string {
	// Check X-Forwarded-For header first
	if xff := ctx.Request().Header("X-Forwarded-For", ""); xff != "" {
		// Take the first IP from the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := ctx.Request().Header("X-Real-IP", ""); xri != "" {
		return xri
	}

	// Fallback to request IP
	return ctx.Request().Ip()
}

// getUserIDFromContext extracts user ID from context if available
func getUserIDFromContext(ctx http.Context) string {
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// ClearRateLimit clears the rate limit for a specific identifier
func ClearRateLimit(identifier string) error {
	cacheKey := fmt.Sprintf("rate_limit:%s", identifier)
	facades.Cache().Forget(cacheKey)
	return nil
}

// GetRateLimitStatus returns the current rate limit status for an identifier
func GetRateLimitStatus(identifier string, maxAttempts int, window time.Duration) (map[string]interface{}, error) {
	attempts, err := getCurrentAttempts(identifier)
	if err != nil {
		return nil, err
	}

	remaining := maxAttempts - attempts
	if remaining < 0 {
		remaining = 0
	}

	resetTime := getRateLimitResetTime(identifier, window)

	return map[string]interface{}{
		"limit":     maxAttempts,
		"remaining": remaining,
		"reset":     resetTime.Unix(),
		"window":    window.Seconds(),
	}, nil
}
