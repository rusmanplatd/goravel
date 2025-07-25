package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type RateLimitMiddleware struct{}

func NewRateLimitMiddleware() *RateLimitMiddleware {
	return &RateLimitMiddleware{}
}

// Handle implements rate limiting for API endpoints
func (m *RateLimitMiddleware) Handle(ctx http.Context) http.Response {
	// Get client IP
	clientIP := m.getClientIP(ctx)

	// Get endpoint path for different rate limits
	path := ctx.Request().Path()

	// Define rate limits based on endpoint
	var limit, window int
	switch {
	case path == "/api/v1/auth/login":
		limit = 5   // 5 attempts
		window = 15 // per 15 minutes
	case path == "/api/v1/auth/register":
		limit = 3   // 3 attempts
		window = 60 // per hour
	case path == "/api/v1/auth/forgot-password":
		limit = 3   // 3 attempts
		window = 60 // per hour
	case path == "/api/v1/auth/reset-password":
		limit = 5   // 5 attempts
		window = 15 // per 15 minutes
	default:
		limit = 100 // 100 requests
		window = 1  // per minute
	}

	// Check rate limit
	key := fmt.Sprintf("rate_limit:%s:%s", clientIP, path)
	current, err := m.checkRateLimit(key, limit, window)
	if err != nil {
		facades.Log().Error("Rate limit check failed", map[string]interface{}{
			"error": err.Error(),
			"ip":    clientIP,
			"path":  path,
		})
		// Continue without rate limiting if there's an error
		ctx.Request().Next()
		return nil
	}

	// Check if rate limit exceeded
	if current > limit {
		return ctx.Response().Status(429).Json(http.Json{
			"status":  "error",
			"message": "Rate limit exceeded",
			"data": map[string]interface{}{
				"retry_after": window * 60, // seconds
				"limit":       limit,
				"window":      window,
			},
		})
	}

	// Add rate limit headers
	ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(limit))
	ctx.Response().Header("X-RateLimit-Remaining", strconv.Itoa(limit-current))
	ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Duration(window)*time.Minute).Unix(), 10))

	ctx.Request().Next()
	return nil
}

// checkRateLimit checks and increments the rate limit counter
func (m *RateLimitMiddleware) checkRateLimit(key string, limit, window int) (int, error) {
	// Get current count
	var current int
	err := facades.Cache().Get(key, &current)
	if err != nil {
		// Key doesn't exist, start fresh
		current = 0
	}

	// Increment counter
	current++

	// Store with expiration
	putErr := facades.Cache().Put(key, current, time.Duration(window)*time.Minute)
	if putErr != nil {
		return 0, putErr
	}

	return current, nil
}

// getClientIP gets the real client IP address
func (m *RateLimitMiddleware) getClientIP(ctx http.Context) string {
	// Check for forwarded headers first
	if ip := ctx.Request().Header("X-Forwarded-For", ""); ip != "" {
		return ip
	}
	if ip := ctx.Request().Header("X-Real-IP", ""); ip != "" {
		return ip
	}
	if ip := ctx.Request().Header("CF-Connecting-IP", ""); ip != "" {
		return ip
	}

	// Fallback to remote address
	return ctx.Request().Ip()
}

// RateLimit returns a middleware function for rate limiting
func RateLimit() http.Middleware {
	return func(ctx http.Context) {
		middleware := NewRateLimitMiddleware()
		response := middleware.Handle(ctx)
		if response != nil {
			// If middleware returned a response, it means rate limit was exceeded
			response.Render()
			ctx.Request().Abort()
		}
	}
}

// RateLimitWithConfig allows custom rate limiting configuration
func RateLimitWithConfig(limit, window int) func(ctx http.Context) http.Response {
	return func(ctx http.Context) http.Response {
		clientIP := ctx.Request().Ip()
		path := ctx.Request().Path()

		key := fmt.Sprintf("rate_limit:%s:%s", clientIP, path)
		var current int
		err := facades.Cache().Get(key, &current)
		if err != nil {
			current = 0
		}

		current++

		if current > limit {
			return ctx.Response().Status(429).Json(http.Json{
				"status":  "error",
				"message": "Rate limit exceeded",
				"data": map[string]interface{}{
					"retry_after": window * 60,
					"limit":       limit,
					"window":      window,
				},
			})
		}

		facades.Cache().Put(key, current, time.Duration(window)*time.Minute)

		ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(limit))
		ctx.Response().Header("X-RateLimit-Remaining", strconv.Itoa(limit-current))
		ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Duration(window)*time.Minute).Unix(), 10))

		ctx.Request().Next()
		return nil
	}
}
