package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"goravel/app/models"
	"goravel/app/services"

	goravelhttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// WebSocketAuth middleware for websocket authentication with proper JWT validation
func WebSocketAuth() goravelhttp.Middleware {
	return func(ctx goravelhttp.Context) {
		// Check if websocket authentication is required
		if !facades.Config().GetBool("websocket.auth.required", true) {
			ctx.Request().Next()
			return
		}

		// Extract token from query parameter or header
		token := ctx.Request().Query("token", "")
		if token == "" {
			// Try to get from Authorization header
			authHeader := ctx.Request().Header("Authorization", "")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			facades.Log().Warning("WebSocket authentication failed: no token provided", map[string]interface{}{
				"ip":         ctx.Request().Ip(),
				"user_agent": ctx.Request().Header("User-Agent", ""),
			})
			ctx.Request().AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Validate JWT token with proper service integration
		user, claims, err := validateWebSocketToken(token)
		if err != nil {
			facades.Log().Warning("WebSocket authentication failed: invalid token", map[string]interface{}{
				"error":      err.Error(),
				"ip":         ctx.Request().Ip(),
				"user_agent": ctx.Request().Header("User-Agent", ""),
			})
			ctx.Request().AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Check if user is active
		if !user.IsActive {
			facades.Log().Warning("WebSocket authentication failed: inactive user", map[string]interface{}{
				"user_id": user.ID,
				"ip":      ctx.Request().Ip(),
			})
			ctx.Request().AbortWithStatus(http.StatusForbidden)
			return
		}

		// Check token expiration with buffer
		if claims.ExpiresAt != nil && time.Now().Add(30*time.Second).After(claims.ExpiresAt.Time) {
			facades.Log().Warning("WebSocket authentication failed: token near expiration", map[string]interface{}{
				"user_id":    user.ID,
				"expires_at": claims.ExpiresAt.Time,
			})
			ctx.Request().AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Store user and claims in context for later use
		ctx.WithValue("user", user)
		ctx.WithValue("user_id", user.ID)
		ctx.WithValue("jwt_claims", claims)
		ctx.WithValue("auth_token", token)

		// Log successful authentication
		facades.Log().Info("WebSocket authentication successful", map[string]interface{}{
			"user_id": user.ID,
			"ip":      ctx.Request().Ip(),
		})

		ctx.Request().Next()
	}
}

// WebSocketRateLimit middleware with enhanced rate limiting
func WebSocketRateLimit() goravelhttp.Middleware {
	// Enhanced rate limiter storage with cleanup
	var (
		rateLimiters = make(map[string]*enhancedRateLimiter)
		mu           sync.RWMutex
		lastCleanup  = time.Now()
	)

	return func(ctx goravelhttp.Context) {
		if !facades.Config().GetBool("websocket.rate_limit.enabled", true) {
			ctx.Request().Next()
			return
		}

		// Periodic cleanup of old rate limiters
		mu.Lock()
		if time.Since(lastCleanup) > 5*time.Minute {
			cleanupOldRateLimiters(rateLimiters)
			lastCleanup = time.Now()
		}
		mu.Unlock()

		// Get client identifier (prefer user ID over IP)
		clientID := getClientIdentifier(ctx)

		mu.Lock()
		limiter, exists := rateLimiters[clientID]
		if !exists {
			limiter = newEnhancedRateLimiter(
				facades.Config().GetInt("websocket.rate_limit.messages_per_minute", 60),
				facades.Config().GetInt("websocket.rate_limit.burst_limit", 10),
				facades.Config().GetInt("websocket.rate_limit.window_seconds", 60),
			)
			rateLimiters[clientID] = limiter
		}
		mu.Unlock()

		if !limiter.Allow() {
			facades.Log().Warning("WebSocket rate limit exceeded", map[string]interface{}{
				"client_id": clientID,
				"ip":        ctx.Request().Ip(),
				"user_id":   ctx.Value("user_id"),
			})
			ctx.Request().AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		ctx.Request().Next()
	}
}

// WebSocketSecurity middleware with enhanced security checks
func WebSocketSecurity() goravelhttp.Middleware {
	// Enhanced connection tracking with TTL
	var (
		connectionCounts = make(map[string]*connectionTracker)
		ipConnections    = make(map[string]*connectionTracker)
		mu               sync.RWMutex
		lastCleanup      = time.Now()
	)

	return func(ctx goravelhttp.Context) {
		clientIP := ctx.Request().Ip()

		// Periodic cleanup
		mu.Lock()
		if time.Since(lastCleanup) > 2*time.Minute {
			cleanupConnectionTrackers(connectionCounts, ipConnections)
			lastCleanup = time.Now()
		}
		mu.Unlock()

		// Check maximum connections per IP with enhanced tracking
		maxConnectionsPerIP := facades.Config().GetInt("websocket.security.max_connections_per_ip", 10)

		mu.Lock()
		ipTracker, exists := ipConnections[clientIP]
		if !exists {
			ipTracker = &connectionTracker{count: 0, lastSeen: time.Now()}
			ipConnections[clientIP] = ipTracker
		}
		currentIPConnections := ipTracker.count
		mu.Unlock()

		if currentIPConnections >= maxConnectionsPerIP {
			facades.Log().Warning("WebSocket connection limit exceeded for IP", map[string]interface{}{
				"ip":                  clientIP,
				"current_connections": currentIPConnections,
				"max_allowed":         maxConnectionsPerIP,
				"user_agent":          ctx.Request().Header("User-Agent", ""),
			})
			ctx.Request().AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		// Check user connection limits if authenticated
		if userID := ctx.Value("user_id"); userID != nil {
			maxConnectionsPerUser := facades.Config().GetInt("websocket.connection.max_connections_per_user", 5)

			mu.Lock()
			userTracker, exists := connectionCounts[userID.(string)]
			if !exists {
				userTracker = &connectionTracker{count: 0, lastSeen: time.Now()}
				connectionCounts[userID.(string)] = userTracker
			}
			currentUserConnections := userTracker.count
			mu.Unlock()

			if maxConnectionsPerUser > 0 && currentUserConnections >= maxConnectionsPerUser {
				facades.Log().Warning("WebSocket connection limit exceeded for user", map[string]interface{}{
					"user_id":             userID,
					"current_connections": currentUserConnections,
					"max_allowed":         maxConnectionsPerUser,
					"ip":                  clientIP,
				})
				ctx.Request().AbortWithStatus(http.StatusTooManyRequests)
				return
			}
		}

		// Increment connection counters
		mu.Lock()
		ipConnections[clientIP].count++
		ipConnections[clientIP].lastSeen = time.Now()
		if userID := ctx.Value("user_id"); userID != nil {
			connectionCounts[userID.(string)].count++
			connectionCounts[userID.(string)].lastSeen = time.Now()
		}
		mu.Unlock()

		// Set cleanup handler for when connection closes
		ctx.WithValue("websocket_cleanup", func() {
			mu.Lock()
			defer mu.Unlock()

			if tracker, exists := ipConnections[clientIP]; exists {
				tracker.count--
				if tracker.count <= 0 {
					delete(ipConnections, clientIP)
				}
			}

			if userID := ctx.Value("user_id"); userID != nil {
				if tracker, exists := connectionCounts[userID.(string)]; exists {
					tracker.count--
					if tracker.count <= 0 {
						delete(connectionCounts, userID.(string))
					}
				}
			}
		})

		ctx.Request().Next()
	}
}

// WebSocketCORS middleware with enhanced origin validation
func WebSocketCORS() goravelhttp.Middleware {
	return func(ctx goravelhttp.Context) {
		if !facades.Config().GetBool("websocket.cors.check_origin", true) {
			ctx.Request().Next()
			return
		}

		origin := ctx.Request().Header("Origin", "")
		if origin == "" {
			// Allow connections without origin (like from mobile apps) but log it
			facades.Log().Info("WebSocket connection without origin header", map[string]interface{}{
				"ip":         ctx.Request().Ip(),
				"user_agent": ctx.Request().Header("User-Agent", ""),
			})
			ctx.Request().Next()
			return
		}

		// Get allowed origins from config
		allowedOrigins := facades.Config().Get("websocket.cors.allowed_origins", []string{})
		allowed := false

		// Check against allowed origins with pattern matching
		for _, allowedOrigin := range allowedOrigins.([]string) {
			if origin == allowedOrigin || allowedOrigin == "*" {
				allowed = true
				break
			}
			// Support wildcard subdomains
			if strings.HasPrefix(allowedOrigin, "*.") {
				domain := strings.TrimPrefix(allowedOrigin, "*.")
				if strings.HasSuffix(origin, domain) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			facades.Log().Warning("WebSocket connection blocked due to CORS policy", map[string]interface{}{
				"origin":          origin,
				"ip":              ctx.Request().Ip(),
				"user_agent":      ctx.Request().Header("User-Agent", ""),
				"allowed_origins": allowedOrigins,
			})
			ctx.Request().AbortWithStatus(http.StatusForbidden)
			return
		}

		// Set CORS headers for successful validation
		ctx.Response().Header("Access-Control-Allow-Origin", origin)
		ctx.Response().Header("Access-Control-Allow-Credentials", "true")

		ctx.Request().Next()
	}
}

// Helper types and functions

type enhancedRateLimiter struct {
	limit         int
	burst         int
	window        time.Duration
	tokens        int
	lastRefill    time.Time
	violations    int
	lastViolation time.Time
	mu            sync.Mutex
}

type connectionTracker struct {
	count    int
	lastSeen time.Time
}

func newEnhancedRateLimiter(limit, burst, windowSeconds int) *enhancedRateLimiter {
	return &enhancedRateLimiter{
		limit:      limit,
		burst:      burst,
		window:     time.Duration(windowSeconds) * time.Second,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

func (rl *enhancedRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed >= rl.window {
		rl.tokens = rl.burst
		rl.lastRefill = now
	} else {
		// Calculate tokens to add based on rate
		tokensToAdd := int(elapsed.Seconds()) * rl.limit / int(rl.window.Seconds())
		rl.tokens = minInt(rl.burst, rl.tokens+tokensToAdd)
		if tokensToAdd > 0 {
			rl.lastRefill = now
		}
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	// Track violations for potential blocking
	rl.violations++
	rl.lastViolation = now
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getClientIdentifier(ctx goravelhttp.Context) string {
	// Prefer user ID if authenticated
	if userID := ctx.Value("user_id"); userID != nil {
		return fmt.Sprintf("user:%s", userID.(string))
	}
	// Fall back to IP address
	return fmt.Sprintf("ip:%s", ctx.Request().Ip())
}

// validateWebSocketToken validates JWT token using the JWT service
func validateWebSocketToken(token string) (*models.User, *services.JWTClaims, error) {
	if len(token) < 10 {
		return nil, nil, fmt.Errorf("token too short")
	}

	// Create JWT service instance
	jwtService := services.NewJWTService()

	// Validate token using JWT service
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check if it's an access token
	if claims.Type != "access" {
		return nil, nil, fmt.Errorf("invalid token type: expected access, got %s", claims.Type)
	}

	// Find user by ID
	var user models.User
	err = facades.Orm().Query().Where("id", claims.UserID).First(&user)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %v", err)
	}

	return &user, claims, nil
}

// cleanupOldRateLimiters removes rate limiters that haven't been used recently
func cleanupOldRateLimiters(limiters map[string]*enhancedRateLimiter) {
	cutoff := time.Now().Add(-10 * time.Minute)
	for key, limiter := range limiters {
		limiter.mu.Lock()
		if limiter.lastRefill.Before(cutoff) && limiter.lastViolation.Before(cutoff) {
			delete(limiters, key)
		}
		limiter.mu.Unlock()
	}
}

// cleanupConnectionTrackers removes old connection trackers
func cleanupConnectionTrackers(userTrackers, ipTrackers map[string]*connectionTracker) {
	cutoff := time.Now().Add(-5 * time.Minute)

	for key, tracker := range userTrackers {
		if tracker.lastSeen.Before(cutoff) && tracker.count <= 0 {
			delete(userTrackers, key)
		}
	}

	for key, tracker := range ipTrackers {
		if tracker.lastSeen.Before(cutoff) && tracker.count <= 0 {
			delete(ipTrackers, key)
		}
	}
}
