package middleware

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"goravel/app/http/responses"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type OAuthRateLimitMiddleware struct {
	cache map[string]*RateLimitInfo
}

type RateLimitInfo struct {
	Count     int
	ResetTime time.Time
	Blocked   bool
}

func NewOAuthRateLimitMiddleware() *OAuthRateLimitMiddleware {
	return &OAuthRateLimitMiddleware{
		cache: make(map[string]*RateLimitInfo),
	}
}

// Handle implements OAuth2-specific rate limiting similar to Google's approach
func (m *OAuthRateLimitMiddleware) Handle(ctx http.Context) http.Response {
	// Check if rate limiting is enabled
	if !facades.Config().GetBool("oauth.enable_rate_limiting", true) {
		ctx.Request().Next()
		return nil
	}

	// Get client identifier (IP + User-Agent + Client ID if available)
	clientID := m.getClientIdentifier(ctx)

	// Get endpoint-specific rate limit
	endpoint := m.getEndpointType(ctx.Request().Path())
	limit, window := m.getRateLimit(endpoint)

	// Check rate limit
	if m.isRateLimited(clientID, endpoint, limit, window) {
		return m.rateLimitExceededResponse(ctx, limit, window)
	}

	// Increment counter
	m.incrementCounter(clientID, endpoint, window)

	// Add rate limit headers before continuing
	m.addRateLimitHeaders(ctx, clientID, endpoint, limit, window)

	ctx.Request().Next()
	return nil
}

// getClientIdentifier creates a unique identifier for rate limiting
func (m *OAuthRateLimitMiddleware) getClientIdentifier(ctx http.Context) string {
	// Get IP address
	ip := m.getClientIP(ctx)

	// Get User-Agent
	userAgent := ctx.Request().Header("User-Agent")
	if len(userAgent) > 50 {
		userAgent = userAgent[:50] // Truncate for cache efficiency
	}

	// Get OAuth client ID if available
	clientID := m.extractClientID(ctx)

	// Create composite identifier
	identifier := fmt.Sprintf("%s:%s", ip, userAgent)
	if clientID != "" {
		identifier = fmt.Sprintf("%s:%s", identifier, clientID)
	}

	return identifier
}

// getClientIP extracts the real client IP address
func (m *OAuthRateLimitMiddleware) getClientIP(ctx http.Context) string {
	// Check X-Forwarded-For header
	if xff := ctx.Request().Header("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := ctx.Request().Header("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	return ctx.Request().Ip()
}

// extractClientID tries to extract OAuth client ID from request
func (m *OAuthRateLimitMiddleware) extractClientID(ctx http.Context) string {
	// Try to get from form data
	if clientID := ctx.Request().Input("client_id"); clientID != "" {
		return clientID
	}

	// Try to get from query parameters
	if clientID := ctx.Request().Query("client_id"); clientID != "" {
		return clientID
	}

	// Try to get from Authorization header (Basic auth)
	if auth := ctx.Request().Header("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			// Could decode basic auth to get client_id, but for rate limiting
			// the existence of the header is sufficient indication
			return "authenticated_client"
		}
	}

	return ""
}

// getEndpointType determines the type of OAuth2 endpoint
func (m *OAuthRateLimitMiddleware) getEndpointType(path string) string {
	switch {
	case strings.Contains(path, "/oauth/authorize"):
		return "authorization"
	case strings.Contains(path, "/oauth/token"):
		return "token"
	case strings.Contains(path, "/oauth/userinfo"):
		return "userinfo"
	case strings.Contains(path, "/oauth/introspect"):
		return "introspection"
	case strings.Contains(path, "/oauth/revoke"):
		return "revocation"
	case strings.Contains(path, "/oauth/device"):
		return "device"
	case strings.Contains(path, "/oauth/clients"):
		return "client_registration"
	case strings.Contains(path, "/oauth/jwks"):
		return "jwks"
	case strings.Contains(path, "/.well-known/"):
		return "discovery"
	default:
		return "general"
	}
}

// getRateLimit returns the rate limit and window for an endpoint type
func (m *OAuthRateLimitMiddleware) getRateLimit(endpoint string) (int, time.Duration) {
	rateLimitConfig := facades.Config().Get("oauth.rate_limiting").(map[string]interface{})

	switch endpoint {
	case "authorization":
		limit := rateLimitConfig["authorization_requests_per_minute"].(int)
		return limit, time.Minute
	case "token":
		limit := rateLimitConfig["token_requests_per_minute"].(int)
		return limit, time.Minute
	case "userinfo":
		// UserInfo typically has higher limits since it's used frequently
		return 300, time.Minute
	case "introspection":
		limit := rateLimitConfig["introspection_requests_per_minute"].(int)
		return limit, time.Minute
	case "revocation":
		limit := rateLimitConfig["revocation_requests_per_minute"].(int)
		return limit, time.Minute
	case "device":
		// Device flow has lower limits to prevent abuse
		return 10, time.Minute
	case "client_registration":
		limit := rateLimitConfig["client_registration_requests_per_minute"].(int)
		return limit, time.Minute
	case "jwks":
		// JWKS can be cached, so higher limits are acceptable
		return 1000, time.Minute
	case "discovery":
		// Discovery endpoints can be cached, very high limits
		return 2000, time.Minute
	default:
		return 100, time.Minute
	}
}

// isRateLimited checks if the client has exceeded the rate limit
func (m *OAuthRateLimitMiddleware) isRateLimited(clientID, endpoint string, limit int, window time.Duration) bool {
	key := fmt.Sprintf("%s:%s", clientID, endpoint)

	now := time.Now()
	info, exists := m.cache[key]

	if !exists {
		return false
	}

	// Check if window has expired
	if now.After(info.ResetTime) {
		return false
	}

	// Check if blocked due to previous violations
	if info.Blocked && now.Before(info.ResetTime) {
		return true
	}

	return info.Count >= limit
}

// incrementCounter increments the request counter for a client
func (m *OAuthRateLimitMiddleware) incrementCounter(clientID, endpoint string, window time.Duration) {
	key := fmt.Sprintf("%s:%s", clientID, endpoint)
	now := time.Now()

	info, exists := m.cache[key]
	if !exists || now.After(info.ResetTime) {
		m.cache[key] = &RateLimitInfo{
			Count:     1,
			ResetTime: now.Add(window),
			Blocked:   false,
		}
	} else {
		info.Count++
	}
}

// addRateLimitHeaders adds Google-like rate limit headers to the response
func (m *OAuthRateLimitMiddleware) addRateLimitHeaders(ctx http.Context, clientID, endpoint string, limit int, window time.Duration) {
	key := fmt.Sprintf("%s:%s", clientID, endpoint)
	info, exists := m.cache[key]

	if !exists {
		return
	}

	remaining := limit - info.Count
	if remaining < 0 {
		remaining = 0
	}

	resetTime := info.ResetTime.Unix()

	// Add standard rate limit headers
	ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(limit))
	ctx.Response().Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

	// Add Google-style headers
	ctx.Response().Header("X-RateLimit-Window", window.String())
	ctx.Response().Header("X-RateLimit-Endpoint", endpoint)
}

// rateLimitExceededResponse returns a rate limit exceeded error response
func (m *OAuthRateLimitMiddleware) rateLimitExceededResponse(ctx http.Context, limit int, window time.Duration) http.Response {
	// Mark client as blocked for additional time (exponential backoff could be added)
	clientID := m.getClientIdentifier(ctx)
	endpoint := m.getEndpointType(ctx.Request().Path())
	key := fmt.Sprintf("%s:%s", clientID, endpoint)

	if info, exists := m.cache[key]; exists {
		info.Blocked = true
		// Extend block time for repeated violations
		info.ResetTime = time.Now().Add(window * 2)
	}

	// Add rate limit headers
	ctx.Response().Header("X-RateLimit-Limit", strconv.Itoa(limit))
	ctx.Response().Header("X-RateLimit-Remaining", "0")
	ctx.Response().Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(window).Unix(), 10))
	ctx.Response().Header("Retry-After", strconv.Itoa(int(window.Seconds())))

	// Return OAuth2-compliant error response
	return responses.OAuth2ErrorResponse(ctx, "temporarily_unavailable",
		fmt.Sprintf("Rate limit exceeded. Limit: %d requests per %s", limit, window), 429)
}

// CleanupExpiredEntries removes expired entries from the cache (should be called periodically)
func (m *OAuthRateLimitMiddleware) CleanupExpiredEntries() {
	now := time.Now()
	for key, info := range m.cache {
		if now.After(info.ResetTime) {
			delete(m.cache, key)
		}
	}
}
