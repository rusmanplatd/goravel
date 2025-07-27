package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

// SecurityThreat represents different types of security threats
type SecurityThreat string

const (
	ThreatSuspiciousUserAgent SecurityThreat = "suspicious_user_agent"
	ThreatRapidRequests       SecurityThreat = "rapid_requests"
	ThreatUnusualLocation     SecurityThreat = "unusual_location"
	ThreatTokenReuse          SecurityThreat = "token_reuse"
	ThreatBruteForce          SecurityThreat = "brute_force"
	ThreatAnomalousPattern    SecurityThreat = "anomalous_pattern"
)

// ThreatAnalysis represents the result of threat analysis
type ThreatAnalysis struct {
	ThreatLevel     string           `json:"threat_level"` // "low", "medium", "high", "critical"
	Threats         []SecurityThreat `json:"threats"`
	RiskScore       int              `json:"risk_score"` // 0-100
	Blocked         bool             `json:"blocked"`
	Reason          string           `json:"reason"`
	Recommendations []string         `json:"recommendations"`
}

// AuthConfig represents authentication middleware configuration
type AuthConfig struct {
	RequireActiveUser      bool
	RequireMFA             bool
	RequireWebAuthn        bool
	AllowedRoles           []string
	AllowedPermissions     []string
	MaxSessionAge          time.Duration
	CheckIPRestrictions    bool
	EnableThreatDetection  bool
	EnableAnomalyDetection bool
	MaxRiskScore           int
}

// Auth returns a middleware function for API authentication using JWT tokens
func Auth() http.Middleware {
	return AuthWithConfig(AuthConfig{
		RequireActiveUser:      true,
		MaxSessionAge:          24 * time.Hour,
		CheckIPRestrictions:    true,
		EnableThreatDetection:  true,
		EnableAnomalyDetection: true,
		MaxRiskScore:           70,
	})
}

// AuthWithMFA returns middleware that requires MFA authentication
func AuthWithMFA() http.Middleware {
	return AuthWithConfig(AuthConfig{
		RequireActiveUser:      true,
		RequireMFA:             true,
		MaxSessionAge:          24 * time.Hour,
		EnableThreatDetection:  true,
		EnableAnomalyDetection: true,
		MaxRiskScore:           50, // Lower tolerance for MFA-protected routes
	})
}

// AuthWithWebAuthn returns middleware that requires WebAuthn authentication
func AuthWithWebAuthn() http.Middleware {
	return AuthWithConfig(AuthConfig{
		RequireActiveUser:      true,
		RequireWebAuthn:        true,
		MaxSessionAge:          24 * time.Hour,
		EnableThreatDetection:  true,
		EnableAnomalyDetection: true,
		MaxRiskScore:           50,
	})
}

// AuthWithRoles returns middleware that requires specific roles
func AuthWithRoles(roles ...string) http.Middleware {
	return AuthWithConfig(AuthConfig{
		RequireActiveUser:      true,
		AllowedRoles:           roles,
		MaxSessionAge:          24 * time.Hour,
		EnableThreatDetection:  true,
		EnableAnomalyDetection: true,
		MaxRiskScore:           60,
	})
}

// AuthWithPermissions returns middleware that requires specific permissions
func AuthWithPermissions(permissions ...string) http.Middleware {
	return AuthWithConfig(AuthConfig{
		RequireActiveUser:      true,
		AllowedPermissions:     permissions,
		MaxSessionAge:          24 * time.Hour,
		EnableThreatDetection:  true,
		EnableAnomalyDetection: true,
		MaxRiskScore:           60,
	})
}

// AuthWithConfig returns a middleware function with custom configuration
func AuthWithConfig(config AuthConfig) http.Middleware {
	auditService := services.NewAuditService()

	return func(ctx http.Context) {
		// Enhanced threat detection
		if config.EnableThreatDetection {
			threatAnalysis := performThreatAnalysis(ctx)
			if threatAnalysis.Blocked {
				auditService.LogSecurityEvent("auth_threat_blocked", threatAnalysis.Reason, ctx, map[string]interface{}{
					"threat_level":    threatAnalysis.ThreatLevel,
					"risk_score":      threatAnalysis.RiskScore,
					"threats":         threatAnalysis.Threats,
					"recommendations": threatAnalysis.Recommendations,
				})
				respondWithThreatBlocked(ctx, threatAnalysis)
				return
			}
		}

		// Get Authorization header
		authHeader := ctx.Request().Header("Authorization", "")
		if authHeader == "" {
			auditService.LogSecurityEvent("auth_missing_header", "Authorization header missing", ctx, map[string]interface{}{})
			respondWithError(ctx, "Authorization header required", 401)
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			auditService.LogSecurityEvent("auth_invalid_format", "Invalid authorization format", ctx, map[string]interface{}{
				"auth_header_prefix": authHeader[:min(len(authHeader), 20)],
			})
			respondWithError(ctx, "Invalid authorization format", 401)
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			auditService.LogSecurityEvent("auth_empty_token", "Empty authorization token", ctx, map[string]interface{}{})
			respondWithError(ctx, "Empty authorization token", 401)
			return
		}

		// Enhanced token validation with security checks
		user, claims, tokenAnalysis, err := validateTokenWithSecurityAnalysis(token, ctx)
		if err != nil {
			auditService.LogSecurityEvent("auth_token_validation_failed", "Token validation failed", ctx, map[string]interface{}{
				"error":          err.Error(),
				"token_analysis": tokenAnalysis,
			})
			respondWithError(ctx, "Invalid token", 401)
			return
		}

		// Check if user is active (if required)
		if config.RequireActiveUser && !user.IsActive {
			auditService.LogSecurityEvent("auth_inactive_user", "Inactive user attempted access", ctx, map[string]interface{}{
				"user_id": user.ID,
			})
			respondWithError(ctx, "Account is deactivated", 403)
			return
		}

		// Check account lockout
		if user.LockedAt != nil && user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
			auditService.LogSecurityEvent("auth_locked_user", "Locked user attempted access", ctx, map[string]interface{}{
				"user_id":      user.ID,
				"locked_until": user.LockedUntil,
			})
			respondWithError(ctx, "Account is temporarily locked", 423)
			return
		}

		// Check session age
		if config.MaxSessionAge > 0 && claims != nil {
			sessionAge := time.Since(claims.IssuedAt.Time)
			if sessionAge > config.MaxSessionAge {
				auditService.LogSecurityEvent("auth_session_expired", "Session expired due to age", ctx, map[string]interface{}{
					"user_id":     user.ID,
					"session_age": sessionAge,
					"max_age":     config.MaxSessionAge,
				})
				respondWithError(ctx, "Session expired", 401)
				return
			}
		}

		// Enhanced anomaly detection
		if config.EnableAnomalyDetection {
			anomalies := detectUserAnomalies(user, ctx, claims)
			if len(anomalies) > 0 {
				riskScore := calculateAnomalyRiskScore(anomalies)
				if riskScore > config.MaxRiskScore {
					auditService.LogSecurityEvent("auth_anomaly_detected", "User behavior anomaly detected", ctx, map[string]interface{}{
						"user_id":    user.ID,
						"anomalies":  anomalies,
						"risk_score": riskScore,
					})
					respondWithAnomalyDetected(ctx, anomalies, riskScore)
					return
				}
			}
		}

		// Check IP restrictions if enabled
		if config.CheckIPRestrictions {
			if err := checkEnhancedIPRestrictions(user, ctx); err != nil {
				auditService.LogSecurityEvent("auth_ip_restriction", "IP restriction violation", ctx, map[string]interface{}{
					"user_id": user.ID,
					"error":   err.Error(),
				})
				respondWithError(ctx, "Access from this IP is not allowed", 403)
				return
			}
		}

		// Check MFA requirement
		if config.RequireMFA && !user.MfaEnabled {
			respondWithError(ctx, "Multi-factor authentication required", 403)
			return
		}

		// Check WebAuthn requirement
		if config.RequireWebAuthn && !user.WebauthnEnabled {
			respondWithError(ctx, "WebAuthn authentication required", 403)
			return
		}

		// Check role requirements
		if len(config.AllowedRoles) > 0 {
			if !userHasAnyRole(user, config.AllowedRoles) {
				facades.Log().Warning("Insufficient role permissions", map[string]interface{}{
					"user_id":        user.ID,
					"required_roles": config.AllowedRoles,
				})
				respondWithError(ctx, "Insufficient permissions", 403)
				return
			}
		}

		// Check permission requirements
		if len(config.AllowedPermissions) > 0 {
			if !userHasAnyPermission(user, config.AllowedPermissions) {
				facades.Log().Warning("Insufficient permissions", map[string]interface{}{
					"user_id":              user.ID,
					"required_permissions": config.AllowedPermissions,
				})
				respondWithError(ctx, "Insufficient permissions", 403)
				return
			}
		}

		// Update last activity
		updateLastActivity(user, ctx)

		// Add user and claims to context
		ctx.WithValue("user", user)
		ctx.WithValue("user_id", user.ID)
		ctx.WithValue("jwt_claims", claims)

		// Add security headers
		addSecurityHeaders(ctx)

		// Continue to next middleware/handler
		ctx.Request().Next()
	}
}

// OptionalAuth returns a middleware that doesn't require authentication but adds user context if available
func OptionalAuth() http.Middleware {
	return func(ctx http.Context) {
		authHeader := ctx.Request().Header("Authorization", "")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if user, claims, err := validateTokenWithClaims(token); err == nil && user.IsActive {
				ctx.WithValue("user", user)
				ctx.WithValue("user_id", user.ID)
				ctx.WithValue("jwt_claims", claims)
			}
		}

		addSecurityHeaders(ctx)
		ctx.Request().Next()
	}
}

// validateTokenWithClaims validates JWT token and returns user with claims
func validateTokenWithClaims(token string) (*models.User, *services.JWTClaims, error) {
	// Create JWT service instance with proper error handling
	jwtService, err := services.NewJWTService()
	if err != nil {
		facades.Log().Error("Failed to initialize JWT service in auth middleware", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, nil, fmt.Errorf("JWT service initialization failed: %w", err)
	}

	// Validate token using JWT service
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check if it's an access token
	if claims.Type != "access" {
		return nil, nil, fmt.Errorf("invalid token type")
	}

	// Find user by ID
	var user models.User
	err = facades.Orm().Query().Where("id", claims.UserID).First(&user)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}

	return &user, claims, nil
}

// checkIPRestrictions checks if the user is allowed to access from the current IP
func checkIPRestrictions(user *models.User, ctx http.Context) error {
	// Get client IP
	clientIP := ctx.Request().Ip()

	// Check X-Forwarded-For for real IP
	if xff := ctx.Request().Header("X-Forwarded-For", ""); xff != "" {
		// Take the first IP from the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	}

	// Check if IP is in allowed list (this would typically be stored in database)
	// For now, we'll check against a simple configuration
	allowedIPsStr := facades.Config().GetString("auth.allowed_ips", "")
	if allowedIPsStr != "" {
		allowedIPs := strings.Split(allowedIPsStr, ",")
		for _, allowedIP := range allowedIPs {
			allowedIP = strings.TrimSpace(allowedIP)
			if clientIP == allowedIP || strings.HasPrefix(clientIP, allowedIP) {
				return nil
			}
		}
		return fmt.Errorf("IP %s not in allowed list", clientIP)
	}

	// Check if IP is in blocked list
	blockedIPsStr := facades.Config().GetString("auth.blocked_ips", "")
	if blockedIPsStr != "" {
		blockedIPs := strings.Split(blockedIPsStr, ",")
		for _, blockedIP := range blockedIPs {
			blockedIP = strings.TrimSpace(blockedIP)
			if clientIP == blockedIP || strings.HasPrefix(clientIP, blockedIP) {
				return fmt.Errorf("IP %s is blocked", clientIP)
			}
		}
	}

	return nil
}

// userHasAnyRole checks if user has any of the required roles
func userHasAnyRole(user *models.User, requiredRoles []string) bool {
	// Load user roles if not already loaded
	if len(user.Roles) == 0 {
		var userWithRoles models.User
		err := facades.Orm().Query().With("Roles").Where("id", user.ID).First(&userWithRoles)
		if err == nil {
			user.Roles = userWithRoles.Roles
		}
	}

	// Check if user has any of the required roles
	for _, userRole := range user.Roles {
		for _, requiredRole := range requiredRoles {
			if userRole.Name == requiredRole {
				return true
			}
		}
	}

	return false
}

// userHasAnyPermission checks if user has any of the required permissions
func userHasAnyPermission(user *models.User, requiredPermissions []string) bool {
	// Load user roles if not already loaded
	if len(user.Roles) == 0 {
		var userWithRoles models.User
		err := facades.Orm().Query().With("Roles").Where("id", user.ID).First(&userWithRoles)
		if err == nil {
			user.Roles = userWithRoles.Roles
		}
	}

	// Check permissions through roles (simplified - TODO: In production you'd load role permissions)
	// For now, we'll assume roles have the permissions they need
	for _, userRole := range user.Roles {
		// This is a simplified check - TODO: In production you'd have a proper permission system
		for _, requiredPermission := range requiredPermissions {
			// Basic role-to-permission mapping
			if (userRole.Name == "admin" && requiredPermission != "") ||
				(userRole.Name == "user" && (requiredPermission == "read" || requiredPermission == "basic")) {
				return true
			}
		}
	}

	return false
}

// updateLastActivity updates the user's last activity timestamp
func updateLastActivity(user *models.User, ctx http.Context) {
	// Update in background to avoid blocking the request
	go func() {
		now := time.Now()
		user.LastLoginAt = &now
		user.LastLoginIp = ctx.Request().Ip()
		user.LastLoginUserAgent = ctx.Request().Header("User-Agent", "")

		// Save without error handling to avoid blocking
		facades.Orm().Query().Save(user)
	}()
}

// addSecurityHeaders adds security headers to the response
func addSecurityHeaders(ctx http.Context) {
	ctx.Response().Header("X-Content-Type-Options", "nosniff")
	ctx.Response().Header("X-Frame-Options", "DENY")
	ctx.Response().Header("X-XSS-Protection", "1; mode=block")
	ctx.Response().Header("Referrer-Policy", "strict-origin-when-cross-origin")
	ctx.Response().Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	ctx.Response().Header("Pragma", "no-cache")
	ctx.Response().Header("Expires", "0")
}

// respondWithError sends an error response and aborts the request
func respondWithError(ctx http.Context, message string, status int) {
	ctx.Response().Status(status).Json(map[string]interface{}{
		"status":  "error",
		"message": message,
		"code":    status,
	}).Abort()
}

// GetUserFromContext extracts the user from the request context
func GetUserFromContext(ctx http.Context) *models.User {
	if user := ctx.Value("user"); user != nil {
		if u, ok := user.(*models.User); ok {
			return u
		}
	}
	return nil
}

// GetJWTClaimsFromContext extracts the JWT claims from the request context
func GetJWTClaimsFromContext(ctx http.Context) *services.JWTClaims {
	if claims := ctx.Value("jwt_claims"); claims != nil {
		if c, ok := claims.(*services.JWTClaims); ok {
			return c
		}
	}
	return nil
}

// Enhanced security analysis functions

// performThreatAnalysis analyzes incoming requests for security threats
func performThreatAnalysis(ctx http.Context) *ThreatAnalysis {
	var threats []SecurityThreat
	riskScore := 0

	userAgent := ctx.Request().Header("User-Agent", "")
	ip := ctx.Request().Ip()

	// Check for suspicious user agents
	if isSuspiciousUserAgent(userAgent) {
		threats = append(threats, ThreatSuspiciousUserAgent)
		riskScore += 30
	}

	// Check for rapid requests from same IP
	if isRapidRequests(ip) {
		threats = append(threats, ThreatRapidRequests)
		riskScore += 40
	}

	// Check for unusual geographical location
	if isUnusualLocation(ip) {
		threats = append(threats, ThreatUnusualLocation)
		riskScore += 20
	}

	// Determine threat level
	var threatLevel string
	var blocked bool
	var reason string
	var recommendations []string

	switch {
	case riskScore >= 80:
		threatLevel = "critical"
		blocked = true
		reason = "Critical security threat detected"
		recommendations = []string{"Block request", "Investigate source", "Alert security team"}
	case riskScore >= 60:
		threatLevel = "high"
		blocked = false
		reason = "High risk activity detected"
		recommendations = []string{"Monitor closely", "Require additional verification"}
	case riskScore >= 30:
		threatLevel = "medium"
		blocked = false
		reason = "Medium risk activity detected"
		recommendations = []string{"Log for analysis", "Monitor user behavior"}
	default:
		threatLevel = "low"
		blocked = false
		reason = "Normal activity"
		recommendations = []string{"Continue monitoring"}
	}

	return &ThreatAnalysis{
		ThreatLevel:     threatLevel,
		Threats:         threats,
		RiskScore:       riskScore,
		Blocked:         blocked,
		Reason:          reason,
		Recommendations: recommendations,
	}
}

// validateTokenWithSecurityAnalysis validates token with additional security analysis
func validateTokenWithSecurityAnalysis(token string, ctx http.Context) (*models.User, *services.JWTClaims, map[string]interface{}, error) {
	// Use existing token validation
	user, claims, err := validateTokenWithClaims(token)

	tokenAnalysis := map[string]interface{}{
		"token_length": len(token),
		"ip_address":   ctx.Request().Ip(),
		"user_agent":   ctx.Request().Header("User-Agent", ""),
	}

	if err != nil {
		tokenAnalysis["validation_error"] = err.Error()
		return nil, nil, tokenAnalysis, err
	}

	// Additional security checks
	if claims != nil {
		tokenAnalysis["issued_at"] = claims.IssuedAt
		tokenAnalysis["expires_at"] = claims.ExpiresAt
		tokenAnalysis["user_id"] = claims.UserID
	}

	return user, claims, tokenAnalysis, nil
}

// detectUserAnomalies detects anomalous user behavior patterns
func detectUserAnomalies(user *models.User, ctx http.Context, claims *services.JWTClaims) []string {
	var anomalies []string

	currentIP := ctx.Request().Ip()
	currentUA := ctx.Request().Header("User-Agent", "")

	// Check for IP address changes
	if isIPAddressAnomaly(user.ID, currentIP) {
		anomalies = append(anomalies, "unusual_ip_address")
	}

	// Check for user agent changes
	if isUserAgentAnomaly(user.ID, currentUA) {
		anomalies = append(anomalies, "unusual_user_agent")
	}

	// Check for unusual access patterns
	if isUnusualAccessPattern(user.ID, ctx.Request().Path()) {
		anomalies = append(anomalies, "unusual_access_pattern")
	}

	// Check for time-based anomalies
	if isUnusualAccessTime(user.ID) {
		anomalies = append(anomalies, "unusual_access_time")
	}

	return anomalies
}

// calculateAnomalyRiskScore calculates risk score based on detected anomalies
func calculateAnomalyRiskScore(anomalies []string) int {
	baseScore := 0

	for _, anomaly := range anomalies {
		switch anomaly {
		case "unusual_ip_address":
			baseScore += 25
		case "unusual_user_agent":
			baseScore += 15
		case "unusual_access_pattern":
			baseScore += 20
		case "unusual_access_time":
			baseScore += 10
		default:
			baseScore += 5
		}
	}

	// Cap at 100
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// checkEnhancedIPRestrictions performs enhanced IP restriction checks
func checkEnhancedIPRestrictions(user *models.User, ctx http.Context) error {
	ip := ctx.Request().Ip()

	// Check if IP is in blocked list
	if isIPBlocked(ip) {
		return fmt.Errorf("IP address is blocked")
	}

	// Check geographical restrictions
	if isGeoBlocked(ip) {
		return fmt.Errorf("access from this geographical location is restricted")
	}

	// Check for VPN/Proxy usage
	if isVPNOrProxy(ip) {
		return fmt.Errorf("access through VPN or proxy is not allowed")
	}

	return nil
}

// Helper functions for threat detection

func isSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"bot", "crawler", "spider", "scraper",
		"curl", "wget", "python", "java",
		"automated", "script",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

func isRapidRequests(ip string) bool {
	// Production rate limiting using Redis
	key := fmt.Sprintf("rate_limit:%s", ip)

	// Get current count
	current := facades.Cache().GetInt(key, 0)

	// Allow up to 100 requests per minute
	limit := 100
	window := time.Minute

	if current >= limit {
		facades.Log().Warning("Rate limit exceeded", map[string]interface{}{
			"ip":      ip,
			"current": current,
			"limit":   limit,
		})
		return true
	}

	// Increment counter with expiration
	facades.Cache().Put(key, current+1, window)
	return false
}

func isUnusualLocation(ip string) bool {
	// Use production GeoIP service to check location
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
		return false // Local requests are normal
	}

	// Create GeoIP service instance
	geoService := services.NewGeoIPService()
	defer geoService.Close()

	if !geoService.IsEnabled() {
		return false // Skip check if GeoIP not available
	}

	location := geoService.GetLocation(ip)

	// Check for suspicious indicators
	if location.IsVPN || location.IsProxy || location.IsTor {
		facades.Log().Warning("Suspicious location detected", map[string]interface{}{
			"ip":       ip,
			"country":  location.Country,
			"is_vpn":   location.IsVPN,
			"is_proxy": location.IsProxy,
			"is_tor":   location.IsTor,
		})
		return true
	}

	// Check against blocked countries (configurable)
	blockedCountries := facades.Config().GetString("security.blocked_countries", "")
	if blockedCountries != "" {
		blocked := strings.Split(blockedCountries, ",")
		for _, country := range blocked {
			if strings.EqualFold(strings.TrimSpace(country), location.CountryCode) {
				facades.Log().Warning("Access from blocked country", map[string]interface{}{
					"ip":      ip,
					"country": location.Country,
					"code":    location.CountryCode,
				})
				return true
			}
		}
	}

	return false
}

func isIPAddressAnomaly(userID, currentIP string) bool {
	// Check user's IP history for anomalies
	key := fmt.Sprintf("user_ips:%s", userID)

	// Get user's recent IPs from cache/database
	var recentIPs []string
	if ipsData := facades.Cache().GetString(key); ipsData != "" {
		json.Unmarshal([]byte(ipsData), &recentIPs)
	}

	// Check if current IP is in recent history
	for _, ip := range recentIPs {
		if ip == currentIP {
			return false // Known IP
		}
	}

	// If we have a history and this is a new IP, it's potentially anomalous
	if len(recentIPs) > 0 {
		// Get GeoIP info for comparison
		geoService := services.NewGeoIPService()
		defer geoService.Close()

		if geoService.IsEnabled() {
			currentLocation := geoService.GetLocation(currentIP)

			// Check if it's from a completely different country than recent activity
			for _, recentIP := range recentIPs {
				recentLocation := geoService.GetLocation(recentIP)
				if currentLocation.CountryCode != recentLocation.CountryCode {
					facades.Log().Warning("IP address anomaly detected", map[string]interface{}{
						"user_id":         userID,
						"current_ip":      currentIP,
						"current_country": currentLocation.CountryCode,
						"recent_country":  recentLocation.CountryCode,
					})
					return true
				}
			}
		}
	}

	// Add current IP to history (keep last 10)
	recentIPs = append([]string{currentIP}, recentIPs...)
	if len(recentIPs) > 10 {
		recentIPs = recentIPs[:10]
	}

	// Store updated history
	if data, err := json.Marshal(recentIPs); err == nil {
		facades.Cache().Put(key, string(data), 24*time.Hour)
	}

	return false
}

func isUserAgentAnomaly(userID, currentUA string) bool {
	// Check user's User Agent history for anomalies
	key := fmt.Sprintf("user_agents:%s", userID)

	// Get user's recent User Agents from cache
	var recentUAs []string
	if uasData := facades.Cache().GetString(key); uasData != "" {
		json.Unmarshal([]byte(uasData), &recentUAs)
	}

	// Check if current UA is in recent history
	for _, ua := range recentUAs {
		if ua == currentUA {
			return false // Known User Agent
		}
	}

	// If we have history and this is completely new, it might be anomalous
	if len(recentUAs) > 0 {
		// Simple check for drastically different user agents
		// (e.g., switching from Chrome to curl or automated tools)
		if strings.Contains(strings.ToLower(currentUA), "bot") ||
			strings.Contains(strings.ToLower(currentUA), "crawler") ||
			strings.Contains(strings.ToLower(currentUA), "curl") ||
			strings.Contains(strings.ToLower(currentUA), "wget") {

			facades.Log().Warning("Suspicious user agent detected", map[string]interface{}{
				"user_id":    userID,
				"user_agent": currentUA,
			})
			return true
		}
	}

	// Add current UA to history (keep last 5)
	recentUAs = append([]string{currentUA}, recentUAs...)
	if len(recentUAs) > 5 {
		recentUAs = recentUAs[:5]
	}

	// Store updated history
	if data, err := json.Marshal(recentUAs); err == nil {
		facades.Cache().Put(key, string(data), 24*time.Hour)
	}

	return false
}

func isUnusualAccessPattern(userID, path string) bool {
	// Analyze user's access patterns for anomalies
	key := fmt.Sprintf("user_patterns:%s", userID)

	// Get user's access pattern data
	type AccessPattern struct {
		Paths      map[string]int `json:"paths"`
		LastAccess time.Time      `json:"last_access"`
	}

	var pattern AccessPattern
	if patternData := facades.Cache().GetString(key); patternData != "" {
		json.Unmarshal([]byte(patternData), &pattern)
	} else {
		pattern.Paths = make(map[string]int)
	}

	// Check for rapid sequential access to sensitive endpoints
	sensitiveEndpoints := []string{"/admin", "/api/users", "/api/oauth", "/api/security"}
	isSensitive := false
	for _, endpoint := range sensitiveEndpoints {
		if strings.HasPrefix(path, endpoint) {
			isSensitive = true
			break
		}
	}

	if isSensitive {
		// Check if accessing sensitive endpoints too rapidly
		if time.Since(pattern.LastAccess) < 5*time.Second {
			facades.Log().Warning("Rapid access to sensitive endpoints", map[string]interface{}{
				"user_id": userID,
				"path":    path,
				"gap":     time.Since(pattern.LastAccess),
			})
			return true
		}
	}

	// Update pattern data
	pattern.Paths[path]++
	pattern.LastAccess = time.Now()

	// Store updated pattern
	if data, err := json.Marshal(pattern); err == nil {
		facades.Cache().Put(key, string(data), 24*time.Hour)
	}

	return false
}

func isUnusualAccessTime(userID string) bool {
	// Analyze user's typical access times
	key := fmt.Sprintf("user_times:%s", userID)

	// Get user's access time history
	var accessTimes []int // Hours of the day (0-23)
	if timesData := facades.Cache().GetString(key); timesData != "" {
		json.Unmarshal([]byte(timesData), &accessTimes)
	}

	currentHour := time.Now().Hour()

	// If we have history, check if current time is unusual
	if len(accessTimes) > 10 { // Need sufficient history
		// Count occurrences of current hour
		hourCount := 0
		for _, hour := range accessTimes {
			if hour == currentHour {
				hourCount++
			}
		}

		// If this hour represents less than 5% of access times, it's unusual
		if float64(hourCount)/float64(len(accessTimes)) < 0.05 {
			facades.Log().Info("Unusual access time detected", map[string]interface{}{
				"user_id":      userID,
				"current_hour": currentHour,
				"frequency":    float64(hourCount) / float64(len(accessTimes)),
			})
			return true
		}
	}

	// Add current hour to history (keep last 100 entries)
	accessTimes = append(accessTimes, currentHour)
	if len(accessTimes) > 100 {
		accessTimes = accessTimes[1:]
	}

	// Store updated times
	if data, err := json.Marshal(accessTimes); err == nil {
		facades.Cache().Put(key, string(data), 7*24*time.Hour) // Keep for a week
	}

	return false
}

func isIPBlocked(ip string) bool {
	// Check against IP blocklist stored in Redis/database
	key := fmt.Sprintf("blocked_ip:%s", ip)

	// Check if IP is in blocked list
	if facades.Cache().Has(key) {
		facades.Log().Warning("Blocked IP attempted access", map[string]interface{}{
			"ip": ip,
		})
		return true
	}

	// Check against subnet blocks
	blockedSubnets := facades.Config().GetString("security.blocked_subnets", "")
	if blockedSubnets != "" {
		subnets := strings.Split(blockedSubnets, ",")
		for _, subnet := range subnets {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" {
				continue
			}

			_, network, err := net.ParseCIDR(subnet)
			if err != nil {
				continue
			}

			ipAddr := net.ParseIP(ip)
			if ipAddr != nil && network.Contains(ipAddr) {
				facades.Log().Warning("IP from blocked subnet attempted access", map[string]interface{}{
					"ip":     ip,
					"subnet": subnet,
				})
				return true
			}
		}
	}

	return false
}

func isGeoBlocked(ip string) bool {
	// Check geographical restrictions using GeoIP service
	geoService := services.NewGeoIPService()
	defer geoService.Close()

	if !geoService.IsEnabled() {
		return false // Skip check if GeoIP not available
	}

	location := geoService.GetLocation(ip)

	// Check against blocked countries
	blockedCountries := facades.Config().GetString("security.geo_blocked_countries", "")
	if blockedCountries != "" {
		blocked := strings.Split(blockedCountries, ",")
		for _, country := range blocked {
			if strings.EqualFold(strings.TrimSpace(country), location.CountryCode) {
				facades.Log().Warning("Access blocked due to geographical restrictions", map[string]interface{}{
					"ip":      ip,
					"country": location.Country,
					"code":    location.CountryCode,
				})
				return true
			}
		}
	}

	// Check for high-risk regions (configurable)
	highRiskCountries := facades.Config().GetString("security.high_risk_countries", "")
	if highRiskCountries != "" {
		highRisk := strings.Split(highRiskCountries, ",")
		for _, country := range highRisk {
			if strings.EqualFold(strings.TrimSpace(country), location.CountryCode) {
				// Log but don't block, just flag for additional monitoring
				facades.Log().Info("Access from high-risk region", map[string]interface{}{
					"ip":      ip,
					"country": location.Country,
					"code":    location.CountryCode,
				})
				break
			}
		}
	}

	return false
}

func isVPNOrProxy(ip string) bool {
	// Use GeoIP service for VPN/proxy detection
	geoService := services.NewGeoIPService()
	defer geoService.Close()

	if !geoService.IsEnabled() {
		return false // Skip check if GeoIP not available
	}

	location := geoService.GetLocation(ip)

	// Check VPN/Proxy detection from GeoIP
	if location.IsVPN || location.IsProxy || location.IsTor {
		facades.Log().Warning("VPN/Proxy/Tor access detected", map[string]interface{}{
			"ip":       ip,
			"is_vpn":   location.IsVPN,
			"is_proxy": location.IsProxy,
			"is_tor":   location.IsTor,
			"isp":      location.ISP,
		})

		// Check if VPN/Proxy access is allowed
		allowVPN := facades.Config().GetBool("security.allow_vpn_access", true)
		if !allowVPN {
			return true // Block VPN/Proxy access
		}
	}

	return false
}

// Enhanced response functions

func respondWithThreatBlocked(ctx http.Context, analysis *ThreatAnalysis) {
	ctx.Response().Header("X-Threat-Level", analysis.ThreatLevel)
	ctx.Response().Header("X-Risk-Score", fmt.Sprintf("%d", analysis.RiskScore))

	ctx.Response().Status(403).Json(http.Json{
		"error":   "Security threat detected",
		"message": analysis.Reason,
		"details": map[string]interface{}{
			"threat_level": analysis.ThreatLevel,
			"risk_score":   analysis.RiskScore,
			"threats":      analysis.Threats,
		},
	})
}

func respondWithAnomalyDetected(ctx http.Context, anomalies []string, riskScore int) {
	ctx.Response().Header("X-Anomaly-Detected", "true")
	ctx.Response().Header("X-Risk-Score", fmt.Sprintf("%d", riskScore))

	ctx.Response().Status(403).Json(http.Json{
		"error":   "Anomalous behavior detected",
		"message": "Unusual activity pattern detected for your account",
		"details": map[string]interface{}{
			"anomalies":  anomalies,
			"risk_score": riskScore,
			"action":     "Please verify your identity or contact support",
		},
	})
}

// Utility functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
