package middleware

import (
	"fmt"
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
	// Create JWT service instance
	jwtService := services.NewJWTService()

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

	// Check permissions through roles (simplified - in production you'd load role permissions)
	// For now, we'll assume roles have the permissions they need
	for _, userRole := range user.Roles {
		// This is a simplified check - in production you'd have a proper permission system
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
	// Check request rate from IP (simplified implementation)
	// In production, use Redis or similar for distributed rate limiting
	key := fmt.Sprintf("rate_check:%s", ip)
	// This is a placeholder - implement proper rate checking
	_ = key
	return false
}

func isUnusualLocation(ip string) bool {
	// Check if IP is from unusual geographical location
	// In production, use GeoIP service
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
		return false // Local requests are normal
	}
	return false // Placeholder
}

func isIPAddressAnomaly(userID, currentIP string) bool {
	// Check if this IP is unusual for this user
	// In production, maintain user IP history
	return false // Placeholder
}

func isUserAgentAnomaly(userID, currentUA string) bool {
	// Check if this user agent is unusual for this user
	// In production, maintain user agent history
	return false // Placeholder
}

func isUnusualAccessPattern(userID, path string) bool {
	// Check if this access pattern is unusual for this user
	// In production, analyze user behavior patterns
	return false // Placeholder
}

func isUnusualAccessTime(userID string) bool {
	// Check if current access time is unusual for this user
	// In production, analyze user's typical access times
	return false // Placeholder
}

func isIPBlocked(ip string) bool {
	// Check against IP blocklist
	// In production, maintain a blocklist in Redis or database
	return false // Placeholder
}

func isGeoBlocked(ip string) bool {
	// Check geographical restrictions
	// In production, use GeoIP service and restriction rules
	return false // Placeholder
}

func isVPNOrProxy(ip string) bool {
	// Check if IP is from VPN or proxy service
	// In production, use VPN/proxy detection service
	return false // Placeholder
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
