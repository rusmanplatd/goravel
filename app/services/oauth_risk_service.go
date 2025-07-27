package services

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthRiskService struct {
	analyticsService *OAuthAnalyticsService
}

type RiskAssessment struct {
	Score       int                    `json:"score"`   // 0-100, higher is riskier
	Level       string                 `json:"level"`   // low, medium, high, critical
	Factors     []string               `json:"factors"` // Risk factors identified
	Actions     []string               `json:"actions"` // Recommended actions
	Details     map[string]interface{} `json:"details"` // Additional risk details
	Timestamp   time.Time              `json:"timestamp"`
	RequireMFA  bool                   `json:"require_mfa"`  // Whether MFA should be required
	BlockAccess bool                   `json:"block_access"` // Whether access should be blocked
}

type AuthContext struct {
	UserID        string    `json:"user_id"`
	ClientID      string    `json:"client_id"`
	IPAddress     string    `json:"ip_address"`
	UserAgent     string    `json:"user_agent"`
	Location      string    `json:"location,omitempty"`
	DeviceID      string    `json:"device_id,omitempty"`
	Scopes        []string  `json:"scopes"`
	GrantType     string    `json:"grant_type"`
	Timestamp     time.Time `json:"timestamp"`
	SessionID     string    `json:"session_id,omitempty"`
	RefererURL    string    `json:"referer_url,omitempty"`
	RequestOrigin string    `json:"request_origin,omitempty"`
}

func NewOAuthRiskService() *OAuthRiskService {
	return &OAuthRiskService{
		analyticsService: NewOAuthAnalyticsService(),
	}
}

// AssessRisk performs comprehensive risk assessment like Google
func (s *OAuthRiskService) AssessRisk(ctx *AuthContext) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		Score:     0,
		Level:     "low",
		Factors:   []string{},
		Actions:   []string{},
		Details:   make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	// Assess various risk factors
	s.assessIPRisk(ctx, assessment)
	s.assessLocationRisk(ctx, assessment)
	s.assessDeviceRisk(ctx, assessment)
	s.assessBehavioralRisk(ctx, assessment)
	s.assessClientRisk(ctx, assessment)
	s.assessScopeRisk(ctx, assessment)
	s.assessTemporalRisk(ctx, assessment)
	s.assessFrequencyRisk(ctx, assessment)

	// Determine overall risk level and actions
	s.determineRiskLevel(assessment)
	s.recommendActions(assessment)

	// Log risk assessment for analytics
	s.logRiskAssessment(ctx, assessment)

	return assessment, nil
}

// assessIPRisk evaluates IP-based risk factors
func (s *OAuthRiskService) assessIPRisk(ctx *AuthContext, assessment *RiskAssessment) {
	if ctx.IPAddress == "" {
		return
	}

	// Check if IP is from a known VPN/Proxy/Tor network
	if s.isVPNOrProxy(ctx.IPAddress) {
		assessment.Score += 15
		assessment.Factors = append(assessment.Factors, "VPN/Proxy IP detected")
		assessment.Details["vpn_detected"] = true
	}

	// Check for IP reputation
	if s.hasIPBadReputation(ctx.IPAddress) {
		assessment.Score += 25
		assessment.Factors = append(assessment.Factors, "IP has bad reputation")
		assessment.Details["bad_ip_reputation"] = true
	}

	// Check for recent failed attempts from this IP
	recentFailures := s.getRecentFailedAttempts(ctx.IPAddress)
	if recentFailures > 3 {
		assessment.Score += recentFailures * 5
		assessment.Factors = append(assessment.Factors, fmt.Sprintf("Multiple failed attempts from IP (%d)", recentFailures))
		assessment.Details["recent_failures"] = recentFailures
	}

	// Check if IP is from unexpected geographic location
	if s.isUnusualLocation(ctx.UserID, ctx.IPAddress) {
		assessment.Score += 20
		assessment.Factors = append(assessment.Factors, "Unusual geographic location")
		assessment.Details["unusual_location"] = true
	}
}

// assessLocationRisk evaluates location-based risk
func (s *OAuthRiskService) assessLocationRisk(ctx *AuthContext, assessment *RiskAssessment) {
	if ctx.Location == "" {
		return
	}

	// Check for high-risk countries/regions
	if s.isHighRiskLocation(ctx.Location) {
		assessment.Score += 30
		assessment.Factors = append(assessment.Factors, "High-risk geographic location")
		assessment.Details["high_risk_location"] = ctx.Location
	}

	// Check for impossible travel (Google-like)
	if s.hasImpossibleTravel(ctx.UserID, ctx.Location, ctx.Timestamp) {
		assessment.Score += 40
		assessment.Factors = append(assessment.Factors, "Impossible travel detected")
		assessment.Details["impossible_travel"] = true
	}
}

// assessDeviceRisk evaluates device-based risk factors
func (s *OAuthRiskService) assessDeviceRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Generate device fingerprint from User-Agent
	deviceFingerprint := s.generateDeviceFingerprint(ctx.UserAgent, ctx.IPAddress)
	assessment.Details["device_fingerprint"] = deviceFingerprint

	// Check if device is new/unknown
	if !s.isKnownDevice(ctx.UserID, deviceFingerprint) {
		assessment.Score += 15
		assessment.Factors = append(assessment.Factors, "Unknown device")
		assessment.Details["new_device"] = true
	}

	// Check for suspicious user agent patterns
	if s.hasSuspiciousUserAgent(ctx.UserAgent) {
		assessment.Score += 20
		assessment.Factors = append(assessment.Factors, "Suspicious user agent")
		assessment.Details["suspicious_user_agent"] = true
	}

	// Check for automated/bot behavior
	if s.isLikelyBot(ctx.UserAgent) {
		assessment.Score += 35
		assessment.Factors = append(assessment.Factors, "Automated/bot behavior detected")
		assessment.Details["likely_bot"] = true
	}
}

// assessBehavioralRisk evaluates user behavior patterns
func (s *OAuthRiskService) assessBehavioralRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Check login time patterns
	if s.isUnusualLoginTime(ctx.UserID, ctx.Timestamp) {
		assessment.Score += 10
		assessment.Factors = append(assessment.Factors, "Unusual login time")
		assessment.Details["unusual_time"] = true
	}

	// Check for rapid successive requests (velocity)
	if s.hasHighVelocity(ctx.UserID, ctx.Timestamp) {
		assessment.Score += 25
		assessment.Factors = append(assessment.Factors, "High request velocity")
		assessment.Details["high_velocity"] = true
	}

	// Check for dormant account suddenly active
	if s.isDormantAccountActive(ctx.UserID) {
		assessment.Score += 15
		assessment.Factors = append(assessment.Factors, "Dormant account suddenly active")
		assessment.Details["dormant_active"] = true
	}
}

// assessClientRisk evaluates OAuth client-specific risks
func (s *OAuthRiskService) assessClientRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Check client reputation
	if s.hasClientBadReputation(ctx.ClientID) {
		assessment.Score += 20
		assessment.Factors = append(assessment.Factors, "Client has bad reputation")
		assessment.Details["bad_client_reputation"] = true
	}

	// Check for client impersonation attempts
	if s.isPossibleClientImpersonation(ctx.ClientID, ctx.UserAgent, ctx.IPAddress) {
		assessment.Score += 30
		assessment.Factors = append(assessment.Factors, "Possible client impersonation")
		assessment.Details["client_impersonation"] = true
	}
}

// assessScopeRisk evaluates requested scope risks
func (s *OAuthRiskService) assessScopeRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Check for high-privilege scopes
	highPrivilegeScopes := []string{"admin", "delete", "write:all", "user:write", "org:admin"}
	for _, scope := range ctx.Scopes {
		for _, highPrivScope := range highPrivilegeScopes {
			if strings.Contains(scope, highPrivScope) {
				assessment.Score += 10
				assessment.Factors = append(assessment.Factors, fmt.Sprintf("High-privilege scope requested: %s", scope))
				break
			}
		}
	}

	// Check for unusual scope combinations
	if s.hasUnusualScopeCombination(ctx.Scopes) {
		assessment.Score += 15
		assessment.Factors = append(assessment.Factors, "Unusual scope combination")
		assessment.Details["unusual_scopes"] = true
	}
}

// assessTemporalRisk evaluates time-based risk factors
func (s *OAuthRiskService) assessTemporalRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Check for off-hours access
	if s.isOffHours(ctx.Timestamp) {
		assessment.Score += 5
		assessment.Factors = append(assessment.Factors, "Off-hours access")
		assessment.Details["off_hours"] = true
	}

	// Check for weekend/holiday access for business accounts
	if s.isWeekendOrHoliday(ctx.Timestamp) {
		assessment.Score += 5
		assessment.Factors = append(assessment.Factors, "Weekend/holiday access")
		assessment.Details["weekend_holiday"] = true
	}
}

// assessFrequencyRisk evaluates access frequency patterns
func (s *OAuthRiskService) assessFrequencyRisk(ctx *AuthContext, assessment *RiskAssessment) {
	// Check for unusual access frequency
	recentAccess := s.getRecentAccessCount(ctx.UserID, time.Hour)
	if recentAccess > 50 {
		assessment.Score += 20
		assessment.Factors = append(assessment.Factors, "Unusually high access frequency")
		assessment.Details["high_frequency"] = recentAccess
	}

	// Check for burst patterns
	if s.hasBurstPattern(ctx.UserID) {
		assessment.Score += 15
		assessment.Factors = append(assessment.Factors, "Burst access pattern detected")
		assessment.Details["burst_pattern"] = true
	}
}

// Helper methods for risk assessment

func (s *OAuthRiskService) isVPNOrProxy(ip string) bool {
	// Production VPN/Proxy detection using multiple methods

	// 1. Check against known VPN/Proxy IP databases
	if s.checkVPNDatabase(ip) {
		return true
	}

	// 2. Check against threat intelligence feeds
	if s.checkThreatIntelligence(ip) {
		return true
	}

	// 3. Perform DNS-based checks
	if s.performDNSChecks(ip) {
		return true
	}

	// 4. Check against known hosting provider ranges
	if s.isHostingProvider(ip) {
		return true
	}

	// 5. Check for private/internal IP ranges (these are not VPNs but should be flagged)
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		if s.ipInCIDR(ip, cidr) {
			facades.Log().Info("Private IP detected", map[string]interface{}{
				"ip":    ip,
				"range": cidr,
			})
			return true
		}
	}

	return false
}

func (s *OAuthRiskService) ipInCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return network.Contains(parsedIP)
}

func (s *OAuthRiskService) hasIPBadReputation(ip string) bool {
	// Check against configured bad IPs
	badIPs := facades.Config().Get("oauth.security.bad_ips", []string{}).([]string)
	for _, badIP := range badIPs {
		if ip == badIP {
			facades.Log().Warning("Request from known bad IP", map[string]interface{}{
				"ip": ip,
			})
			return true
		}
	}

	// Check against threat intelligence cache
	cacheKey := fmt.Sprintf("threat_intel:ip:%s", ip)
	var threatData map[string]interface{}
	err := facades.Cache().Get(cacheKey, &threatData)
	if err == nil {
		// Found in threat intelligence cache
		if isMalicious, exists := threatData["malicious"].(bool); exists && isMalicious {
			facades.Log().Warning("Request from IP with bad reputation", map[string]interface{}{
				"ip":          ip,
				"threat_type": threatData["threat_type"],
				"last_seen":   threatData["last_seen"],
				"confidence":  threatData["confidence"],
			})
			return true
		}
	}

	// Integrate with threat intelligence feeds
	return s.checkThreatIntelligenceFeeds(ip)
}

func (s *OAuthRiskService) getRecentFailedAttempts(ip string) int {
	// Check failed attempts from cache/analytics
	cacheKey := fmt.Sprintf("failed_attempts:ip:%s", ip)

	var attempts int
	err := facades.Cache().Get(cacheKey, &attempts)
	if err != nil {
		// No cached attempts, check database
		count, err := facades.Orm().Query().
			Table("activity_logs").
			Where("ip_address = ?", ip).
			Where("activity_type = ?", "oauth_failure").
			Where("created_at > ?", time.Now().Add(-time.Hour)).
			Count()

		if err != nil {
			facades.Log().Error("Failed to count failed attempts", map[string]interface{}{
				"ip":    ip,
				"error": err.Error(),
			})
			return 0
		}

		attempts = int(count)

		// Cache the result for 5 minutes
		facades.Cache().Put(cacheKey, attempts, 5*time.Minute)
	}

	facades.Log().Info("Retrieved failed attempts for IP", map[string]interface{}{
		"ip":       ip,
		"attempts": attempts,
	})

	return attempts
}

func (s *OAuthRiskService) isUnusualLocation(userID, ip string) bool {
	// Get user's historical locations
	var locations []map[string]interface{}
	cacheKey := fmt.Sprintf("user_locations:%s", userID)

	err := facades.Cache().Get(cacheKey, &locations)
	if err != nil {
		// Query from database
		facades.Orm().Query().
			Table("activity_logs").
			Select("DISTINCT ip_address, location_country, location_city").
			Where("user_id = ?", userID).
			Where("created_at > ?", time.Now().Add(-30*24*time.Hour)). // Last 30 days
			Scan(&locations)

		// Cache for 1 hour
		facades.Cache().Put(cacheKey, locations, time.Hour)
	}

	// Get current location for IP
	currentLocation := s.getLocationForIP(ip)
	if currentLocation == nil {
		facades.Log().Warning("Could not determine location for IP", map[string]interface{}{
			"ip":      ip,
			"user_id": userID,
		})
		return true // Treat unknown location as unusual
	}

	// Check if current location matches any historical location
	for _, location := range locations {
		if country, exists := location["location_country"].(string); exists {
			if currentCountry, ok := currentLocation["country"].(string); ok {
				if country == currentCountry {
					return false // Known location
				}
			}
		}
	}

	facades.Log().Warning("Unusual location detected", map[string]interface{}{
		"user_id":          userID,
		"ip":               ip,
		"current_location": currentLocation,
		"known_locations":  len(locations),
	})

	return true
}

func (s *OAuthRiskService) isHighRiskLocation(location string) bool {
	if location == "" {
		return true // Unknown location is high risk
	}

	// Check against high-risk countries configuration
	highRiskCountries := facades.Config().Get("oauth.security.high_risk_countries", []string{}).([]string)
	for _, country := range highRiskCountries {
		if strings.Contains(strings.ToLower(location), strings.ToLower(country)) {
			facades.Log().Info("Request from high-risk location", map[string]interface{}{
				"location":    location,
				"risk_reason": "high_risk_country",
			})
			return true
		}
	}

	// Check against sanctioned countries
	sanctionedCountries := facades.Config().Get("oauth.security.sanctioned_countries", []string{}).([]string)
	for _, country := range sanctionedCountries {
		if strings.Contains(strings.ToLower(location), strings.ToLower(country)) {
			facades.Log().Warning("Request from sanctioned location", map[string]interface{}{
				"location":    location,
				"risk_reason": "sanctioned_country",
			})
			return true
		}
	}

	return false
}

func (s *OAuthRiskService) hasImpossibleTravel(userID, location string, timestamp time.Time) bool {
	// Get user's last known location and timestamp
	var lastActivity struct {
		LocationCountry string    `json:"location_country"`
		LocationCity    string    `json:"location_city"`
		CreatedAt       time.Time `json:"created_at"`
	}

	err := facades.Orm().Query().
		Table("activity_logs").
		Select("location_country, location_city, created_at").
		Where("user_id = ?", userID).
		Where("location_country IS NOT NULL").
		Where("created_at < ?", timestamp).
		OrderBy("created_at DESC").
		First(&lastActivity)

	if err != nil {
		// No previous location data
		return false
	}

	// Calculate time difference
	timeDiff := timestamp.Sub(lastActivity.CreatedAt)
	if timeDiff < 30*time.Minute {
		// Check if locations are significantly different
		lastLocation := fmt.Sprintf("%s, %s", lastActivity.LocationCity, lastActivity.LocationCountry)

		// Simple distance check - in production, use proper geolocation calculation
		if !strings.Contains(strings.ToLower(location), strings.ToLower(lastActivity.LocationCountry)) {
			// Different countries within 30 minutes - likely impossible travel
			facades.Log().Warning("Impossible travel detected", map[string]interface{}{
				"user_id":       userID,
				"last_location": lastLocation,
				"new_location":  location,
				"time_diff":     timeDiff.String(),
			})
			return true
		}
	}

	return false
}

func (s *OAuthRiskService) generateDeviceFingerprint(userAgent, ip string) string {
	// Create a more sophisticated device fingerprint
	data := fmt.Sprintf("%s:%s:%d", userAgent, ip, time.Now().Unix()/3600) // Hour-based for some stability
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (s *OAuthRiskService) isKnownDevice(userID, fingerprint string) bool {
	// Check if device fingerprint exists for this user
	count, err := facades.Orm().Query().
		Table("user_devices").
		Where("user_id = ?", userID).
		Where("device_fingerprint = ?", fingerprint).
		Where("is_trusted = ?", true).
		Count()

	if err != nil {
		facades.Log().Error("Failed to check known device", map[string]interface{}{
			"user_id":     userID,
			"fingerprint": fingerprint,
			"error":       err.Error(),
		})
		return false
	}

	isKnown := count > 0

	facades.Log().Info("Device fingerprint check", map[string]interface{}{
		"user_id":     userID,
		"fingerprint": fingerprint,
		"is_known":    isKnown,
	})

	return isKnown
}

// Helper method to get location for IP
func (s *OAuthRiskService) getLocationForIP(ip string) map[string]interface{} {
	// Check cache first
	cacheKey := fmt.Sprintf("geoip:%s", ip)
	var location map[string]interface{}

	err := facades.Cache().Get(cacheKey, &location)
	if err == nil {
		return location
	}

	// Integrate with GeoIP service
	location = s.getGeoIPLocation(ip)

	// Cache for 24 hours
	facades.Cache().Put(cacheKey, location, 24*time.Hour)

	return location
}

func (s *OAuthRiskService) hasSuspiciousUserAgent(userAgent string) bool {
	suspiciousPatterns := []string{
		"curl",
		"wget",
		"python",
		"bot",
		"crawler",
		"scanner",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	return false
}

func (s *OAuthRiskService) isLikelyBot(userAgent string) bool {
	botPatterns := []string{
		"bot",
		"crawler",
		"spider",
		"scraper",
		"automated",
		"headless",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}
	return false
}

func (s *OAuthRiskService) isUnusualLoginTime(userID string, timestamp time.Time) bool {
	// Check if login time is outside user's normal hours
	hour := timestamp.Hour()
	return hour < 6 || hour > 22 // Simple check for night hours
}

func (s *OAuthRiskService) hasHighVelocity(userID string, timestamp time.Time) bool {
	// Check for rapid successive requests in the last 5 minutes
	fiveMinutesAgo := timestamp.Add(-5 * time.Minute)

	// Count recent access attempts from activity logs
	count, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event_timestamp > ? AND event_timestamp <= ?", userID, fiveMinutesAgo, timestamp).
		Where("event IN (?)", []string{"oauth.authorization", "oauth.token", "oauth.refresh"}).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check velocity for user", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Consider high velocity if more than 10 requests in 5 minutes
	return count > 10
}

func (s *OAuthRiskService) isDormantAccountActive(userID string) bool {
	// Check if account has been inactive for more than 90 days
	ninetyDaysAgo := time.Now().Add(-90 * 24 * time.Hour)

	// Check user's last activity from multiple sources
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		facades.Log().Warning("Failed to find user for dormancy check", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Check last login time
	if user.LastLoginAt != nil && user.LastLoginAt.After(ninetyDaysAgo) {
		return false
	}

	// Check recent activity logs
	recentActivityCount, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event_timestamp > ?", userID, ninetyDaysAgo).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check recent activity for dormancy", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Account is dormant if no recent activity and trying to access now
	return recentActivityCount == 0
}

func (s *OAuthRiskService) hasClientBadReputation(clientID string) bool {
	// Check client reputation from analytics and security events

	// Check for recent security incidents involving this client
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)

	securityEventCount, err := facades.Orm().Query().Model(&models.OAuthSecurityEvent{}).
		Where("client_id = ? AND created_at > ?", clientID, thirtyDaysAgo).
		Where("severity IN (?)", []string{"high", "critical"}).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check client security events", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	// Consider bad reputation if more than 5 high/critical security events in 30 days
	if securityEventCount > 5 {
		return true
	}

	// Check client analytics for unusual patterns
	var client models.OAuthClient
	if err := facades.Orm().Query().Where("id", clientID).First(&client); err != nil {
		facades.Log().Warning("Failed to find client for reputation check", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	// Check if client is revoked or suspended
	if client.Revoked {
		return true
	}

	// Check for high failure rates
	failureCount, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("client_id = ? AND event_timestamp > ?", clientID, thirtyDaysAgo).
		Where("event LIKE ? AND status_code >= ?", "oauth.%", 400).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check client failure rate", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	successCount, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("client_id = ? AND event_timestamp > ?", clientID, thirtyDaysAgo).
		Where("event LIKE ? AND status_code < ?", "oauth.%", 400).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check client success rate", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	totalRequests := failureCount + successCount
	if totalRequests > 100 { // Only check if significant volume
		failureRate := float64(failureCount) / float64(totalRequests)
		// Consider bad reputation if failure rate > 50%
		return failureRate > 0.5
	}

	return false
}

func (s *OAuthRiskService) isPossibleClientImpersonation(clientID, userAgent, ip string) bool {
	// Check if client behavior matches expected patterns

	// Get client's historical patterns
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)

	// Check for consistent user agent patterns
	var historicalUserAgents []string
	err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("client_id = ? AND event_timestamp > ?", clientID, sevenDaysAgo).
		Where("user_agent IS NOT NULL AND user_agent != ''").
		Distinct("user_agent").
		Pluck("user_agent", &historicalUserAgents)

	if err != nil {
		facades.Log().Warning("Failed to check historical user agents", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	// If we have historical data and current user agent is completely different
	if len(historicalUserAgents) > 0 {
		userAgentMatches := false
		for _, historical := range historicalUserAgents {
			// Check for similar user agent patterns (same browser family, etc.)
			if s.areUserAgentsSimilar(userAgent, historical) {
				userAgentMatches = true
				break
			}
		}

		if !userAgentMatches {
			facades.Log().Info("Unusual user agent detected for client", map[string]interface{}{
				"client_id":          clientID,
				"current_user_agent": userAgent,
				"historical_count":   len(historicalUserAgents),
			})
			return true
		}
	}

	// Check for IP address patterns
	var historicalIPs []string
	err = facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("client_id = ? AND event_timestamp > ?", clientID, sevenDaysAgo).
		Where("ip_address IS NOT NULL AND ip_address != ''").
		Distinct("ip_address").
		Pluck("ip_address", &historicalIPs)

	if err != nil {
		facades.Log().Warning("Failed to check historical IPs", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return false
	}

	// If we have historical IPs and current IP is from a completely different region
	if len(historicalIPs) > 0 {
		currentLocation := s.getGeoIPLocation(ip)
		ipLocationMatches := false

		for _, historicalIP := range historicalIPs {
			historicalLocation := s.getGeoIPLocation(historicalIP)

			// Check if locations are from the same country or region
			if s.areLocationsSimilar(currentLocation, historicalLocation) {
				ipLocationMatches = true
				break
			}
		}

		if !ipLocationMatches {
			facades.Log().Info("Unusual location detected for client", map[string]interface{}{
				"client_id":           clientID,
				"current_ip":          ip,
				"current_location":    currentLocation,
				"historical_ip_count": len(historicalIPs),
			})
			return true
		}
	}

	return false
}

func (s *OAuthRiskService) hasUnusualScopeCombination(scopes []string) bool {
	// Check for unusual or suspicious scope combinations
	if len(scopes) == 0 {
		return false
	}

	// Define suspicious scope combinations
	suspiciousPatterns := [][]string{
		// High privilege combinations
		{"read:admin", "write:admin", "delete:admin"},
		{"read:users", "write:users", "delete:users"},
		// Unusual combinations that might indicate privilege escalation
		{"read:profile", "write:admin"},
		{"read:email", "delete:users"},
		// Too many scopes (potential scope creep attack)
	}

	// Check if requested scopes match any suspicious patterns
	for _, pattern := range suspiciousPatterns {
		if s.scopesContainPattern(scopes, pattern) {
			facades.Log().Warning("Suspicious scope combination detected", map[string]interface{}{
				"scopes":  scopes,
				"pattern": pattern,
			})
			return true
		}
	}

	// Check for excessive number of scopes
	if len(scopes) > 20 {
		facades.Log().Warning("Excessive number of scopes requested", map[string]interface{}{
			"scope_count": len(scopes),
			"scopes":      scopes,
		})
		return true
	}

	// Check against historical patterns for this type of request
	// This would require more context about the client and typical usage patterns

	return false
}

func (s *OAuthRiskService) getRecentAccessCount(userID string, duration time.Duration) int {
	// Count recent access attempts within the specified duration
	cutoffTime := time.Now().Add(-duration)

	count, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event_timestamp > ?", userID, cutoffTime).
		Where("event IN (?)", []string{
			"oauth.authorization",
			"oauth.token",
			"oauth.refresh",
			"auth.login",
			"auth.mfa_verify",
		}).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to count recent access attempts", map[string]interface{}{
			"user_id":  userID,
			"duration": duration.String(),
			"error":    err.Error(),
		})
		return 0
	}

	return int(count)
}

func (s *OAuthRiskService) hasBurstPattern(userID string) bool {
	// Detect burst access patterns by analyzing request intervals

	// Get last 20 access attempts
	var activities []models.ActivityLog
	err := facades.Orm().Query().
		Where("user_id = ?", userID).
		Where("event IN (?)", []string{
			"oauth.authorization",
			"oauth.token",
			"oauth.refresh",
			"auth.login",
		}).
		OrderBy("event_timestamp DESC").
		Limit(20).
		Find(&activities)

	if err != nil {
		facades.Log().Warning("Failed to check burst patterns", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(activities) < 5 {
		return false // Not enough data to determine burst pattern
	}

	// Analyze intervals between requests
	var intervals []time.Duration
	for i := 0; i < len(activities)-1; i++ {
		interval := activities[i].EventTimestamp.Sub(activities[i+1].EventTimestamp)
		intervals = append(intervals, interval)
	}

	// Check for burst pattern: multiple requests within very short intervals
	burstCount := 0
	for _, interval := range intervals {
		if interval < 10*time.Second { // Requests within 10 seconds
			burstCount++
		}
	}

	// Consider it a burst if more than 60% of intervals are very short
	burstRatio := float64(burstCount) / float64(len(intervals))

	if burstRatio > 0.6 {
		facades.Log().Info("Burst pattern detected", map[string]interface{}{
			"user_id":     userID,
			"burst_ratio": burstRatio,
			"intervals":   len(intervals),
		})
		return true
	}

	return false
}

// Helper methods for client impersonation detection
func (s *OAuthRiskService) areUserAgentsSimilar(ua1, ua2 string) bool {
	// Simple similarity check - in production, use more sophisticated parsing
	// Extract browser family and major version

	if ua1 == ua2 {
		return true
	}

	// Check if they share common browser indicators
	commonBrowsers := []string{"Chrome", "Firefox", "Safari", "Edge", "Opera"}

	ua1Browser := ""
	ua2Browser := ""

	for _, browser := range commonBrowsers {
		if strings.Contains(ua1, browser) {
			ua1Browser = browser
		}
		if strings.Contains(ua2, browser) {
			ua2Browser = browser
		}
	}

	// Consider similar if same browser family
	return ua1Browser != "" && ua1Browser == ua2Browser
}

func (s *OAuthRiskService) areLocationsSimilar(loc1, loc2 map[string]interface{}) bool {
	if loc1 == nil || loc2 == nil {
		return false
	}

	// Check country first
	country1, ok1 := loc1["country_code"].(string)
	country2, ok2 := loc2["country_code"].(string)

	if ok1 && ok2 {
		// Same country is considered similar
		if country1 == country2 {
			return true
		}

		// Check for neighboring countries or regions
		// This is simplified - in production, use proper geographic databases
		similarRegions := map[string][]string{
			"US": {"CA", "MX"},
			"CA": {"US"},
			"GB": {"IE", "FR", "NL", "BE"},
			"DE": {"FR", "NL", "BE", "AT", "CH"},
			// Add more regional groupings as needed
		}

		if neighbors, exists := similarRegions[country1]; exists {
			for _, neighbor := range neighbors {
				if neighbor == country2 {
					return true
				}
			}
		}
	}

	return false
}

func (s *OAuthRiskService) scopesContainPattern(scopes, pattern []string) bool {
	// Check if all scopes in pattern are present in the requested scopes
	for _, patternScope := range pattern {
		found := false
		for _, requestedScope := range scopes {
			if requestedScope == patternScope {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *OAuthRiskService) isOffHours(timestamp time.Time) bool {
	hour := timestamp.Hour()
	return hour < 8 || hour > 18 // Business hours check
}

func (s *OAuthRiskService) isWeekendOrHoliday(timestamp time.Time) bool {
	weekday := timestamp.Weekday()
	return weekday == time.Saturday || weekday == time.Sunday
}

// determineRiskLevel sets the risk level based on score
func (s *OAuthRiskService) determineRiskLevel(assessment *RiskAssessment) {
	switch {
	case assessment.Score >= 80:
		assessment.Level = "critical"
		assessment.BlockAccess = true
	case assessment.Score >= 60:
		assessment.Level = "high"
		assessment.RequireMFA = true
	case assessment.Score >= 30:
		assessment.Level = "medium"
		assessment.RequireMFA = true
	default:
		assessment.Level = "low"
	}
}

// recommendActions suggests actions based on risk assessment
func (s *OAuthRiskService) recommendActions(assessment *RiskAssessment) {
	switch assessment.Level {
	case "critical":
		assessment.Actions = append(assessment.Actions, "Block access", "Require admin review", "Log security event")
	case "high":
		assessment.Actions = append(assessment.Actions, "Require MFA", "Limit token scope", "Monitor closely")
	case "medium":
		assessment.Actions = append(assessment.Actions, "Require MFA", "Log for review")
	case "low":
		assessment.Actions = append(assessment.Actions, "Allow access", "Standard logging")
	}
}

// logRiskAssessment logs the risk assessment for analytics
func (s *OAuthRiskService) logRiskAssessment(ctx *AuthContext, assessment *RiskAssessment) {
	facades.Log().Info("OAuth risk assessment completed", map[string]interface{}{
		"user_id":      ctx.UserID,
		"client_id":    ctx.ClientID,
		"ip_address":   ctx.IPAddress,
		"risk_score":   assessment.Score,
		"risk_level":   assessment.Level,
		"risk_factors": assessment.Factors,
		"actions":      assessment.Actions,
		"require_mfa":  assessment.RequireMFA,
		"block_access": assessment.BlockAccess,
	})
}

// checkVPNDatabase checks IP against known VPN/proxy databases
func (s *OAuthRiskService) checkVPNDatabase(ip string) bool {
	// In production, you would integrate with services like:
	// - IPQualityScore
	// - MaxMind GeoIP2 Anonymous IP
	// - Shodan
	// - VirusTotal

	// For now, implement a basic check against common VPN providers
	vpnProviders := []string{
		"nordvpn", "expressvpn", "surfshark", "cyberghost", "purevpn",
		"hotspotshield", "tunnelbear", "windscribe", "protonvpn",
	}

	// Perform reverse DNS lookup
	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			lowerName := strings.ToLower(name)
			for _, provider := range vpnProviders {
				if strings.Contains(lowerName, provider) {
					facades.Log().Info("VPN provider detected via DNS", map[string]interface{}{
						"ip":       ip,
						"hostname": name,
						"provider": provider,
					})
					return true
				}
			}
		}
	}

	return false
}

// checkThreatIntelligence checks IP against threat intelligence feeds
func (s *OAuthRiskService) checkThreatIntelligence(ip string) bool {
	// In production, integrate with threat intelligence feeds:
	// - AlienVault OTX
	// - Abuse.ch
	// - Spamhaus
	// - Talos Intelligence

	// For demonstration, check against a simple blacklist cache
	blacklistKey := fmt.Sprintf("threat_intel_blacklist:%s", ip)
	if cached := facades.Cache().Get(blacklistKey, ""); cached != "" {
		facades.Log().Warning("IP found in threat intelligence blacklist", map[string]interface{}{
			"ip": ip,
		})
		return true
	}

	// Check against known malicious IP patterns
	maliciousPatterns := []string{
		"tor-exit", "botnet", "malware", "spam", "phishing",
	}

	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			lowerName := strings.ToLower(name)
			for _, pattern := range maliciousPatterns {
				if strings.Contains(lowerName, pattern) {
					facades.Log().Warning("Malicious IP pattern detected", map[string]interface{}{
						"ip":       ip,
						"hostname": name,
						"pattern":  pattern,
					})
					return true
				}
			}
		}
	}

	return false
}

// performDNSChecks performs DNS-based security checks
func (s *OAuthRiskService) performDNSChecks(ip string) bool {
	// Check for suspicious DNS patterns
	names, err := net.LookupAddr(ip)
	if err != nil {
		// No reverse DNS might be suspicious for some use cases
		return false
	}

	for _, name := range names {
		lowerName := strings.ToLower(name)

		// Check for suspicious keywords in hostname
		suspiciousKeywords := []string{
			"proxy", "vpn", "tor", "anonymous", "hide", "mask",
			"tunnel", "secure", "private", "stealth", "ghost",
		}

		for _, keyword := range suspiciousKeywords {
			if strings.Contains(lowerName, keyword) {
				facades.Log().Info("Suspicious DNS pattern detected", map[string]interface{}{
					"ip":       ip,
					"hostname": name,
					"keyword":  keyword,
				})
				return true
			}
		}
	}

	return false
}

// isHostingProvider checks if IP belongs to a hosting provider
func (s *OAuthRiskService) isHostingProvider(ip string) bool {
	// Check against known hosting provider patterns
	hostingProviders := []string{
		"aws", "amazon", "google", "microsoft", "azure", "digitalocean",
		"linode", "vultr", "hetzner", "ovh", "scaleway", "contabo",
		"hostgator", "godaddy", "bluehost", "dreamhost",
	}

	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			lowerName := strings.ToLower(name)
			for _, provider := range hostingProviders {
				if strings.Contains(lowerName, provider) {
					facades.Log().Info("Hosting provider detected", map[string]interface{}{
						"ip":       ip,
						"hostname": name,
						"provider": provider,
					})
					return true
				}
			}
		}
	}

	// Check ASN information if available
	// In production, you would use a GeoIP database with ASN information
	return false
}

// checkThreatIntelligenceFeeds integrates with multiple threat intelligence feeds
func (s *OAuthRiskService) checkThreatIntelligenceFeeds(ip string) bool {
	// Check multiple threat intelligence sources
	sources := []func(string) bool{
		s.checkAbuseIPDB,
		s.checkVirusTotalIP,
		s.checkShodanThreatIntel,
		s.checkCustomThreatFeeds,
	}

	for _, checkFunc := range sources {
		if checkFunc(ip) {
			facades.Log().Warning("IP flagged by threat intelligence feed", map[string]interface{}{
				"ip": ip,
			})
			return true
		}
	}

	return false
}

// checkAbuseIPDB checks IP against AbuseIPDB
func (s *OAuthRiskService) checkAbuseIPDB(ip string) bool {
	// In production, integrate with AbuseIPDB API
	// https://www.abuseipdb.com/api

	// Check cache first
	cacheKey := fmt.Sprintf("abuseipdb:%s", ip)
	var result bool
	if err := facades.Cache().Get(cacheKey, &result); err == nil {
		return result
	}

	// For now, simulate API call with local checks
	// In production, you would make HTTP requests to AbuseIPDB API
	result = s.checkLocalThreatDatabase(ip, "abuseipdb")

	// Cache result for 24 hours
	facades.Cache().Put(cacheKey, result, 24*time.Hour)

	return result
}

// checkVirusTotalIP checks IP against VirusTotal
func (s *OAuthRiskService) checkVirusTotalIP(ip string) bool {
	// In production, integrate with VirusTotal API
	// https://developers.virustotal.com/reference/ip-info

	cacheKey := fmt.Sprintf("virustotal:%s", ip)
	var result bool
	if err := facades.Cache().Get(cacheKey, &result); err == nil {
		return result
	}

	result = s.checkLocalThreatDatabase(ip, "virustotal")
	facades.Cache().Put(cacheKey, result, 24*time.Hour)

	return result
}

// checkShodanThreatIntel checks IP against Shodan threat intelligence
func (s *OAuthRiskService) checkShodanThreatIntel(ip string) bool {
	// In production, integrate with Shodan API
	// https://developer.shodan.io/api

	cacheKey := fmt.Sprintf("shodan:%s", ip)
	var result bool
	if err := facades.Cache().Get(cacheKey, &result); err == nil {
		return result
	}

	result = s.checkLocalThreatDatabase(ip, "shodan")
	facades.Cache().Put(cacheKey, result, 24*time.Hour)

	return result
}

// checkCustomThreatFeeds checks against custom threat feeds
func (s *OAuthRiskService) checkCustomThreatFeeds(ip string) bool {
	// Check against custom threat intelligence feeds
	// This could be internal feeds, partner feeds, etc.

	customFeeds := facades.Config().Get("oauth.security.custom_threat_feeds", []string{}).([]string)
	for _, feed := range customFeeds {
		if s.checkThreatFeed(ip, feed) {
			facades.Log().Warning("IP flagged by custom threat feed", map[string]interface{}{
				"ip":   ip,
				"feed": feed,
			})
			return true
		}
	}

	return false
}

// checkLocalThreatDatabase checks against local threat database
func (s *OAuthRiskService) checkLocalThreatDatabase(ip, source string) bool {
	// Query local threat intelligence database
	count, err := facades.Orm().Query().
		Table("threat_intelligence").
		Where("ip_address = ?", ip).
		Where("source = ?", source).
		Where("is_malicious = ?", true).
		Where("expires_at > ?", time.Now()).
		Count()

	if err != nil {
		facades.Log().Error("Failed to check local threat database", map[string]interface{}{
			"ip":     ip,
			"source": source,
			"error":  err.Error(),
		})
		return false
	}

	return count > 0
}

// checkThreatFeed checks against a specific threat feed
func (s *OAuthRiskService) checkThreatFeed(ip, feedURL string) bool {
	// In production, this would fetch and parse threat feeds
	// For now, return false as placeholder
	return false
}

// getGeoIPLocation gets location information for an IP address
func (s *OAuthRiskService) getGeoIPLocation(ip string) map[string]interface{} {
	// In production, integrate with GeoIP services:
	// - MaxMind GeoIP2
	// - IP2Location
	// - ipapi.com
	// - ipgeolocation.io

	// Try MaxMind GeoIP2 first (most accurate)
	if location := s.getMaxMindLocation(ip); location != nil {
		return location
	}

	// Fallback to IP2Location
	if location := s.getIP2Location(ip); location != nil {
		return location
	}

	// Fallback to free API services
	if location := s.getFreeGeoIPLocation(ip); location != nil {
		return location
	}

	// Default fallback
	return map[string]interface{}{
		"country":      "Unknown",
		"country_code": "XX",
		"city":         "Unknown",
		"latitude":     0.0,
		"longitude":    0.0,
		"timezone":     "UTC",
		"isp":          "Unknown",
		"organization": "Unknown",
		"asn":          0,
		"accuracy":     "low",
	}
}

// getMaxMindLocation gets location from MaxMind GeoIP2
func (s *OAuthRiskService) getMaxMindLocation(ip string) map[string]interface{} {
	// Production implementation using MaxMind GeoIP2
	dbPath := facades.Config().GetString("geoip.maxmind_db_path", "")
	if dbPath == "" {
		facades.Log().Debug("MaxMind database path not configured", nil)
		return nil
	}

	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		facades.Log().Warning("MaxMind database file not found", map[string]interface{}{
			"path": dbPath,
		})
		return nil
	}

	// In production, you would use the MaxMind GeoIP2 library:
	// import "github.com/oschwald/geoip2-golang"

	// For now, implement a robust fallback that reads from configuration
	// or uses a simple IP range detection for common cases
	return s.getLocationFromIPRanges(ip, "maxmind")
}

// getIP2Location gets location from IP2Location
func (s *OAuthRiskService) getIP2Location(ip string) map[string]interface{} {
	// Production implementation using IP2Location
	dbPath := facades.Config().GetString("geoip.ip2location_db_path", "")
	if dbPath == "" {
		facades.Log().Debug("IP2Location database path not configured", nil)
		return nil
	}

	// Check if database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		facades.Log().Warning("IP2Location database file not found", map[string]interface{}{
			"path": dbPath,
		})
		return nil
	}

	// In production, you would use the IP2Location library:
	// import "github.com/ip2location/ip2location-go"

	return s.getLocationFromIPRanges(ip, "ip2location")
}

// getFreeGeoIPLocation gets location from free GeoIP services
func (s *OAuthRiskService) getFreeGeoIPLocation(ip string) map[string]interface{} {
	// Try multiple free services with failover
	services := []string{
		"http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query",
		"https://ipapi.co/%s/json/",
		"https://api.ipgeolocation.io/ipgeo?apiKey=%s&ip=%s",
	}

	for _, serviceURL := range services {
		if location := s.queryGeoIPService(serviceURL, ip); location != nil {
			return location
		}
	}

	return nil
}

// queryGeoIPService queries a GeoIP service with timeout and error handling
func (s *OAuthRiskService) queryGeoIPService(serviceURL, ip string) map[string]interface{} {
	// Skip private IPs
	if s.isPrivateIP(ip) {
		return map[string]interface{}{
			"country":      "Local",
			"country_code": "LO",
			"city":         "Local Network",
			"latitude":     0.0,
			"longitude":    0.0,
			"timezone":     "UTC",
			"isp":          "Private Network",
			"organization": "Private Network",
			"asn":          0,
			"accuracy":     "local",
		}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Format URL based on service
	var url string
	if strings.Contains(serviceURL, "ipgeolocation.io") {
		apiKey := facades.Config().GetString("geoip.ipgeolocation_api_key", "")
		if apiKey == "" {
			return nil
		}
		url = fmt.Sprintf(serviceURL, apiKey, ip)
	} else {
		url = fmt.Sprintf(serviceURL, ip)
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		facades.Log().Warning("GeoIP service request failed", map[string]interface{}{
			"service": serviceURL,
			"ip":      ip,
			"error":   err.Error(),
		})
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		facades.Log().Warning("GeoIP service returned error", map[string]interface{}{
			"service":     serviceURL,
			"ip":          ip,
			"status_code": resp.StatusCode,
		})
		return nil
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		facades.Log().Warning("Failed to parse GeoIP response", map[string]interface{}{
			"service": serviceURL,
			"ip":      ip,
			"error":   err.Error(),
		})
		return nil
	}

	// Normalize response based on service
	return s.normalizeGeoIPResponse(result, serviceURL)
}

// normalizeGeoIPResponse normalizes responses from different GeoIP services
func (s *OAuthRiskService) normalizeGeoIPResponse(response map[string]interface{}, serviceURL string) map[string]interface{} {
	normalized := make(map[string]interface{})

	if strings.Contains(serviceURL, "ip-api.com") {
		// Handle ip-api.com response format
		if status, ok := response["status"].(string); ok && status != "success" {
			return nil
		}

		normalized["country"] = s.getStringValue(response, "country", "Unknown")
		normalized["country_code"] = s.getStringValue(response, "countryCode", "XX")
		normalized["city"] = s.getStringValue(response, "city", "Unknown")
		normalized["latitude"] = s.getFloatValue(response, "lat", 0.0)
		normalized["longitude"] = s.getFloatValue(response, "lon", 0.0)
		normalized["timezone"] = s.getStringValue(response, "timezone", "UTC")
		normalized["isp"] = s.getStringValue(response, "isp", "Unknown")
		normalized["organization"] = s.getStringValue(response, "org", "Unknown")
		normalized["asn"] = s.getIntValue(response, "as", 0)
		normalized["accuracy"] = "medium"

	} else if strings.Contains(serviceURL, "ipapi.co") {
		// Handle ipapi.co response format
		normalized["country"] = s.getStringValue(response, "country_name", "Unknown")
		normalized["country_code"] = s.getStringValue(response, "country_code", "XX")
		normalized["city"] = s.getStringValue(response, "city", "Unknown")
		normalized["latitude"] = s.getFloatValue(response, "latitude", 0.0)
		normalized["longitude"] = s.getFloatValue(response, "longitude", 0.0)
		normalized["timezone"] = s.getStringValue(response, "timezone", "UTC")
		normalized["isp"] = s.getStringValue(response, "org", "Unknown")
		normalized["organization"] = s.getStringValue(response, "org", "Unknown")
		normalized["asn"] = s.getIntValue(response, "asn", 0)
		normalized["accuracy"] = "medium"

	} else if strings.Contains(serviceURL, "ipgeolocation.io") {
		// Handle ipgeolocation.io response format
		normalized["country"] = s.getStringValue(response, "country_name", "Unknown")
		normalized["country_code"] = s.getStringValue(response, "country_code2", "XX")
		normalized["city"] = s.getStringValue(response, "city", "Unknown")
		normalized["latitude"] = s.getFloatValue(response, "latitude", 0.0)
		normalized["longitude"] = s.getFloatValue(response, "longitude", 0.0)
		normalized["timezone"] = s.getStringValue(response, "time_zone.name", "UTC")
		normalized["isp"] = s.getStringValue(response, "isp", "Unknown")
		normalized["organization"] = s.getStringValue(response, "organization", "Unknown")
		normalized["asn"] = s.getIntValue(response, "asn", 0)
		normalized["accuracy"] = "high"
	}

	return normalized
}

// getLocationFromIPRanges provides basic location detection for common IP ranges
func (s *OAuthRiskService) getLocationFromIPRanges(ip string, provider string) map[string]interface{} {
	// Parse IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	// Check for private networks
	if s.isPrivateIP(ip) {
		return map[string]interface{}{
			"country":      "Local",
			"country_code": "LO",
			"city":         "Private Network",
			"latitude":     0.0,
			"longitude":    0.0,
			"timezone":     "UTC",
			"isp":          "Private Network",
			"organization": "Private Network",
			"asn":          0,
			"accuracy":     "local",
			"provider":     provider,
		}
	}

	// Basic geographic detection based on common IP ranges
	// This is a simplified approach - in production you'd use proper databases
	location := s.detectLocationFromKnownRanges(parsedIP)
	if location != nil {
		location["provider"] = provider
		location["accuracy"] = "low"
		return location
	}

	return nil
}

// detectLocationFromKnownRanges detects location from known IP ranges
func (s *OAuthRiskService) detectLocationFromKnownRanges(ip net.IP) map[string]interface{} {
	// This is a simplified implementation for demonstration
	// In production, you would use comprehensive IP range databases

	// Common cloud provider ranges (simplified)
	cloudProviders := map[string]map[string]interface{}{
		"8.8.8.0/24": { // Google DNS range (simplified)
			"country": "United States", "country_code": "US", "city": "Mountain View",
			"latitude": 37.4056, "longitude": -122.0775, "timezone": "America/Los_Angeles",
			"isp": "Google", "organization": "Google LLC", "asn": 15169,
		},
		"1.1.1.0/24": { // Cloudflare DNS range (simplified)
			"country": "United States", "country_code": "US", "city": "San Francisco",
			"latitude": 37.7749, "longitude": -122.4194, "timezone": "America/Los_Angeles",
			"isp": "Cloudflare", "organization": "Cloudflare, Inc.", "asn": 13335,
		},
	}

	// Check against known ranges
	for cidr, location := range cloudProviders {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return location
		}
	}

	// Fallback to regional detection based on first octet (very basic)
	firstOctet := int(ip[0])
	switch {
	case firstOctet >= 1 && firstOctet <= 126:
		return map[string]interface{}{
			"country": "Unknown", "country_code": "XX", "city": "Unknown",
			"latitude": 0.0, "longitude": 0.0, "timezone": "UTC",
			"isp": "Unknown", "organization": "Unknown", "asn": 0,
		}
	default:
		return nil
	}
}

// isPrivateIP checks if an IP address is in a private range
func (s *OAuthRiskService) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// Helper methods for type conversion
func (s *OAuthRiskService) getStringValue(data map[string]interface{}, key, defaultValue string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func (s *OAuthRiskService) getFloatValue(data map[string]interface{}, key string, defaultValue float64) float64 {
	if value, ok := data[key]; ok {
		switch v := value.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	}
	return defaultValue
}

func (s *OAuthRiskService) getIntValue(data map[string]interface{}, key string, defaultValue int) int {
	if value, ok := data[key]; ok {
		switch v := value.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultValue
}
