package services

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"

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

	// TODO: For production, integrate with threat intelligence feeds like:
	// - VirusTotal API
	// - AbuseIPDB
	// - Shodan
	// - Custom threat feeds

	return false
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

	// TODO: For production, integrate with GeoIP services like:
	// - MaxMind GeoIP2
	// - IP2Location
	// - ipapi.com
	// - ipgeolocation.io

	// Mock implementation for now
	location = map[string]interface{}{
		"country":   "Unknown",
		"city":      "Unknown",
		"latitude":  0.0,
		"longitude": 0.0,
		"timezone":  "UTC",
	}

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
	// Check for rapid successive requests
	// This would query recent request timestamps
	return false // Placeholder
}

func (s *OAuthRiskService) isDormantAccountActive(userID string) bool {
	// Check if account has been inactive for a long period
	// This would query user's last activity
	return false // Placeholder
}

func (s *OAuthRiskService) hasClientBadReputation(clientID string) bool {
	// Check client reputation from analytics
	return false // Placeholder
}

func (s *OAuthRiskService) isPossibleClientImpersonation(clientID, userAgent, ip string) bool {
	// Check if client behavior matches expected patterns
	return false // Placeholder
}

func (s *OAuthRiskService) hasUnusualScopeCombination(scopes []string) bool {
	// Check for unusual or suspicious scope combinations
	return false // Placeholder
}

func (s *OAuthRiskService) isOffHours(timestamp time.Time) bool {
	hour := timestamp.Hour()
	return hour < 8 || hour > 18 // Business hours check
}

func (s *OAuthRiskService) isWeekendOrHoliday(timestamp time.Time) bool {
	weekday := timestamp.Weekday()
	return weekday == time.Saturday || weekday == time.Sunday
}

func (s *OAuthRiskService) getRecentAccessCount(userID string, duration time.Duration) int {
	// Count recent access attempts
	return 0 // Placeholder
}

func (s *OAuthRiskService) hasBurstPattern(userID string) bool {
	// Detect burst access patterns
	return false // Placeholder
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
