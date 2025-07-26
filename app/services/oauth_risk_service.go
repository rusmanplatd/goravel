package services

import (
	"crypto/md5"
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
	// In production, integrate with VPN/Proxy detection services
	// For now, check against common VPN IP ranges
	vpnRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range vpnRanges {
		if s.ipInCIDR(ip, cidr) {
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
	// In production, integrate with threat intelligence feeds
	// For now, simple check against known bad IPs
	badIPs := facades.Config().Get("oauth.security.bad_ips", []string{}).([]string)
	for _, badIP := range badIPs {
		if ip == badIP {
			return true
		}
	}
	return false
}

func (s *OAuthRiskService) getRecentFailedAttempts(ip string) int {
	// Query recent failed attempts from analytics or cache
	// This would integrate with your analytics service
	return 0 // Placeholder
}

func (s *OAuthRiskService) isUnusualLocation(userID, ip string) bool {
	// Check user's historical locations
	// In production, use GeoIP service
	return false // Placeholder
}

func (s *OAuthRiskService) isHighRiskLocation(location string) bool {
	highRiskCountries := facades.Config().Get("oauth.security.high_risk_countries", []string{}).([]string)
	for _, country := range highRiskCountries {
		if strings.Contains(location, country) {
			return true
		}
	}
	return false
}

func (s *OAuthRiskService) hasImpossibleTravel(userID, location string, timestamp time.Time) bool {
	// Check if user could physically travel between locations in the given time
	// This requires storing previous location and timestamp
	return false // Placeholder - would need geolocation and travel time calculation
}

func (s *OAuthRiskService) generateDeviceFingerprint(userAgent, ip string) string {
	data := fmt.Sprintf("%s:%s", userAgent, ip)
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

func (s *OAuthRiskService) isKnownDevice(userID, fingerprint string) bool {
	// Check if device fingerprint is known for this user
	// This would query a device tracking table
	return true // Placeholder - assume devices are known for now
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
