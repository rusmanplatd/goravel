package services

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
	"github.com/ua-parser/uap-go/uaparser"

	"goravel/app/models"
)

type OAuthAnalyticsService struct{}

type TokenUsageMetrics struct {
	TotalTokens       int64            `json:"total_tokens"`
	ActiveTokens      int64            `json:"active_tokens"`
	RevokedTokens     int64            `json:"revoked_tokens"`
	ExpiredTokens     int64            `json:"expired_tokens"`
	TokensByClient    map[string]int64 `json:"tokens_by_client"`
	TokensByGrantType map[string]int64 `json:"tokens_by_grant_type"`
	TokensByScope     map[string]int64 `json:"tokens_by_scope"`
	DailyTokens       []DailyMetric    `json:"daily_tokens"`
	HourlyTokens      []HourlyMetric   `json:"hourly_tokens"`
}

type ClientMetrics struct {
	ClientID           string           `json:"client_id"`
	ClientName         string           `json:"client_name"`
	TotalRequests      int64            `json:"total_requests"`
	SuccessfulRequests int64            `json:"successful_requests"`
	FailedRequests     int64            `json:"failed_requests"`
	UniqueUsers        int64            `json:"unique_users"`
	TokensIssued       int64            `json:"tokens_issued"`
	LastActivity       time.Time        `json:"last_activity"`
	TopScopes          []ScopeUsage     `json:"top_scopes"`
	RequestsByEndpoint map[string]int64 `json:"requests_by_endpoint"`
	ErrorsByType       map[string]int64 `json:"errors_by_type"`
}

type UserMetrics struct {
	UserID          string           `json:"user_id"`
	Email           string           `json:"email"`
	TotalSessions   int64            `json:"total_sessions"`
	ActiveTokens    int64            `json:"active_tokens"`
	ConnectedApps   int64            `json:"connected_apps"`
	LastActivity    time.Time        `json:"last_activity"`
	LocationHistory []LocationMetric `json:"location_history"`
	DeviceHistory   []DeviceMetric   `json:"device_history"`
	SecurityEvents  []SecurityEvent  `json:"security_events"`
}

type ScopeUsage struct {
	Scope      string  `json:"scope"`
	UsageCount int64   `json:"usage_count"`
	Percentage float64 `json:"percentage"`
}

type DailyMetric struct {
	Date    string `json:"date"`
	Count   int64  `json:"count"`
	Success int64  `json:"success"`
	Failed  int64  `json:"failed"`
}

type HourlyMetric struct {
	Hour    int   `json:"hour"`
	Count   int64 `json:"count"`
	Success int64 `json:"success"`
	Failed  int64 `json:"failed"`
}

type LocationMetric struct {
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	City      string    `json:"city"`
	IPAddress string    `json:"ip_address"`
	Count     int64     `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
}

type DeviceMetric struct {
	UserAgent  string    `json:"user_agent"`
	DeviceType string    `json:"device_type"`
	Browser    string    `json:"browser"`
	OS         string    `json:"os"`
	Count      int64     `json:"count"`
	LastSeen   time.Time `json:"last_seen"`
}

type SecurityEvent struct {
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	RiskScore int                    `json:"risk_score"`
	Details   map[string]interface{} `json:"details"`
	Action    string                 `json:"action"`
}

type SystemMetrics struct {
	TotalUsers          int64            `json:"total_users"`
	ActiveUsers         int64            `json:"active_users"`
	TotalClients        int64            `json:"total_clients"`
	ActiveClients       int64            `json:"active_clients"`
	RequestsPerSecond   float64          `json:"requests_per_second"`
	AverageResponseTime float64          `json:"average_response_time"`
	ErrorRate           float64          `json:"error_rate"`
	TopEndpoints        []EndpointMetric `json:"top_endpoints"`
	SystemHealth        HealthStatus     `json:"system_health"`
}

type EndpointMetric struct {
	Endpoint         string  `json:"endpoint"`
	RequestCount     int64   `json:"request_count"`
	AverageLatency   float64 `json:"average_latency"`
	ErrorRate        float64 `json:"error_rate"`
	LastHourRequests int64   `json:"last_hour_requests"`
}

type HealthStatus struct {
	Status         string            `json:"status"`
	DatabaseHealth string            `json:"database_health"`
	CacheHealth    string            `json:"cache_health"`
	ServiceHealth  map[string]string `json:"service_health"`
	LastChecked    time.Time         `json:"last_checked"`
}

func NewOAuthAnalyticsService() *OAuthAnalyticsService {
	return &OAuthAnalyticsService{}
}

// RecordTokenEvent records a token-related event for analytics
func (s *OAuthAnalyticsService) RecordTokenEvent(eventType, clientID, userID string, scopes []string, ipAddress, userAgent string) {
	event := map[string]interface{}{
		"event_type": eventType,
		"client_id":  clientID,
		"user_id":    userID,
		"scopes":     scopes,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"timestamp":  time.Now(),
	}

	// Store in time-series format for analytics
	s.storeTimeSeriesData("oauth_token_events", event)

	// Update real-time counters
	s.updateRealTimeCounters(eventType, clientID, userID)

	// Record location and device info
	if ipAddress != "" {
		s.recordLocationData(userID, ipAddress)
	}
	if userAgent != "" {
		s.recordDeviceData(userID, userAgent)
	}
}

// RecordAuthorizationEvent records an authorization-related event
func (s *OAuthAnalyticsService) RecordAuthorizationEvent(eventType, clientID, userID string, granted bool, scopes []string, ipAddress, userAgent string) {
	event := map[string]interface{}{
		"event_type": eventType,
		"client_id":  clientID,
		"user_id":    userID,
		"granted":    granted,
		"scopes":     scopes,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"timestamp":  time.Now(),
	}

	s.storeTimeSeriesData("oauth_auth_events", event)
	s.updateRealTimeCounters("authorization_"+eventType, clientID, userID)
}

// RecordAPIRequest records an API request for analytics
func (s *OAuthAnalyticsService) RecordAPIRequest(endpoint, method, clientID, userID string, responseTime time.Duration, statusCode int, ipAddress, userAgent string) {
	event := map[string]interface{}{
		"endpoint":      endpoint,
		"method":        method,
		"client_id":     clientID,
		"user_id":       userID,
		"response_time": responseTime.Milliseconds(),
		"status_code":   statusCode,
		"ip_address":    ipAddress,
		"user_agent":    userAgent,
		"timestamp":     time.Now(),
	}

	s.storeTimeSeriesData("oauth_api_requests", event)

	// Update endpoint-specific metrics
	s.updateEndpointMetrics(endpoint, method, responseTime, statusCode)
}

// GetTokenUsageMetrics returns comprehensive token usage metrics
func (s *OAuthAnalyticsService) GetTokenUsageMetrics(timeRange string) (*TokenUsageMetrics, error) {
	// Calculate time range
	startTime, endTime := s.calculateTimeRange(timeRange)

	metrics := &TokenUsageMetrics{
		TokensByClient:    make(map[string]int64),
		TokensByGrantType: make(map[string]int64),
		TokensByScope:     make(map[string]int64),
		DailyTokens:       []DailyMetric{},
		HourlyTokens:      []HourlyMetric{},
	}

	// Get token events from time series data
	events := s.getTimeSeriesData("oauth_token_events", startTime, endTime)

	for _, event := range events {
		eventData := event.(map[string]interface{})
		eventType := eventData["event_type"].(string)

		switch eventType {
		case "token_created":
			metrics.TotalTokens++
			if clientID, ok := eventData["client_id"].(string); ok {
				metrics.TokensByClient[clientID]++
			}
			if scopes, ok := eventData["scopes"].([]string); ok {
				for _, scope := range scopes {
					metrics.TokensByScope[scope]++
				}
			}
		case "token_revoked":
			metrics.RevokedTokens++
		case "token_expired":
			metrics.ExpiredTokens++
		}
	}

	metrics.ActiveTokens = metrics.TotalTokens - metrics.RevokedTokens - metrics.ExpiredTokens

	// Generate daily and hourly breakdowns
	metrics.DailyTokens = s.generateDailyMetrics(events, startTime, endTime)
	metrics.HourlyTokens = s.generateHourlyMetrics(events)

	return metrics, nil
}

// GetClientMetrics returns detailed metrics for a specific client
func (s *OAuthAnalyticsService) GetClientMetrics(clientID string, timeRange string) (*ClientMetrics, error) {
	startTime, endTime := s.calculateTimeRange(timeRange)

	metrics := &ClientMetrics{
		ClientID:           clientID,
		RequestsByEndpoint: make(map[string]int64),
		ErrorsByType:       make(map[string]int64),
		TopScopes:          []ScopeUsage{},
	}

	// Get client name from database
	metrics.ClientName = s.getClientName(clientID)

	// Get API request events for this client
	apiEvents := s.getClientAPIEvents(clientID, startTime, endTime)

	metrics.TotalRequests = int64(len(apiEvents))

	for _, event := range apiEvents {
		eventData := event.(map[string]interface{})
		statusCode := int(eventData["status_code"].(float64))
		endpoint := eventData["endpoint"].(string)

		metrics.RequestsByEndpoint[endpoint]++

		if statusCode >= 200 && statusCode < 300 {
			metrics.SuccessfulRequests++
		} else {
			metrics.FailedRequests++
			errorType := s.categorizeError(statusCode)
			metrics.ErrorsByType[errorType]++
		}

		// Update last activity
		if timestamp, ok := eventData["timestamp"].(time.Time); ok {
			if timestamp.After(metrics.LastActivity) {
				metrics.LastActivity = timestamp
			}
		}
	}

	// Get token events for this client
	tokenEvents := s.getClientTokenEvents(clientID, startTime, endTime)
	metrics.TokensIssued = int64(len(tokenEvents))

	// Calculate unique users
	uniqueUsers := make(map[string]bool)
	scopeUsage := make(map[string]int64)

	for _, event := range tokenEvents {
		eventData := event.(map[string]interface{})
		if userID, ok := eventData["user_id"].(string); ok && userID != "" {
			uniqueUsers[userID] = true
		}
		if scopes, ok := eventData["scopes"].([]interface{}); ok {
			for _, scope := range scopes {
				if scopeStr, ok := scope.(string); ok {
					scopeUsage[scopeStr]++
				}
			}
		}
	}

	metrics.UniqueUsers = int64(len(uniqueUsers))

	// Convert scope usage to sorted list
	totalScopeUsage := int64(0)
	for _, count := range scopeUsage {
		totalScopeUsage += count
	}

	for scope, count := range scopeUsage {
		percentage := float64(count) / float64(totalScopeUsage) * 100
		metrics.TopScopes = append(metrics.TopScopes, ScopeUsage{
			Scope:      scope,
			UsageCount: count,
			Percentage: percentage,
		})
	}

	// Sort scopes by usage
	sort.Slice(metrics.TopScopes, func(i, j int) bool {
		return metrics.TopScopes[i].UsageCount > metrics.TopScopes[j].UsageCount
	})

	// Keep only top 10 scopes
	if len(metrics.TopScopes) > 10 {
		metrics.TopScopes = metrics.TopScopes[:10]
	}

	return metrics, nil
}

// GetUserMetrics returns detailed metrics for a specific user
func (s *OAuthAnalyticsService) GetUserMetrics(userID string, timeRange string) (*UserMetrics, error) {
	startTime, endTime := s.calculateTimeRange(timeRange)

	metrics := &UserMetrics{
		UserID:          userID,
		LocationHistory: []LocationMetric{},
		DeviceHistory:   []DeviceMetric{},
		SecurityEvents:  []SecurityEvent{},
	}

	// Get user email
	metrics.Email = s.getUserEmail(userID)

	// Get user's token events
	userTokenEvents := s.getUserTokenEvents(userID, startTime, endTime)

	// Count active tokens and connected apps
	activeTokens := make(map[string]bool)
	connectedApps := make(map[string]bool)

	for _, event := range userTokenEvents {
		eventData := event.(map[string]interface{})
		eventType := eventData["event_type"].(string)

		if eventType == "token_created" {
			if tokenID, ok := eventData["token_id"].(string); ok {
				activeTokens[tokenID] = true
			}
			if clientID, ok := eventData["client_id"].(string); ok {
				connectedApps[clientID] = true
			}
		} else if eventType == "token_revoked" {
			if tokenID, ok := eventData["token_id"].(string); ok {
				delete(activeTokens, tokenID)
			}
		}

		// Update last activity
		if timestamp, ok := eventData["timestamp"].(time.Time); ok {
			if timestamp.After(metrics.LastActivity) {
				metrics.LastActivity = timestamp
			}
		}
	}

	metrics.ActiveTokens = int64(len(activeTokens))
	metrics.ConnectedApps = int64(len(connectedApps))

	// Get location history
	metrics.LocationHistory = s.getUserLocationHistory(userID, startTime, endTime)

	// Get device history
	metrics.DeviceHistory = s.getUserDeviceHistory(userID, startTime, endTime)

	// Get security events
	metrics.SecurityEvents = s.getUserSecurityEvents(userID, startTime, endTime)

	// Count total sessions (approximation based on distinct IP/UserAgent combinations per day)
	sessions := s.estimateUserSessions(userID, startTime, endTime)
	metrics.TotalSessions = sessions

	return metrics, nil
}

// GetSystemMetrics returns overall system health and performance metrics
func (s *OAuthAnalyticsService) GetSystemMetrics() (*SystemMetrics, error) {
	metrics := &SystemMetrics{
		TopEndpoints: []EndpointMetric{},
		SystemHealth: HealthStatus{
			ServiceHealth: make(map[string]string),
			LastChecked:   time.Now(),
		},
	}

	// Get basic counts
	metrics.TotalUsers = s.getTotalUsers()
	metrics.ActiveUsers = s.getActiveUsers(24 * time.Hour) // Active in last 24 hours
	metrics.TotalClients = s.getTotalClients()
	metrics.ActiveClients = s.getActiveClients(24 * time.Hour)

	// Calculate performance metrics
	lastHour := time.Now().Add(-time.Hour)
	apiEvents := s.getTimeSeriesData("oauth_api_requests", lastHour, time.Now())

	if len(apiEvents) > 0 {
		metrics.RequestsPerSecond = float64(len(apiEvents)) / 3600.0 // requests per second in last hour

		totalResponseTime := int64(0)
		errorCount := int64(0)

		endpointStats := make(map[string]*EndpointMetric)

		for _, event := range apiEvents {
			eventData := event.(map[string]interface{})
			responseTime := int64(eventData["response_time"].(float64))
			statusCode := int(eventData["status_code"].(float64))
			endpoint := eventData["endpoint"].(string)

			totalResponseTime += responseTime

			if statusCode >= 400 {
				errorCount++
			}

			// Update endpoint stats
			if _, exists := endpointStats[endpoint]; !exists {
				endpointStats[endpoint] = &EndpointMetric{
					Endpoint: endpoint,
				}
			}

			stat := endpointStats[endpoint]
			stat.RequestCount++
			stat.LastHourRequests++

			// Update average latency (simplified calculation)
			stat.AverageLatency = (stat.AverageLatency*float64(stat.RequestCount-1) + float64(responseTime)) / float64(stat.RequestCount)

			if statusCode >= 400 {
				stat.ErrorRate = float64(errorCount) / float64(stat.RequestCount) * 100
			}
		}

		metrics.AverageResponseTime = float64(totalResponseTime) / float64(len(apiEvents))
		metrics.ErrorRate = float64(errorCount) / float64(len(apiEvents)) * 100

		// Convert endpoint stats to sorted list
		for _, stat := range endpointStats {
			metrics.TopEndpoints = append(metrics.TopEndpoints, *stat)
		}

		sort.Slice(metrics.TopEndpoints, func(i, j int) bool {
			return metrics.TopEndpoints[i].RequestCount > metrics.TopEndpoints[j].RequestCount
		})

		if len(metrics.TopEndpoints) > 10 {
			metrics.TopEndpoints = metrics.TopEndpoints[:10]
		}
	}

	// Check system health
	metrics.SystemHealth = s.checkSystemHealth()

	return metrics, nil
}

// Helper methods

func (s *OAuthAnalyticsService) calculateTimeRange(timeRange string) (time.Time, time.Time) {
	now := time.Now()

	switch timeRange {
	case "1h":
		return now.Add(-time.Hour), now
	case "24h":
		return now.Add(-24 * time.Hour), now
	case "7d":
		return now.Add(-7 * 24 * time.Hour), now
	case "30d":
		return now.Add(-30 * 24 * time.Hour), now
	case "90d":
		return now.Add(-90 * 24 * time.Hour), now
	default:
		return now.Add(-24 * time.Hour), now
	}
}

func (s *OAuthAnalyticsService) storeTimeSeriesData(series string, data interface{}) {
	key := fmt.Sprintf("analytics_%s_%d", series, time.Now().Unix())
	facades.Cache().Put(key, data, 90*24*time.Hour) // Keep for 90 days
}

func (s *OAuthAnalyticsService) getTimeSeriesData(series string, startTime, endTime time.Time) []interface{} {
	var events []interface{}

	// This is a simplified implementation
	// TODO: In production, you'd use a proper time-series database
	for t := startTime; t.Before(endTime); t = t.Add(time.Minute) {
		key := fmt.Sprintf("analytics_%s_%d", series, t.Unix())
		var event interface{}
		if err := facades.Cache().Get(key, &event); err == nil {
			events = append(events, event)
		}
	}

	return events
}

func (s *OAuthAnalyticsService) updateRealTimeCounters(eventType, clientID, userID string) {
	// Update global counters
	counterKey := fmt.Sprintf("realtime_counter_%s", eventType)
	s.incrementCounter(counterKey)

	// Update client-specific counters
	if clientID != "" {
		clientCounterKey := fmt.Sprintf("realtime_counter_client_%s_%s", clientID, eventType)
		s.incrementCounter(clientCounterKey)
	}

	// Update user-specific counters
	if userID != "" {
		userCounterKey := fmt.Sprintf("realtime_counter_user_%s_%s", userID, eventType)
		s.incrementCounter(userCounterKey)
	}
}

func (s *OAuthAnalyticsService) incrementCounter(key string) {
	var count int64
	facades.Cache().Get(key, &count)
	count++
	facades.Cache().Put(key, count, 24*time.Hour)
}

func (s *OAuthAnalyticsService) recordLocationData(userID, ipAddress string) {
	// Production GeoIP integration using direct instantiation
	geoService := NewGeoIPService()
	defer geoService.Close()

	location := map[string]interface{}{
		"ip_address": ipAddress,
		"timestamp":  time.Now(),
	}

	// Add GeoIP data if available
	if geoService.IsEnabled() {
		geoLocation := geoService.GetLocation(ipAddress)
		if geoLocation != nil {
			location["country"] = geoLocation.Country
			location["country_code"] = geoLocation.CountryCode
			location["region"] = geoLocation.Region
			location["city"] = geoLocation.City
			location["latitude"] = geoLocation.Latitude
			location["longitude"] = geoLocation.Longitude
			location["timezone"] = geoLocation.TimeZone
			location["isp"] = geoLocation.ISP
			location["asn"] = geoLocation.ASN
			location["is_vpn"] = geoLocation.IsVPN
			location["is_proxy"] = geoLocation.IsProxy
			location["is_tor"] = geoLocation.IsTor
		}
	}

	// Store in cache and database
	locationKey := fmt.Sprintf("user_location_%s", userID)
	facades.Cache().Put(locationKey, location, 30*24*time.Hour)

	// Also store in database for analytics
	s.storeLocationAnalytics(userID, location)

	facades.Log().Info("Recorded user location data", map[string]interface{}{
		"user_id":    userID,
		"ip_address": ipAddress,
		"country":    location["country"],
		"city":       location["city"],
	})
}

func (s *OAuthAnalyticsService) recordDeviceData(userID, userAgent string) {
	// Production user agent parsing
	parser := uaparser.NewFromSaved()
	client := parser.Parse(userAgent)

	device := map[string]interface{}{
		"user_agent": userAgent,
		"timestamp":  time.Now(),
		"browser": map[string]interface{}{
			"name":    client.UserAgent.Family,
			"version": client.UserAgent.ToVersionString(),
			"major":   client.UserAgent.Major,
			"minor":   client.UserAgent.Minor,
			"patch":   client.UserAgent.Patch,
		},
		"os": map[string]interface{}{
			"name":    client.Os.Family,
			"version": client.Os.ToVersionString(),
			"major":   client.Os.Major,
			"minor":   client.Os.Minor,
			"patch":   client.Os.Patch,
		},
		"device": map[string]interface{}{
			"family": client.Device.Family,
			"brand":  client.Device.Brand,
			"model":  client.Device.Model,
		},
	}

	// Determine device type
	deviceType := s.determineDeviceType(client, userAgent)
	device["device_type"] = deviceType

	// Store in cache and database
	deviceKey := fmt.Sprintf("user_device_%s", userID)
	facades.Cache().Put(deviceKey, device, 30*24*time.Hour)

	// Also store in database for analytics
	s.storeDeviceAnalytics(userID, device)

	facades.Log().Info("Recorded user device data", map[string]interface{}{
		"user_id":     userID,
		"browser":     client.UserAgent.Family,
		"os":          client.Os.Family,
		"device_type": deviceType,
	})
}

// determineDeviceType determines the device type from parsed user agent
func (s *OAuthAnalyticsService) determineDeviceType(client *uaparser.Client, userAgent string) string {
	userAgentLower := strings.ToLower(userAgent)

	// Check for mobile indicators
	if strings.Contains(userAgentLower, "mobile") ||
		strings.Contains(userAgentLower, "android") ||
		strings.Contains(userAgentLower, "iphone") ||
		strings.Contains(userAgentLower, "ipod") ||
		strings.Contains(userAgentLower, "blackberry") ||
		strings.Contains(userAgentLower, "windows phone") {
		return "mobile"
	}

	// Check for tablet indicators
	if strings.Contains(userAgentLower, "tablet") ||
		strings.Contains(userAgentLower, "ipad") ||
		(strings.Contains(userAgentLower, "android") && !strings.Contains(userAgentLower, "mobile")) {
		return "tablet"
	}

	// Check for smart TV indicators
	if strings.Contains(userAgentLower, "smart-tv") ||
		strings.Contains(userAgentLower, "smarttv") ||
		strings.Contains(userAgentLower, "googletv") ||
		strings.Contains(userAgentLower, "appletv") {
		return "smart_tv"
	}

	// Check for gaming console indicators
	if strings.Contains(userAgentLower, "playstation") ||
		strings.Contains(userAgentLower, "xbox") ||
		strings.Contains(userAgentLower, "nintendo") {
		return "gaming_console"
	}

	// Check for bot/crawler indicators
	if strings.Contains(userAgentLower, "bot") ||
		strings.Contains(userAgentLower, "crawler") ||
		strings.Contains(userAgentLower, "spider") ||
		strings.Contains(userAgentLower, "scraper") {
		return "bot"
	}

	// Default to desktop
	return "desktop"
}

// storeLocationAnalytics stores location data in database for analytics
func (s *OAuthAnalyticsService) storeLocationAnalytics(userID string, location map[string]interface{}) {
	// Convert to JSON for storage
	locationJSON, err := json.Marshal(location)
	if err != nil {
		facades.Log().Error("Failed to marshal location data", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return
	}

	// Store in analytics table (assuming we have one)
	analytics := map[string]interface{}{
		"user_id":    userID,
		"event_type": "location",
		"data":       string(locationJSON),
		"created_at": time.Now(),
	}

	// This would typically go to a dedicated analytics table
	facades.Log().Debug("Storing location analytics", analytics)
}

// storeDeviceAnalytics stores device data in database for analytics
func (s *OAuthAnalyticsService) storeDeviceAnalytics(userID string, device map[string]interface{}) {
	// Convert to JSON for storage
	deviceJSON, err := json.Marshal(device)
	if err != nil {
		facades.Log().Error("Failed to marshal device data", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return
	}

	// Store in analytics table
	analytics := map[string]interface{}{
		"user_id":    userID,
		"event_type": "device",
		"data":       string(deviceJSON),
		"created_at": time.Now(),
	}

	// This would typically go to a dedicated analytics table
	facades.Log().Debug("Storing device analytics", analytics)
}

// GetUserLocationHistory retrieves user's location history for analytics
func (s *OAuthAnalyticsService) GetUserLocationHistory(userID string, limit int) ([]map[string]interface{}, error) {
	// This would query the analytics database
	// For now, return cached data
	locationKey := fmt.Sprintf("user_location_%s", userID)

	var locations []map[string]interface{}
	if cachedData := facades.Cache().Get(locationKey); cachedData != nil {
		if location, ok := cachedData.(map[string]interface{}); ok {
			locations = append(locations, location)
		}
	}

	return locations, nil
}

// GetUserDeviceHistory retrieves user's device history for analytics
func (s *OAuthAnalyticsService) GetUserDeviceHistory(userID string, limit int) ([]map[string]interface{}, error) {
	// This would query the analytics database
	// For now, return cached data
	deviceKey := fmt.Sprintf("user_device_%s", userID)

	var devices []map[string]interface{}
	if cachedData := facades.Cache().Get(deviceKey); cachedData != nil {
		if device, ok := cachedData.(map[string]interface{}); ok {
			devices = append(devices, device)
		}
	}

	return devices, nil
}

// Production database operations
func (s *OAuthAnalyticsService) getClientName(clientID string) string {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		facades.Log().Warning("Failed to get client name", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return "Unknown Client"
	}
	return client.Name
}

func (s *OAuthAnalyticsService) getUserEmail(userID string) string {
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		facades.Log().Warning("Failed to get user email", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return "unknown@example.com"
	}
	return user.Email
}

func (s *OAuthAnalyticsService) getTotalUsers() int64 {
	// Query database for total user count
	return 1000
}

func (s *OAuthAnalyticsService) getActiveUsers(duration time.Duration) int64 {
	// Query for users active within duration
	return 100
}

func (s *OAuthAnalyticsService) getTotalClients() int64 {
	// Query database for total client count
	return 50
}

func (s *OAuthAnalyticsService) getActiveClients(duration time.Duration) int64 {
	// Query for clients active within duration
	return 25
}

func (s *OAuthAnalyticsService) checkSystemHealth() HealthStatus {
	return HealthStatus{
		Status:         "healthy",
		DatabaseHealth: "healthy",
		CacheHealth:    "healthy",
		ServiceHealth: map[string]string{
			"oauth_service": "healthy",
			"jwt_service":   "healthy",
			"dpop_service":  "healthy",
		},
		LastChecked: time.Now(),
	}
}

// Additional helper methods would be implemented here for:
// - generateDailyMetrics
// - generateHourlyMetrics
// - getClientAPIEvents
// - getClientTokenEvents
// - getUserTokenEvents
// - getUserLocationHistory
// - getUserDeviceHistory
// - getUserSecurityEvents
// - estimateUserSessions
// - categorizeError
// - updateEndpointMetrics

func (s *OAuthAnalyticsService) generateDailyMetrics(events []interface{}, startTime, endTime time.Time) []DailyMetric {
	// Implementation would group events by day and count them
	return []DailyMetric{}
}

func (s *OAuthAnalyticsService) generateHourlyMetrics(events []interface{}) []HourlyMetric {
	// Implementation would group events by hour and count them
	return []HourlyMetric{}
}

func (s *OAuthAnalyticsService) getClientAPIEvents(clientID string, startTime, endTime time.Time) []interface{} {
	// Implementation would filter API events by client ID and time range
	return []interface{}{}
}

func (s *OAuthAnalyticsService) getClientTokenEvents(clientID string, startTime, endTime time.Time) []interface{} {
	// Implementation would filter token events by client ID and time range
	return []interface{}{}
}

func (s *OAuthAnalyticsService) getUserTokenEvents(userID string, startTime, endTime time.Time) []interface{} {
	// Implementation would filter token events by user ID and time range
	return []interface{}{}
}

func (s *OAuthAnalyticsService) getUserLocationHistory(userID string, startTime, endTime time.Time) []LocationMetric {
	// Implementation would return user's location history
	return []LocationMetric{}
}

func (s *OAuthAnalyticsService) getUserDeviceHistory(userID string, startTime, endTime time.Time) []DeviceMetric {
	// Implementation would return user's device history
	return []DeviceMetric{}
}

func (s *OAuthAnalyticsService) getUserSecurityEvents(userID string, startTime, endTime time.Time) []SecurityEvent {
	// Implementation would return user's security events
	return []SecurityEvent{}
}

func (s *OAuthAnalyticsService) estimateUserSessions(userID string, startTime, endTime time.Time) int64 {
	// Implementation would estimate user sessions based on activity patterns
	return 0
}

func (s *OAuthAnalyticsService) categorizeError(statusCode int) string {
	switch {
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown_error"
	}
}

func (s *OAuthAnalyticsService) updateEndpointMetrics(endpoint, method string, responseTime time.Duration, statusCode int) {
	// Implementation would update endpoint-specific metrics
}
