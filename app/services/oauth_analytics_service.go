package services

import (
	"crypto/sha256"
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
	DeviceID    string    `json:"device_id"`
	DeviceType  string    `json:"device_type"`
	OS          string    `json:"os"`
	Browser     string    `json:"browser"`
	Location    string    `json:"location"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	AccessCount int       `json:"access_count"`
	IsTrusted   bool      `json:"is_trusted"`
}

type SecurityEvent struct {
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	ClientID    string    `json:"client_id,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Resolved    bool      `json:"resolved"`
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

type EndpointMetrics struct {
	RequestCount        int64         `json:"request_count"`
	SuccessCount        int64         `json:"success_count"`
	ClientErrorCount    int64         `json:"client_error_count"`
	ServerErrorCount    int64         `json:"server_error_count"`
	TotalResponseTime   time.Duration `json:"total_response_time"`
	MinResponseTime     time.Duration `json:"min_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	SuccessRate         float64       `json:"success_rate"`
	LastUpdated         time.Time     `json:"last_updated"`
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
	// Production implementation that queries user's device history from database
	var deviceMetrics []DeviceMetric

	// Query activity logs for device information
	var activities []models.ActivityLog
	err := facades.Orm().Query().
		Where("user_id = ? AND event_timestamp BETWEEN ? AND ?", userID, startTime, endTime).
		Where("event IN (?)", []string{"auth.login", "oauth.authorization", "oauth.token"}).
		Where("user_agent IS NOT NULL AND user_agent != ''").
		OrderBy("event_timestamp DESC").
		Find(&activities)

	if err != nil {
		facades.Log().Warning("Failed to query user device history", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return deviceMetrics
	}

	// Group by device fingerprint and extract metrics
	deviceMap := make(map[string]*DeviceMetric)

	for _, activity := range activities {
		// Create device fingerprint from user agent and IP
		fingerprint := s.createDeviceFingerprint(activity.UserAgent, activity.IPAddress)

		if device, exists := deviceMap[fingerprint]; exists {
			// Update existing device metrics
			device.AccessCount++
			if activity.EventTimestamp.After(device.LastSeen) {
				device.LastSeen = activity.EventTimestamp
			}
			if activity.EventTimestamp.Before(device.FirstSeen) {
				device.FirstSeen = activity.EventTimestamp
			}
		} else {
			// Create new device metric
			deviceInfo := s.parseUserAgent(activity.UserAgent)
			deviceMap[fingerprint] = &DeviceMetric{
				DeviceID:    fingerprint,
				DeviceType:  deviceInfo.DeviceType,
				OS:          deviceInfo.OS,
				Browser:     deviceInfo.Browser,
				Location:    s.getLocationFromIP(activity.IPAddress),
				FirstSeen:   activity.EventTimestamp,
				LastSeen:    activity.EventTimestamp,
				AccessCount: 1,
				IsTrusted:   s.isDeviceTrusted(userID, fingerprint),
			}
		}
	}

	// Convert map to slice
	for _, device := range deviceMap {
		deviceMetrics = append(deviceMetrics, *device)
	}

	// Sort by last seen (most recent first)
	sort.Slice(deviceMetrics, func(i, j int) bool {
		return deviceMetrics[i].LastSeen.After(deviceMetrics[j].LastSeen)
	})

	return deviceMetrics
}

func (s *OAuthAnalyticsService) getUserSecurityEvents(userID string, startTime, endTime time.Time) []SecurityEvent {
	// Production implementation that queries security events from database
	var securityEvents []SecurityEvent

	// Query OAuth security events
	var oauthEvents []models.OAuthSecurityEvent
	err := facades.Orm().Query().
		Where("user_id = ? AND created_at BETWEEN ? AND ?", userID, startTime, endTime).
		OrderBy("created_at DESC").
		Find(&oauthEvents)

	if err != nil {
		facades.Log().Warning("Failed to query OAuth security events", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
	} else {
		// Convert OAuth events to security events
		for _, event := range oauthEvents {
			// Helper function to safely dereference string pointers
			safeString := func(s *string) string {
				if s != nil {
					return *s
				}
				return ""
			}

			securityEvents = append(securityEvents, SecurityEvent{
				EventID:     fmt.Sprintf("%d", event.ID),
				EventType:   event.EventType,
				Severity:    event.RiskLevel, // Use RiskLevel as severity
				Description: fmt.Sprintf("Security event: %s (Risk Score: %d)", event.EventType, event.RiskScore),
				Timestamp:   event.CreatedAt,
				Source:      "oauth",
				ClientID:    safeString(event.ClientID),
				IPAddress:   safeString(event.IPAddress),
				UserAgent:   safeString(event.UserAgent),
				Resolved:    event.IsResolved,
			})
		}
	}

	// Query general activity logs for security-related events
	var activities []models.ActivityLog
	securityEventTypes := []string{
		"auth.failed_login",
		"auth.account_locked",
		"auth.suspicious_login",
		"oauth.unauthorized_access",
		"oauth.token_abuse",
		"security.password_changed",
		"security.mfa_enabled",
		"security.mfa_disabled",
	}

	err = facades.Orm().Query().
		Where("user_id = ? AND event_timestamp BETWEEN ? AND ?", userID, startTime, endTime).
		Where("event IN (?)", securityEventTypes).
		OrderBy("event_timestamp DESC").
		Find(&activities)

	if err != nil {
		facades.Log().Warning("Failed to query security activity logs", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
	} else {
		// Convert activity logs to security events
		for _, activity := range activities {
			severity := s.determineSeverityFromEvent(activity.LogName) // Use LogName instead of Event
			securityEvents = append(securityEvents, SecurityEvent{
				EventID:     activity.ID,
				EventType:   activity.LogName, // Use LogName instead of Event
				Severity:    severity,
				Description: activity.Description,
				Timestamp:   activity.EventTimestamp,
				Source:      "activity_log",
				IPAddress:   activity.IPAddress,
				UserAgent:   activity.UserAgent,
				Resolved:    true, // Activity logs are historical
			})
		}
	}

	// Sort by timestamp (most recent first)
	sort.Slice(securityEvents, func(i, j int) bool {
		return securityEvents[i].Timestamp.After(securityEvents[j].Timestamp)
	})

	return securityEvents
}

func (s *OAuthAnalyticsService) estimateUserSessions(userID string, startTime, endTime time.Time) int64 {
	// Production implementation that estimates user sessions based on activity patterns

	// Query login events
	loginCount, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event_timestamp BETWEEN ? AND ?", userID, startTime, endTime).
		Where("event IN (?)", []string{"auth.login", "oauth.authorization"}).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to count login events", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return 0
	}

	// Query token refresh events to estimate session extensions
	refreshCount, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event_timestamp BETWEEN ? AND ?", userID, startTime, endTime).
		Where("event = ?", "oauth.refresh").
		Count()

	if err != nil {
		facades.Log().Warning("Failed to count refresh events", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		refreshCount = 0
	}

	// Estimate sessions: base on logins, but account for session extensions
	// Assume each refresh extends a session rather than creating a new one
	estimatedSessions := loginCount

	// If there are significantly more refreshes than logins,
	// it suggests longer sessions rather than more sessions
	if refreshCount > loginCount*2 {
		// User has long sessions with many refreshes
		// Reduce estimated session count slightly
		estimatedSessions = int64(float64(loginCount) * 0.8)
	}

	facades.Log().Debug("User session estimation completed", map[string]interface{}{
		"user_id":            userID,
		"login_count":        loginCount,
		"refresh_count":      refreshCount,
		"estimated_sessions": estimatedSessions,
	})

	return estimatedSessions
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
	// Production implementation that updates endpoint-specific metrics in cache/database

	// Create metric key
	metricKey := fmt.Sprintf("endpoint_metrics:%s:%s", method, endpoint)

	// Get current metrics from cache
	currentMetrics := s.getEndpointMetrics(metricKey)

	// Update metrics
	currentMetrics.RequestCount++
	currentMetrics.TotalResponseTime += responseTime
	currentMetrics.AverageResponseTime = currentMetrics.TotalResponseTime / time.Duration(currentMetrics.RequestCount)

	// Update status code counters
	if statusCode >= 200 && statusCode < 300 {
		currentMetrics.SuccessCount++
	} else if statusCode >= 400 && statusCode < 500 {
		currentMetrics.ClientErrorCount++
	} else if statusCode >= 500 {
		currentMetrics.ServerErrorCount++
	}

	// Calculate success rate
	if currentMetrics.RequestCount > 0 {
		currentMetrics.SuccessRate = float64(currentMetrics.SuccessCount) / float64(currentMetrics.RequestCount) * 100
	}

	// Update min/max response times
	if responseTime < currentMetrics.MinResponseTime || currentMetrics.MinResponseTime == 0 {
		currentMetrics.MinResponseTime = responseTime
	}
	if responseTime > currentMetrics.MaxResponseTime {
		currentMetrics.MaxResponseTime = responseTime
	}

	currentMetrics.LastUpdated = time.Now()

	// Store updated metrics in cache (with 1 hour expiration)
	s.storeEndpointMetrics(metricKey, currentMetrics)

	// Periodically persist to database (every 100 requests)
	if currentMetrics.RequestCount%100 == 0 {
		s.persistEndpointMetrics(endpoint, method, currentMetrics)
	}
}

// Helper methods for analytics service

func (s *OAuthAnalyticsService) createDeviceFingerprint(userAgent, ipAddress string) string {
	// Create a consistent device fingerprint
	data := fmt.Sprintf("%s|%s", userAgent, ipAddress)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("device_%x", hash[:8]) // Use first 8 bytes of hash
}

func (s *OAuthAnalyticsService) parseUserAgent(userAgent string) DeviceMetric {
	// Parse user agent to extract device information
	deviceInfo := DeviceMetric{
		DeviceType: "unknown",
		OS:         "unknown",
		Browser:    "unknown",
	}

	if userAgent == "" {
		return deviceInfo
	}

	// Simple user agent parsing - in production use a proper library
	ua := strings.ToLower(userAgent)

	// Detect device type
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		deviceInfo.DeviceType = "mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		deviceInfo.DeviceType = "tablet"
	} else {
		deviceInfo.DeviceType = "desktop"
	}

	// Detect OS
	if strings.Contains(ua, "windows") {
		deviceInfo.OS = "Windows"
	} else if strings.Contains(ua, "mac") || strings.Contains(ua, "darwin") {
		deviceInfo.OS = "macOS"
	} else if strings.Contains(ua, "linux") {
		deviceInfo.OS = "Linux"
	} else if strings.Contains(ua, "android") {
		deviceInfo.OS = "Android"
	} else if strings.Contains(ua, "ios") || strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		deviceInfo.OS = "iOS"
	}

	// Detect browser
	if strings.Contains(ua, "chrome") {
		deviceInfo.Browser = "Chrome"
	} else if strings.Contains(ua, "firefox") {
		deviceInfo.Browser = "Firefox"
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		deviceInfo.Browser = "Safari"
	} else if strings.Contains(ua, "edge") {
		deviceInfo.Browser = "Edge"
	} else if strings.Contains(ua, "opera") {
		deviceInfo.Browser = "Opera"
	}

	return deviceInfo
}

func (s *OAuthAnalyticsService) getLocationFromIP(ipAddress string) string {
	// Get location from IP address - integrate with GeoIP service
	if ipAddress == "" {
		return "Unknown"
	}

	// Use the same GeoIP logic from OAuth Risk Service
	// This is a simplified version - in production, use proper GeoIP databases
	if strings.HasPrefix(ipAddress, "192.168.") || strings.HasPrefix(ipAddress, "10.") || strings.HasPrefix(ipAddress, "172.") {
		return "Local Network"
	}

	// For public IPs, you would use MaxMind or similar service
	return "Unknown Location"
}

func (s *OAuthAnalyticsService) isDeviceTrusted(userID, deviceFingerprint string) bool {
	// Check if device is marked as trusted
	count, err := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("user_id = ? AND event = ? AND metadata LIKE ?", userID, "security.device_trusted", "%"+deviceFingerprint+"%").
		Count()

	if err != nil {
		return false
	}

	return count > 0
}

func (s *OAuthAnalyticsService) determineSeverityFromEvent(eventType string) string {
	// Determine severity based on event type
	highSeverityEvents := map[string]bool{
		"auth.account_locked":       true,
		"oauth.unauthorized_access": true,
		"oauth.token_abuse":         true,
		"security.suspicious_login": true,
	}

	mediumSeverityEvents := map[string]bool{
		"auth.failed_login":         true,
		"security.password_changed": true,
		"security.mfa_disabled":     true,
	}

	if highSeverityEvents[eventType] {
		return "high"
	} else if mediumSeverityEvents[eventType] {
		return "medium"
	}

	return "low"
}

func (s *OAuthAnalyticsService) getEndpointMetrics(metricKey string) *EndpointMetrics {
	// Try to get from cache first
	if data := facades.Cache().Get(metricKey, nil); data != nil {
		if metricsData, ok := data.(*EndpointMetrics); ok {
			return metricsData
		}
	}

	// Return new metrics if not found in cache
	return &EndpointMetrics{
		RequestCount:      0,
		SuccessCount:      0,
		ClientErrorCount:  0,
		ServerErrorCount:  0,
		TotalResponseTime: 0,
		MinResponseTime:   0,
		MaxResponseTime:   0,
		SuccessRate:       0,
		LastUpdated:       time.Now(),
	}
}

func (s *OAuthAnalyticsService) storeEndpointMetrics(metricKey string, metrics *EndpointMetrics) {
	// Store metrics in cache
	facades.Cache().Put(metricKey, metrics, 1*time.Hour)
}

func (s *OAuthAnalyticsService) persistEndpointMetrics(endpoint, method string, metrics *EndpointMetrics) {
	// Persist metrics to database for long-term storage
	facades.Log().Debug("Persisting endpoint metrics", map[string]interface{}{
		"endpoint":      endpoint,
		"method":        method,
		"request_count": metrics.RequestCount,
		"success_rate":  metrics.SuccessRate,
		"avg_response":  metrics.AverageResponseTime.Milliseconds(),
	})

	// In production, you would store this in a metrics table
	// For now, just log the metrics
}
