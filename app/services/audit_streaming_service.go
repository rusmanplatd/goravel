package services

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// AuditStreamingService provides real-time streaming of audit logs
type AuditStreamingService struct {
	subscribers    map[string]*AuditSubscriber
	subscribersMux sync.RWMutex
	eventBuffer    chan *AuditStreamEvent
	stopChan       chan struct{}
	bufferSize     int
}

// AuditSubscriber represents a subscriber to audit log streams
type AuditSubscriber struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	UserID      string                 `json:"user_id"`
	Filters     *AuditStreamFilters    `json:"filters"`
	EventChan   chan *AuditStreamEvent `json:"-"`
	LastSeen    time.Time              `json:"last_seen"`
	IsActive    bool                   `json:"is_active"`
	Permissions []string               `json:"permissions"`
}

// AuditStreamFilters defines filters for audit log streaming
type AuditStreamFilters struct {
	Categories        []models.ActivityLogCategory `json:"categories"`
	Severities        []models.ActivityLogSeverity `json:"severities"`
	MinRiskScore      int                          `json:"min_risk_score"`
	MaxRiskScore      int                          `json:"max_risk_score"`
	UserIDs           []string                     `json:"user_ids"`
	IPAddresses       []string                     `json:"ip_addresses"`
	EventTypes        []string                     `json:"event_types"`
	SecurityOnly      bool                         `json:"security_only"`
	ComplianceOnly    bool                         `json:"compliance_only"`
	RealTimeOnly      bool                         `json:"real_time_only"`
	IncludeHistorical bool                         `json:"include_historical"`
}

// AuditStreamEvent represents a streamed audit event
type AuditStreamEvent struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	ActivityLog   *models.ActivityLog    `json:"activity_log"`
	Timestamp     time.Time              `json:"timestamp"`
	TenantID      string                 `json:"tenant_id"`
	Priority      string                 `json:"priority"`
	SecurityAlert *SecurityAlert         `json:"security_alert,omitempty"`
	Correlation   *AuditEventCorrelation `json:"correlation,omitempty"`
	Enrichment    *AuditEventEnrichment  `json:"enrichment,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SecurityAlert represents a security alert for streaming
type AuditSecurityAlert struct {
	AlertID      string                 `json:"alert_id"`
	AlertType    string                 `json:"alert_type"`
	Severity     string                 `json:"severity"`
	Description  string                 `json:"description"`
	RiskScore    int                    `json:"risk_score"`
	ThreatLevel  string                 `json:"threat_level"`
	Indicators   []ThreatIndicator      `json:"indicators"`
	Mitigation   []string               `json:"mitigation"`
	AutoResponse bool                   `json:"auto_response"`
	Context      map[string]interface{} `json:"context"`
}

// AuditEventCorrelation represents event correlation data
type AuditEventCorrelation struct {
	CorrelationID string                 `json:"correlation_id"`
	RelatedEvents []string               `json:"related_events"`
	Pattern       string                 `json:"pattern"`
	Confidence    float64                `json:"confidence"`
	Timeline      []CorrelationPoint     `json:"timeline"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// CorrelationPoint represents a point in the correlation timeline
type CorrelationPoint struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
	Importance  string    `json:"importance"`
}

// AuditEventEnrichment represents enriched event data
type AuditEventEnrichment struct {
	GeoLocation     *GeoLocationEnrichment      `json:"geo_location,omitempty"`
	UserContext     *UserContextEnrichment      `json:"user_context,omitempty"`
	DeviceContext   *DeviceContextEnrichment    `json:"device_context,omitempty"`
	ThreatIntel     *AuditThreatIntelEnrichment `json:"threat_intel,omitempty"`
	BusinessContext *BusinessContextEnrichment  `json:"business_context,omitempty"`
}

// GeoLocationEnrichment represents enriched geo location data
type GeoLocationEnrichment struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
	IsVPN        bool    `json:"is_vpn"`
	IsTor        bool    `json:"is_tor"`
	IsProxy      bool    `json:"is_proxy"`
	RiskScore    int     `json:"risk_score"`
	Reputation   string  `json:"reputation"`
	TimeZone     string  `json:"time_zone"`
	Coordinates  *LatLng `json:"coordinates,omitempty"`
}

// UserContextEnrichment represents enriched user context
type UserContextEnrichment struct {
	UserProfile     *UserProfile           `json:"user_profile,omitempty"`
	Roles           []string               `json:"roles"`
	Permissions     []string               `json:"permissions"`
	Groups          []string               `json:"groups"`
	RecentActivity  *RecentActivitySummary `json:"recent_activity,omitempty"`
	RiskProfile     *UserRiskProfile       `json:"risk_profile,omitempty"`
	BehaviorProfile *UserBehaviorProfile   `json:"behavior_profile,omitempty"`
}

// DeviceContextEnrichment represents enriched device context
type DeviceContextEnrichment struct {
	DeviceID         string                 `json:"device_id"`
	DeviceType       string                 `json:"device_type"`
	OS               string                 `json:"os"`
	Browser          string                 `json:"browser"`
	IsKnownDevice    bool                   `json:"is_known_device"`
	IsTrustedDevice  bool                   `json:"is_trusted_device"`
	LastSeen         time.Time              `json:"last_seen"`
	RiskScore        int                    `json:"risk_score"`
	Fingerprint      string                 `json:"fingerprint"`
	Capabilities     []string               `json:"capabilities"`
	SecurityFeatures map[string]interface{} `json:"security_features"`
}

// AuditThreatIntelEnrichment represents threat intelligence enrichment
type AuditThreatIntelEnrichment struct {
	ThreatTypes []string                `json:"threat_types"`
	Indicators  []ThreatIndicator       `json:"indicators"`
	Reputation  string                  `json:"reputation"`
	RiskScore   int                     `json:"risk_score"`
	Sources     []string                `json:"sources"`
	LastUpdated time.Time               `json:"last_updated"`
	Confidence  float64                 `json:"confidence"`
	Attribution *AuditThreatAttribution `json:"attribution,omitempty"`
	Context     map[string]interface{}  `json:"context"`
}

// ThreatIndicator represents a threat indicator
type AuditThreatIndicator struct {
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Context     map[string]interface{} `json:"context"`
}

// AuditThreatAttribution represents threat attribution data
type AuditThreatAttribution struct {
	Actor      string   `json:"actor"`
	Group      string   `json:"group"`
	Campaign   string   `json:"campaign"`
	Motivation string   `json:"motivation"`
	TTPs       []string `json:"ttps"`
	Confidence float64  `json:"confidence"`
}

// BusinessContextEnrichment represents business context enrichment
type BusinessContextEnrichment struct {
	Department         string                 `json:"department"`
	BusinessUnit       string                 `json:"business_unit"`
	CostCenter         string                 `json:"cost_center"`
	Project            string                 `json:"project"`
	DataClassification string                 `json:"data_classification"`
	ComplianceScope    []string               `json:"compliance_scope"`
	BusinessImpact     string                 `json:"business_impact"`
	Criticality        string                 `json:"criticality"`
	Context            map[string]interface{} `json:"context"`
}

// Supporting types
type LatLng struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type UserProfile struct {
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	FullName   string    `json:"full_name"`
	Department string    `json:"department"`
	Title      string    `json:"title"`
	Manager    string    `json:"manager"`
	CreatedAt  time.Time `json:"created_at"`
	LastLogin  time.Time `json:"last_login"`
	IsActive   bool      `json:"is_active"`
}

type RecentActivitySummary struct {
	LoginCount       int       `json:"login_count"`
	FailedAttempts   int       `json:"failed_attempts"`
	LastActivity     time.Time `json:"last_activity"`
	UniqueIPs        int       `json:"unique_ips"`
	SecurityEvents   int       `json:"security_events"`
	AverageRiskScore float64   `json:"average_risk_score"`
}

type UserRiskProfile struct {
	RiskScore      int                    `json:"risk_score"`
	RiskLevel      string                 `json:"risk_level"`
	RiskFactors    []string               `json:"risk_factors"`
	LastAssessment time.Time              `json:"last_assessment"`
	Trends         map[string]interface{} `json:"trends"`
}

type UserBehaviorProfile struct {
	TypicalHours     []int                  `json:"typical_hours"`
	TypicalDays      []int                  `json:"typical_days"`
	TypicalLocations []string               `json:"typical_locations"`
	TypicalDevices   []string               `json:"typical_devices"`
	ActivityPatterns map[string]interface{} `json:"activity_patterns"`
	LastUpdated      time.Time              `json:"last_updated"`
}

// NewAuditStreamingService creates a new audit streaming service
func NewAuditStreamingService() *AuditStreamingService {
	service := &AuditStreamingService{
		subscribers:    make(map[string]*AuditSubscriber),
		subscribersMux: sync.RWMutex{},
		eventBuffer:    make(chan *AuditStreamEvent, 1000),
		stopChan:       make(chan struct{}),
		bufferSize:     1000,
	}

	// Start event processing goroutine
	go service.processEvents()

	return service
}

// Subscribe adds a new subscriber to the audit stream
func (ass *AuditStreamingService) Subscribe(tenantID, userID string, filters *AuditStreamFilters, permissions []string) (*AuditSubscriber, error) {
	ass.subscribersMux.Lock()
	defer ass.subscribersMux.Unlock()

	subscriberID := fmt.Sprintf("%s_%s_%d", tenantID, userID, time.Now().UnixNano())

	subscriber := &AuditSubscriber{
		ID:          subscriberID,
		TenantID:    tenantID,
		UserID:      userID,
		Filters:     filters,
		EventChan:   make(chan *AuditStreamEvent, 100),
		LastSeen:    time.Now(),
		IsActive:    true,
		Permissions: permissions,
	}

	ass.subscribers[subscriberID] = subscriber

	facades.Log().Info("New audit stream subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
		"tenant_id":     tenantID,
		"user_id":       userID,
		"filters":       filters,
	})

	// Send historical events if requested
	if filters != nil && filters.IncludeHistorical {
		go ass.sendHistoricalEvents(subscriber)
	}

	return subscriber, nil
}

// Unsubscribe removes a subscriber from the audit stream
func (ass *AuditStreamingService) Unsubscribe(subscriberID string) error {
	ass.subscribersMux.Lock()
	defer ass.subscribersMux.Unlock()

	subscriber, exists := ass.subscribers[subscriberID]
	if !exists {
		return fmt.Errorf("subscriber not found: %s", subscriberID)
	}

	subscriber.IsActive = false
	close(subscriber.EventChan)
	delete(ass.subscribers, subscriberID)

	facades.Log().Info("Audit stream subscriber unsubscribed", map[string]interface{}{
		"subscriber_id": subscriberID,
		"tenant_id":     subscriber.TenantID,
		"user_id":       subscriber.UserID,
	})

	return nil
}

// StreamEvent streams an audit event to all relevant subscribers
func (ass *AuditStreamingService) StreamEvent(activityLog *models.ActivityLog) {
	event := &AuditStreamEvent{
		ID:          fmt.Sprintf("stream_%d", time.Now().UnixNano()),
		Type:        "audit_log",
		ActivityLog: activityLog,
		Timestamp:   time.Now(),
		TenantID:    activityLog.TenantID,
		Priority:    ass.determinePriority(activityLog),
		Metadata:    make(map[string]interface{}),
	}

	// Add security alert if high risk
	if activityLog.IsHighRisk() || activityLog.IsSecurity() {
		event.SecurityAlert = ass.createSecurityAlert(activityLog)
		event.Type = "security_alert"
	}

	// Add enrichment data
	event.Enrichment = ass.enrichEvent(activityLog)

	// Add correlation data if available
	event.Correlation = ass.correlateEvent(activityLog)

	select {
	case ass.eventBuffer <- event:
		// Event buffered successfully
	default:
		// Buffer full, log warning
		facades.Log().Warning("Audit stream buffer full, dropping event", map[string]interface{}{
			"event_id":    event.ID,
			"activity_id": activityLog.ID,
			"buffer_size": ass.bufferSize,
		})
	}
}

// GetSubscriber returns a subscriber by ID
func (ass *AuditStreamingService) GetSubscriber(subscriberID string) (*AuditSubscriber, error) {
	ass.subscribersMux.RLock()
	defer ass.subscribersMux.RUnlock()

	subscriber, exists := ass.subscribers[subscriberID]
	if !exists {
		return nil, fmt.Errorf("subscriber not found: %s", subscriberID)
	}

	return subscriber, nil
}

// GetActiveSubscribers returns all active subscribers
func (ass *AuditStreamingService) GetActiveSubscribers() []*AuditSubscriber {
	ass.subscribersMux.RLock()
	defer ass.subscribersMux.RUnlock()

	var active []*AuditSubscriber
	for _, subscriber := range ass.subscribers {
		if subscriber.IsActive {
			active = append(active, subscriber)
		}
	}

	return active
}

// UpdateSubscriberFilters updates filters for a subscriber
func (ass *AuditStreamingService) UpdateSubscriberFilters(subscriberID string, filters *AuditStreamFilters) error {
	ass.subscribersMux.Lock()
	defer ass.subscribersMux.Unlock()

	subscriber, exists := ass.subscribers[subscriberID]
	if !exists {
		return fmt.Errorf("subscriber not found: %s", subscriberID)
	}

	subscriber.Filters = filters
	subscriber.LastSeen = time.Now()

	facades.Log().Info("Audit stream subscriber filters updated", map[string]interface{}{
		"subscriber_id": subscriberID,
		"new_filters":   filters,
	})

	return nil
}

// Close gracefully shuts down the streaming service
func (ass *AuditStreamingService) Close() error {
	close(ass.stopChan)

	// Close all subscriber channels
	ass.subscribersMux.Lock()
	for _, subscriber := range ass.subscribers {
		subscriber.IsActive = false
		close(subscriber.EventChan)
	}
	ass.subscribersMux.Unlock()

	close(ass.eventBuffer)

	facades.Log().Info("Audit streaming service closed")
	return nil
}

// processEvents processes events from the buffer and distributes to subscribers
func (ass *AuditStreamingService) processEvents() {
	for {
		select {
		case event := <-ass.eventBuffer:
			ass.distributeEvent(event)
		case <-ass.stopChan:
			return
		}
	}
}

// distributeEvent distributes an event to relevant subscribers
func (ass *AuditStreamingService) distributeEvent(event *AuditStreamEvent) {
	ass.subscribersMux.RLock()
	defer ass.subscribersMux.RUnlock()

	distributed := 0
	for _, subscriber := range ass.subscribers {
		if !subscriber.IsActive {
			continue
		}

		// Check tenant access
		if subscriber.TenantID != event.TenantID {
			continue
		}

		// Apply filters
		if !ass.matchesFilters(event, subscriber.Filters) {
			continue
		}

		// Check permissions
		if !ass.hasPermission(subscriber, event) {
			continue
		}

		// Send event to subscriber
		select {
		case subscriber.EventChan <- event:
			distributed++
			subscriber.LastSeen = time.Now()
		default:
			// Subscriber channel full, log warning
			facades.Log().Warning("Subscriber channel full, dropping event", map[string]interface{}{
				"subscriber_id": subscriber.ID,
				"event_id":      event.ID,
			})
		}
	}

	if distributed > 0 {
		facades.Log().Debug("Event distributed to subscribers", map[string]interface{}{
			"event_id":    event.ID,
			"distributed": distributed,
		})
	}
}

// matchesFilters checks if an event matches subscriber filters
func (ass *AuditStreamingService) matchesFilters(event *AuditStreamEvent, filters *AuditStreamFilters) bool {
	if filters == nil {
		return true
	}

	activityLog := event.ActivityLog
	if activityLog == nil {
		return false
	}

	// Category filter
	if len(filters.Categories) > 0 {
		match := false
		for _, category := range filters.Categories {
			if activityLog.Category == category {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// Severity filter
	if len(filters.Severities) > 0 {
		match := false
		for _, severity := range filters.Severities {
			if activityLog.Severity == severity {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// Risk score filter
	if filters.MinRiskScore > 0 && activityLog.RiskScore < filters.MinRiskScore {
		return false
	}
	if filters.MaxRiskScore > 0 && activityLog.RiskScore > filters.MaxRiskScore {
		return false
	}

	// User ID filter
	if len(filters.UserIDs) > 0 {
		match := false
		for _, userID := range filters.UserIDs {
			if activityLog.SubjectID == userID {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// IP address filter
	if len(filters.IPAddresses) > 0 {
		match := false
		for _, ip := range filters.IPAddresses {
			if activityLog.IPAddress == ip {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// Security only filter
	if filters.SecurityOnly && !activityLog.IsSecurity() {
		return false
	}

	// Compliance only filter
	if filters.ComplianceOnly && activityLog.Category != models.CategoryCompliance {
		return false
	}

	return true
}

// hasPermission checks if subscriber has permission to view the event
func (ass *AuditStreamingService) hasPermission(subscriber *AuditSubscriber, event *AuditStreamEvent) bool {
	// Check if subscriber has audit read permission
	for _, permission := range subscriber.Permissions {
		if permission == "audit.read" || permission == "audit.stream" || permission == "*" {
			return true
		}
	}

	// Check for security event permissions
	if event.Type == "security_alert" {
		for _, permission := range subscriber.Permissions {
			if permission == "security.read" || permission == "security.alerts" {
				return true
			}
		}
	}

	return false
}

// sendHistoricalEvents sends historical events to a new subscriber
func (ass *AuditStreamingService) sendHistoricalEvents(subscriber *AuditSubscriber) {
	// Get recent historical events (last 24 hours)
	since := time.Now().Add(-24 * time.Hour)

	var activities []models.ActivityLog
	query := facades.Orm().Query().
		Where("tenant_id = ? AND event_timestamp >= ?", subscriber.TenantID, since).
		OrderBy("event_timestamp DESC").
		Limit(100)

	err := query.Find(&activities)
	if err != nil {
		facades.Log().Error("Failed to fetch historical events", map[string]interface{}{
			"error":         err.Error(),
			"subscriber_id": subscriber.ID,
		})
		return
	}

	// Send historical events
	for _, activity := range activities {
		event := &AuditStreamEvent{
			ID:          fmt.Sprintf("historical_%s", activity.ID),
			Type:        "historical_audit_log",
			ActivityLog: &activity,
			Timestamp:   activity.EventTimestamp,
			TenantID:    activity.TenantID,
			Priority:    ass.determinePriority(&activity),
			Metadata: map[string]interface{}{
				"historical": true,
			},
		}

		if ass.matchesFilters(event, subscriber.Filters) && ass.hasPermission(subscriber, event) {
			select {
			case subscriber.EventChan <- event:
				// Event sent
			default:
				// Channel full, stop sending historical events
				break
			}
		}
	}

	facades.Log().Info("Historical events sent to subscriber", map[string]interface{}{
		"subscriber_id": subscriber.ID,
		"event_count":   len(activities),
	})
}

// Helper methods

func (ass *AuditStreamingService) determinePriority(activityLog *models.ActivityLog) string {
	if activityLog.Severity == models.SeverityCritical {
		return "critical"
	}
	if activityLog.Severity == models.SeverityHigh || activityLog.RiskScore > 80 {
		return "high"
	}
	if activityLog.Severity == models.SeverityMedium || activityLog.RiskScore > 50 {
		return "medium"
	}
	return "low"
}

func (ass *AuditStreamingService) createSecurityAlert(activityLog *models.ActivityLog) *SecurityAlert {
	return &SecurityAlert{
		ID:        fmt.Sprintf("alert_%s", activityLog.ID),
		UserID:    activityLog.CauserID,
		Provider:  "audit_system",
		AlertType: "audit_security_event",
		Severity:  string(activityLog.Severity),
		Message:   activityLog.Description,
		Details: map[string]interface{}{
			"activity_id":  activityLog.ID,
			"log_name":     activityLog.LogName,
			"category":     activityLog.Category,
			"risk_score":   activityLog.RiskScore,
			"threat_level": activityLog.ThreatLevel,
			"ip_address":   activityLog.IPAddress,
			"indicators": []ThreatIndicator{
				{
					Type:       "ip_address",
					Value:      activityLog.IPAddress,
					Confidence: 0.8,
					Severity:   float64(activityLog.RiskScore) / 100.0, // Convert to 0-1 scale
					Source:     "audit_log",
					FirstSeen:  activityLog.CreatedAt,
					LastSeen:   activityLog.CreatedAt,
				},
			},
		},
		Timestamp:    activityLog.CreatedAt,
		Acknowledged: false,
		ResolvedAt:   nil,
	}
}

func (ass *AuditStreamingService) enrichEvent(activityLog *models.ActivityLog) *AuditEventEnrichment {
	enrichment := &AuditEventEnrichment{}

	// Add geo location enrichment
	if activityLog.GeoLocation != nil {
		var geoData map[string]interface{}
		if err := json.Unmarshal(activityLog.GeoLocation, &geoData); err == nil {
			enrichment.GeoLocation = &GeoLocationEnrichment{
				Country:    getStringValue(geoData, "country"),
				Region:     getStringValue(geoData, "region"),
				City:       getStringValue(geoData, "city"),
				ISP:        getStringValue(geoData, "isp"),
				RiskScore:  getIntValue(geoData, "risk_score"),
				Reputation: getStringValue(geoData, "reputation"),
				TimeZone:   getStringValue(geoData, "timezone"),
			}
		}
	}

	// Add device context enrichment
	if activityLog.DeviceInfo != nil {
		var deviceData map[string]interface{}
		if err := json.Unmarshal(activityLog.DeviceInfo, &deviceData); err == nil {
			enrichment.DeviceContext = &DeviceContextEnrichment{
				DeviceType:      getStringValue(deviceData, "type"),
				OS:              getStringValue(deviceData, "os"),
				Browser:         getStringValue(deviceData, "browser"),
				IsKnownDevice:   getBoolValue(deviceData, "is_known"),
				IsTrustedDevice: getBoolValue(deviceData, "is_trusted"),
				RiskScore:       getIntValue(deviceData, "risk_score"),
				Fingerprint:     getStringValue(deviceData, "fingerprint"),
			}
		}
	}

	return enrichment
}

func (ass *AuditStreamingService) correlateEvent(activityLog *models.ActivityLog) *AuditEventCorrelation {
	// This would implement event correlation logic
	// For now, return basic correlation data
	return &AuditEventCorrelation{
		CorrelationID: fmt.Sprintf("corr_%s", activityLog.ID),
		RelatedEvents: []string{},
		Pattern:       "single_event",
		Confidence:    1.0,
		Timeline: []CorrelationPoint{
			{
				EventID:     activityLog.ID,
				Timestamp:   activityLog.EventTimestamp,
				Description: activityLog.Description,
				Importance:  "primary",
			},
		},
		Metadata: map[string]interface{}{
			"source": "audit_log",
		},
	}
}
