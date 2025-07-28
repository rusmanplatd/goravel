package services

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// AuditCorrelationService provides event correlation capabilities
type AuditCorrelationService struct {
	correlationRules  map[string]*CorrelationRule
	correlationCache  map[string]*CorrelationSession
	cacheMutex        sync.RWMutex
	maxCacheSize      int
	sessionTimeout    time.Duration
	correlationWindow time.Duration
	patternDetector   *PatternDetector
	ruleEngine        *CorrelationRuleEngine
}

// CorrelationRule defines how events should be correlated
type CorrelationRule struct {
	RuleID          string                 `json:"rule_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Priority        int                    `json:"priority"`
	IsActive        bool                   `json:"is_active"`
	TriggerEvents   []string               `json:"trigger_events"`
	CorrelateEvents []string               `json:"correlate_events"`
	TimeWindow      time.Duration          `json:"time_window"`
	MaxEvents       int                    `json:"max_events"`
	MatchCriteria   []MatchCriterion       `json:"match_criteria"`
	Actions         []CorrelationAction    `json:"actions"`
	Conditions      []CorrelationCondition `json:"conditions"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// MatchCriterion defines how events should match for correlation
type MatchCriterion struct {
	Field         string      `json:"field"`
	Operator      string      `json:"operator"` // "equals", "contains", "regex", "range"
	Value         interface{} `json:"value"`
	Weight        float64     `json:"weight"`
	Required      bool        `json:"required"`
	CaseSensitive bool        `json:"case_sensitive"`
}

// CorrelationAction defines actions to take when correlation is found
type CorrelationAction struct {
	ActionType    string                 `json:"action_type"` // "alert", "escalate", "block", "log"
	Parameters    map[string]interface{} `json:"parameters"`
	Threshold     float64                `json:"threshold"`
	IsEnabled     bool                   `json:"is_enabled"`
	Delay         time.Duration          `json:"delay"`
	MaxExecutions int                    `json:"max_executions"`
}

// CorrelationCondition defines additional conditions for correlation
type CorrelationCondition struct {
	Type       string        `json:"type"` // "count", "rate", "sequence", "pattern"
	Operator   string        `json:"operator"`
	Value      interface{}   `json:"value"`
	TimeWindow time.Duration `json:"time_window"`
	IsRequired bool          `json:"is_required"`
}

// CorrelationSession represents an active correlation session
type CorrelationSession struct {
	SessionID       string                 `json:"session_id"`
	RuleID          string                 `json:"rule_id"`
	TenantID        string                 `json:"tenant_id"`
	StartTime       time.Time              `json:"start_time"`
	LastActivity    time.Time              `json:"last_activity"`
	Events          []*models.ActivityLog  `json:"events"`
	CorrelationData map[string]interface{} `json:"correlation_data"`
	Score           float64                `json:"score"`
	Status          string                 `json:"status"` // "active", "completed", "expired"
	Triggers        []CorrelationTrigger   `json:"triggers"`
	Pattern         *DetectedPattern       `json:"pattern,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// CorrelationTrigger represents a trigger in a correlation session
type CorrelationTrigger struct {
	EventID     string                 `json:"event_id"`
	TriggerType string                 `json:"trigger_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CorrelationResult represents the result of event correlation
type CorrelationResult struct {
	CorrelationID    string                 `json:"correlation_id"`
	SessionID        string                 `json:"session_id"`
	RuleID           string                 `json:"rule_id"`
	RuleName         string                 `json:"rule_name"`
	TenantID         string                 `json:"tenant_id"`
	EventCount       int                    `json:"event_count"`
	CorrelatedEvents []*models.ActivityLog  `json:"correlated_events"`
	Score            float64                `json:"score"`
	Confidence       float64                `json:"confidence"`
	Pattern          *DetectedPattern       `json:"pattern,omitempty"`
	Timeline         []TimelineEvent        `json:"timeline"`
	Summary          string                 `json:"summary"`
	Severity         string                 `json:"severity"`
	Categories       []string               `json:"categories"`
	Tags             []string               `json:"tags"`
	StartTime        time.Time              `json:"start_time"`
	EndTime          time.Time              `json:"end_time"`
	Duration         time.Duration          `json:"duration"`
	CreatedAt        time.Time              `json:"created_at"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// TimelineEvent represents an event in the correlation timeline
type TimelineEvent struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Importance  string                 `json:"importance"` // "low", "medium", "high", "critical"
	Metadata    map[string]interface{} `json:"metadata"`
}

// PatternDetector detects patterns in correlated events
type PatternDetector struct {
	patterns map[string]*EventPattern
	mutex    sync.RWMutex
}

// EventPattern represents a detected event pattern
type EventPattern struct {
	PatternID   string                 `json:"pattern_id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "sequence", "frequency", "anomaly", "attack"
	Events      []string               `json:"events"`
	Confidence  float64                `json:"confidence"`
	Frequency   int                    `json:"frequency"`
	LastSeen    time.Time              `json:"last_seen"`
	Description string                 `json:"description"`
	Indicators  []string               `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DetectedPattern represents a pattern detected in events
type DetectedPattern struct {
	PatternID   string                 `json:"pattern_id"`
	PatternType string                 `json:"pattern_type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Severity    string                 `json:"severity"`
	EventCount  int                    `json:"event_count"`
	TimeSpan    time.Duration          `json:"time_span"`
	Indicators  []PatternIndicator     `json:"indicators"`
	Mitigation  []string               `json:"mitigation"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PatternIndicator represents an indicator within a pattern
type PatternIndicator struct {
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Confidence  float64     `json:"confidence"`
	Description string      `json:"description"`
	Source      string      `json:"source"`
}

// CorrelationRuleEngine processes correlation rules
type CorrelationRuleEngine struct {
	rules map[string]*CorrelationRule
	mutex sync.RWMutex
}

// NewAuditCorrelationService creates a new audit correlation service
func NewAuditCorrelationService() *AuditCorrelationService {
	service := &AuditCorrelationService{
		correlationRules:  make(map[string]*CorrelationRule),
		correlationCache:  make(map[string]*CorrelationSession),
		cacheMutex:        sync.RWMutex{},
		maxCacheSize:      facades.Config().GetInt("audit.correlation.max_cache_size", 1000),
		sessionTimeout:    facades.Config().GetDuration("audit.correlation.session_timeout", 30*time.Minute),
		correlationWindow: facades.Config().GetDuration("audit.correlation.window", 5*time.Minute),
		patternDetector:   NewPatternDetector(),
		ruleEngine:        NewCorrelationRuleEngine(),
	}

	// Load default correlation rules
	service.loadDefaultRules()

	// Start cleanup goroutine
	go service.startCleanupRoutine()

	return service
}

// CorrelateEvent correlates a new event with existing events
func (acs *AuditCorrelationService) CorrelateEvent(event *models.ActivityLog) ([]*CorrelationResult, error) {
	var results []*CorrelationResult

	// Check against all active correlation rules
	for _, rule := range acs.correlationRules {
		if !rule.IsActive {
			continue
		}

		// Check if event matches rule triggers
		if acs.matchesRule(event, rule) {
			// Find or create correlation session
			session := acs.findOrCreateSession(event, rule)

			// Add event to session
			session.Events = append(session.Events, event)
			session.LastActivity = time.Now()

			// Update correlation data
			acs.updateCorrelationData(session, event)

			// Calculate correlation score
			session.Score = acs.calculateCorrelationScore(session, rule)

			// Check if correlation threshold is met
			if acs.shouldCreateCorrelation(session, rule) {
				result := acs.createCorrelationResult(session, rule)
				results = append(results, result)

				// Execute correlation actions
				acs.executeCorrelationActions(session, rule, result)

				// Mark session as completed
				session.Status = "completed"
			}

			// Update session in cache
			acs.cacheMutex.Lock()
			acs.correlationCache[session.SessionID] = session
			acs.cacheMutex.Unlock()
		}
	}

	// Detect patterns in the event
	if patterns := acs.patternDetector.DetectPatterns([]*models.ActivityLog{event}); len(patterns) > 0 {
		for _, pattern := range patterns {
			// Create correlation result for detected pattern
			result := &CorrelationResult{
				CorrelationID:    fmt.Sprintf("pattern_%s_%d", pattern.PatternID, time.Now().UnixNano()),
				TenantID:         event.TenantID,
				EventCount:       1,
				CorrelatedEvents: []*models.ActivityLog{event},
				Score:            pattern.Confidence * 100,
				Confidence:       pattern.Confidence,
				Pattern:          pattern,
				Summary:          fmt.Sprintf("Pattern detected: %s", pattern.Name),
				Severity:         pattern.Severity,
				Categories:       []string{"pattern_detection"},
				Tags:             []string{"automated", "pattern"},
				StartTime:        event.EventTimestamp,
				EndTime:          event.EventTimestamp,
				Duration:         0,
				CreatedAt:        time.Now(),
				Metadata: map[string]interface{}{
					"pattern_type":     pattern.PatternType,
					"detection_method": "real_time",
				},
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// AddCorrelationRule adds a new correlation rule
func (acs *AuditCorrelationService) AddCorrelationRule(rule *CorrelationRule) error {
	if rule.RuleID == "" {
		rule.RuleID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
	}

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	acs.correlationRules[rule.RuleID] = rule

	facades.Log().Info("Correlation rule added", map[string]interface{}{
		"rule_id":   rule.RuleID,
		"rule_name": rule.Name,
		"priority":  rule.Priority,
	})

	return nil
}

// UpdateCorrelationRule updates an existing correlation rule
func (acs *AuditCorrelationService) UpdateCorrelationRule(ruleID string, rule *CorrelationRule) error {
	existingRule, exists := acs.correlationRules[ruleID]
	if !exists {
		return fmt.Errorf("correlation rule not found: %s", ruleID)
	}

	rule.RuleID = ruleID
	rule.CreatedAt = existingRule.CreatedAt
	rule.UpdatedAt = time.Now()

	acs.correlationRules[ruleID] = rule

	facades.Log().Info("Correlation rule updated", map[string]interface{}{
		"rule_id":   ruleID,
		"rule_name": rule.Name,
	})

	return nil
}

// RemoveCorrelationRule removes a correlation rule
func (acs *AuditCorrelationService) RemoveCorrelationRule(ruleID string) error {
	_, exists := acs.correlationRules[ruleID]
	if !exists {
		return fmt.Errorf("correlation rule not found: %s", ruleID)
	}

	delete(acs.correlationRules, ruleID)

	facades.Log().Info("Correlation rule removed", map[string]interface{}{
		"rule_id": ruleID,
	})

	return nil
}

// GetCorrelationRule returns a correlation rule by ID
func (acs *AuditCorrelationService) GetCorrelationRule(ruleID string) (*CorrelationRule, error) {
	rule, exists := acs.correlationRules[ruleID]
	if !exists {
		return nil, fmt.Errorf("correlation rule not found: %s", ruleID)
	}

	return rule, nil
}

// GetAllCorrelationRules returns all correlation rules
func (acs *AuditCorrelationService) GetAllCorrelationRules() []*CorrelationRule {
	var rules []*CorrelationRule
	for _, rule := range acs.correlationRules {
		rules = append(rules, rule)
	}

	// Sort by priority
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	return rules
}

// GetActiveCorrelationSessions returns all active correlation sessions
func (acs *AuditCorrelationService) GetActiveCorrelationSessions() []*CorrelationSession {
	acs.cacheMutex.RLock()
	defer acs.cacheMutex.RUnlock()

	var sessions []*CorrelationSession
	for _, session := range acs.correlationCache {
		if session.Status == "active" {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// AnalyzeCorrelationHistory analyzes historical correlations
func (acs *AuditCorrelationService) AnalyzeCorrelationHistory(tenantID string, timeRange TimeRange) (*CorrelationAnalysisReport, error) {
	reportID := fmt.Sprintf("correlation_analysis_%d", time.Now().UnixNano())

	// Get all correlation results for the time range
	var correlationResults []CorrelationResult
	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("correlation_id, session_id, rule_id, rule_name, tenant_id, event_count, score, confidence, "+
			"severity, start_time, end_time, duration, created_at").
		Where("tenant_id = ? AND created_at >= ? AND created_at <= ?", tenantID, timeRange.StartTime, timeRange.EndTime).
		Where("correlation_id IS NOT NULL AND correlation_id != ''").
		Scan(&correlationResults)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch correlation results: %w", err)
	}

	// Calculate summary statistics
	totalCorrelations := len(correlationResults)
	highRiskEvents := 0
	totalScore := 0.0
	severityCount := make(map[string]int)
	ruleStats := make(map[string]*RuleSummary)
	patternFrequency := make(map[string]int)

	for _, result := range correlationResults {
		totalScore += result.Score

		// Count high-risk events (score > 0.7 or critical/high severity)
		if result.Score > 0.7 || result.Severity == "critical" || result.Severity == "high" {
			highRiskEvents++
		}

		severityCount[result.Severity]++

		// Track rule statistics
		if _, exists := ruleStats[result.RuleID]; !exists {
			ruleStats[result.RuleID] = &RuleSummary{
				RuleID:      result.RuleID,
				Name:        result.RuleName,
				Triggers:    0,
				SuccessRate: 0.0,
				LastTrigger: result.CreatedAt,
			}
		}

		rule := ruleStats[result.RuleID]
		rule.Triggers++
		if result.CreatedAt.After(rule.LastTrigger) {
			rule.LastTrigger = result.CreatedAt
		}

		// Track pattern frequency (using rule name as pattern identifier)
		patternFrequency[result.RuleName]++
	}

	// Calculate average score
	averageScore := 0.0
	if totalCorrelations > 0 {
		averageScore = totalScore / float64(totalCorrelations)
	}

	// Calculate success rates for rules
	for _, rule := range ruleStats {
		// Success rate based on high-confidence correlations
		highConfidenceCount := 0
		for _, result := range correlationResults {
			if result.RuleID == rule.RuleID && result.Confidence > 0.8 {
				highConfidenceCount++
			}
		}
		if rule.Triggers > 0 {
			rule.SuccessRate = float64(highConfidenceCount) / float64(rule.Triggers) * 100
		}
	}

	// Create top patterns list
	topPatterns := make([]PatternSummary, 0)
	for patternName, frequency := range patternFrequency {
		// Find the most recent occurrence and calculate average confidence
		var lastSeen time.Time
		totalConfidence := 0.0
		count := 0

		for _, result := range correlationResults {
			if result.RuleName == patternName {
				if result.CreatedAt.After(lastSeen) {
					lastSeen = result.CreatedAt
				}
				totalConfidence += result.Confidence
				count++
			}
		}

		avgConfidence := 0.0
		if count > 0 {
			avgConfidence = totalConfidence / float64(count)
		}

		topPatterns = append(topPatterns, PatternSummary{
			PatternID:  fmt.Sprintf("pattern_%s", strings.ReplaceAll(strings.ToLower(patternName), " ", "_")),
			Name:       patternName,
			Frequency:  frequency,
			Confidence: avgConfidence,
			LastSeen:   lastSeen,
		})
	}

	// Sort patterns by frequency
	sort.Slice(topPatterns, func(i, j int) bool {
		return topPatterns[i].Frequency > topPatterns[j].Frequency
	})

	// Limit to top 10 patterns
	if len(topPatterns) > 10 {
		topPatterns = topPatterns[:10]
	}

	// Create top rules list
	topRules := make([]RuleSummary, 0, len(ruleStats))
	for _, rule := range ruleStats {
		topRules = append(topRules, *rule)
	}

	// Sort rules by trigger count
	sort.Slice(topRules, func(i, j int) bool {
		return topRules[i].Triggers > topRules[j].Triggers
	})

	// Limit to top 10 rules
	if len(topRules) > 10 {
		topRules = topRules[:10]
	}

	// Generate trend data (daily correlation counts)
	trends := make([]TrendData, 0)
	dailyCorrelations := make(map[string]int)

	for _, result := range correlationResults {
		day := result.CreatedAt.Format("2006-01-02")
		dailyCorrelations[day]++
	}

	// Create trend data points
	current := timeRange.StartTime
	for current.Before(timeRange.EndTime) || current.Equal(timeRange.EndTime) {
		day := current.Format("2006-01-02")
		count := dailyCorrelations[day]

		trends = append(trends, TrendData{
			Timestamp: current,
			Value:     float64(count),
			Metric:    "daily_correlations",
		})

		current = current.AddDate(0, 0, 1)
	}

	// Generate intelligent recommendations
	recommendations := generateCorrelationRecommendations(totalCorrelations, highRiskEvents, averageScore, severityCount, len(ruleStats))

	// Create summary
	summary := CorrelationSummary{
		TotalCorrelations: totalCorrelations,
		UniquePatterns:    len(patternFrequency),
		HighRiskEvents:    highRiskEvents,
		AverageScore:      averageScore,
	}

	report := &CorrelationAnalysisReport{
		ReportID:        reportID,
		TenantID:        tenantID,
		TimeRange:       timeRange,
		GeneratedAt:     time.Now(),
		Summary:         summary,
		TopPatterns:     topPatterns,
		TopRules:        topRules,
		Trends:          trends,
		Recommendations: recommendations,
		Metadata: map[string]interface{}{
			"analysis_version":    "1.0",
			"severity_breakdown":  severityCount,
			"total_rules_active":  len(ruleStats),
			"high_risk_threshold": 0.7,
		},
	}

	return report, nil
}

// generateCorrelationRecommendations creates intelligent recommendations based on analysis
func generateCorrelationRecommendations(totalCorrelations, highRiskEvents int, averageScore float64, severityCount map[string]int, activeRules int) []string {
	recommendations := make([]string, 0)

	// Base recommendations
	if totalCorrelations == 0 {
		recommendations = append(recommendations, "No correlations found in the specified time range. Consider reviewing correlation rules and their trigger conditions.")
		recommendations = append(recommendations, "Ensure audit logging is properly configured and events are being generated.")
		return recommendations
	}

	// High-risk event recommendations
	riskRatio := float64(highRiskEvents) / float64(totalCorrelations)
	if riskRatio > 0.3 {
		recommendations = append(recommendations, "High number of high-risk correlations detected. Immediate investigation recommended.")
		recommendations = append(recommendations, "Consider implementing automated response actions for critical security patterns.")
	} else if riskRatio < 0.05 {
		recommendations = append(recommendations, "Very few high-risk correlations detected. Review rule sensitivity and thresholds.")
	}

	// Score-based recommendations
	if averageScore < 0.3 {
		recommendations = append(recommendations, "Low average correlation scores suggest rules may need refinement or additional context.")
		recommendations = append(recommendations, "Consider adding more correlation criteria or adjusting rule weights.")
	} else if averageScore > 0.8 {
		recommendations = append(recommendations, "High correlation scores indicate effective rule configuration.")
		recommendations = append(recommendations, "Consider expanding successful rule patterns to detect similar threats.")
	}

	// Rule quantity recommendations
	if activeRules < 5 {
		recommendations = append(recommendations, "Limited number of correlation rules active. Consider adding more rules for comprehensive threat detection.")
		recommendations = append(recommendations, "Review industry best practices for security event correlation patterns.")
	} else if activeRules > 50 {
		recommendations = append(recommendations, "Large number of correlation rules may lead to alert fatigue. Consider consolidating similar rules.")
	}

	// Severity-based recommendations
	if criticalCount, exists := severityCount["critical"]; exists && criticalCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d critical correlations require immediate attention and response.", criticalCount))
	}

	if highCount, exists := severityCount["high"]; exists && highCount > totalCorrelations/2 {
		recommendations = append(recommendations, "High proportion of high-severity correlations may indicate ongoing security issues.")
	}

	// Pattern diversity recommendations
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Correlation analysis shows normal security posture. Continue monitoring for emerging patterns.")
		recommendations = append(recommendations, "Consider periodic review of correlation rules to ensure they remain effective against evolving threats.")
	}

	return recommendations
}

// Private methods

func (acs *AuditCorrelationService) loadDefaultRules() {
	// Brute force attack detection
	bruteForceRule := &CorrelationRule{
		RuleID:        "brute_force_detection",
		Name:          "Brute Force Attack Detection",
		Description:   "Detects multiple failed login attempts followed by successful login",
		Priority:      90,
		IsActive:      true,
		TriggerEvents: []string{"auth.login.failed", "auth.login.success"},
		TimeWindow:    15 * time.Minute,
		MaxEvents:     10,
		MatchCriteria: []MatchCriterion{
			{
				Field:    "subject_id",
				Operator: "equals",
				Weight:   1.0,
				Required: true,
			},
			{
				Field:    "ip_address",
				Operator: "equals",
				Weight:   0.8,
				Required: false,
			},
		},
		Conditions: []CorrelationCondition{
			{
				Type:       "count",
				Operator:   ">=",
				Value:      5,
				TimeWindow: 15 * time.Minute,
				IsRequired: true,
			},
		},
		Actions: []CorrelationAction{
			{
				ActionType: "alert",
				Parameters: map[string]interface{}{
					"severity": "high",
					"message":  "Potential brute force attack detected",
				},
				Threshold: 80.0,
				IsEnabled: true,
			},
		},
	}

	// Privilege escalation detection
	privEscRule := &CorrelationRule{
		RuleID:        "privilege_escalation",
		Name:          "Privilege Escalation Detection",
		Description:   "Detects privilege escalation attempts",
		Priority:      95,
		IsActive:      true,
		TriggerEvents: []string{"permission.granted", "role.assigned"},
		TimeWindow:    5 * time.Minute,
		MaxEvents:     5,
		MatchCriteria: []MatchCriterion{
			{
				Field:    "subject_id",
				Operator: "equals",
				Weight:   1.0,
				Required: true,
			},
		},
		Actions: []CorrelationAction{
			{
				ActionType: "alert",
				Parameters: map[string]interface{}{
					"severity": "critical",
					"message":  "Privilege escalation detected",
				},
				Threshold: 90.0,
				IsEnabled: true,
			},
		},
	}

	// Data exfiltration detection
	dataExfilRule := &CorrelationRule{
		RuleID:        "data_exfiltration",
		Name:          "Data Exfiltration Detection",
		Description:   "Detects potential data exfiltration patterns",
		Priority:      85,
		IsActive:      true,
		TriggerEvents: []string{"data.accessed", "data.exported"},
		TimeWindow:    30 * time.Minute,
		MaxEvents:     20,
		MatchCriteria: []MatchCriterion{
			{
				Field:    "subject_id",
				Operator: "equals",
				Weight:   1.0,
				Required: true,
			},
		},
		Conditions: []CorrelationCondition{
			{
				Type:       "count",
				Operator:   ">=",
				Value:      10,
				TimeWindow: 30 * time.Minute,
				IsRequired: true,
			},
		},
		Actions: []CorrelationAction{
			{
				ActionType: "alert",
				Parameters: map[string]interface{}{
					"severity": "high",
					"message":  "Potential data exfiltration detected",
				},
				Threshold: 75.0,
				IsEnabled: true,
			},
		},
	}

	acs.correlationRules[bruteForceRule.RuleID] = bruteForceRule
	acs.correlationRules[privEscRule.RuleID] = privEscRule
	acs.correlationRules[dataExfilRule.RuleID] = dataExfilRule

	facades.Log().Info("Default correlation rules loaded", map[string]interface{}{
		"rules_count": len(acs.correlationRules),
	})
}

func (acs *AuditCorrelationService) matchesRule(event *models.ActivityLog, rule *CorrelationRule) bool {
	// Check if event type matches trigger events
	eventMatches := false
	for _, triggerEvent := range rule.TriggerEvents {
		if event.LogName == triggerEvent {
			eventMatches = true
			break
		}
	}

	if !eventMatches {
		return false
	}

	// Check match criteria
	for _, criterion := range rule.MatchCriteria {
		if criterion.Required && !acs.matchesCriterion(event, criterion) {
			return false
		}
	}

	return true
}

func (acs *AuditCorrelationService) matchesCriterion(event *models.ActivityLog, criterion MatchCriterion) bool {
	var fieldValue string

	// Get field value from event
	switch criterion.Field {
	case "subject_id":
		fieldValue = event.SubjectID
	case "causer_id":
		fieldValue = event.CauserID
	case "ip_address":
		fieldValue = event.IPAddress
	case "session_id":
		fieldValue = event.SessionID
	case "tenant_id":
		fieldValue = event.TenantID
	default:
		return false
	}

	// Apply operator
	switch criterion.Operator {
	case "equals":
		if criterion.CaseSensitive {
			return fieldValue == fmt.Sprintf("%v", criterion.Value)
		}
		return strings.EqualFold(fieldValue, fmt.Sprintf("%v", criterion.Value))
	case "contains":
		if criterion.CaseSensitive {
			return strings.Contains(fieldValue, fmt.Sprintf("%v", criterion.Value))
		}
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(fmt.Sprintf("%v", criterion.Value)))
	default:
		return false
	}
}

func (acs *AuditCorrelationService) findOrCreateSession(event *models.ActivityLog, rule *CorrelationRule) *CorrelationSession {
	acs.cacheMutex.Lock()
	defer acs.cacheMutex.Unlock()

	// Look for existing session
	sessionKey := fmt.Sprintf("%s_%s_%s", rule.RuleID, event.TenantID, acs.getSessionKey(event, rule))

	if session, exists := acs.correlationCache[sessionKey]; exists {
		// Check if session is still within time window
		if time.Since(session.StartTime) <= rule.TimeWindow {
			return session
		}
		// Session expired, remove it
		delete(acs.correlationCache, sessionKey)
	}

	// Create new session
	session := &CorrelationSession{
		SessionID:       fmt.Sprintf("session_%d", time.Now().UnixNano()),
		RuleID:          rule.RuleID,
		TenantID:        event.TenantID,
		StartTime:       time.Now(),
		LastActivity:    time.Now(),
		Events:          []*models.ActivityLog{},
		CorrelationData: make(map[string]interface{}),
		Score:           0.0,
		Status:          "active",
		Triggers:        []CorrelationTrigger{},
		Metadata:        make(map[string]interface{}),
	}

	acs.correlationCache[sessionKey] = session
	return session
}

func (acs *AuditCorrelationService) getSessionKey(event *models.ActivityLog, rule *CorrelationRule) string {
	// Create session key based on match criteria
	var keyParts []string
	for _, criterion := range rule.MatchCriteria {
		if criterion.Required {
			switch criterion.Field {
			case "subject_id":
				keyParts = append(keyParts, event.SubjectID)
			case "ip_address":
				keyParts = append(keyParts, event.IPAddress)
			case "session_id":
				keyParts = append(keyParts, event.SessionID)
			}
		}
	}
	return strings.Join(keyParts, "_")
}

func (acs *AuditCorrelationService) updateCorrelationData(session *CorrelationSession, event *models.ActivityLog) {
	// Update correlation statistics
	session.CorrelationData["event_count"] = len(session.Events)
	session.CorrelationData["last_event_type"] = event.LogName
	session.CorrelationData["last_event_time"] = event.EventTimestamp

	// Track unique values
	if uniqueIPs, exists := session.CorrelationData["unique_ips"]; exists {
		ipSet := uniqueIPs.(map[string]bool)
		ipSet[event.IPAddress] = true
		session.CorrelationData["unique_ip_count"] = len(ipSet)
	} else {
		ipSet := make(map[string]bool)
		ipSet[event.IPAddress] = true
		session.CorrelationData["unique_ips"] = ipSet
		session.CorrelationData["unique_ip_count"] = 1
	}

	// Track event types
	if eventTypes, exists := session.CorrelationData["event_types"]; exists {
		typeMap := eventTypes.(map[string]int)
		typeMap[event.LogName]++
	} else {
		typeMap := make(map[string]int)
		typeMap[event.LogName] = 1
		session.CorrelationData["event_types"] = typeMap
	}
}

func (acs *AuditCorrelationService) calculateCorrelationScore(session *CorrelationSession, rule *CorrelationRule) float64 {
	score := 0.0

	// Base score from event count
	eventCount := len(session.Events)
	if eventCount > 0 {
		score += float64(eventCount) * 10.0
	}

	// Time factor (events closer together get higher score)
	if eventCount > 1 {
		timeSpan := session.LastActivity.Sub(session.StartTime)
		if timeSpan < rule.TimeWindow/4 {
			score += 20.0 // Events clustered in short time
		} else if timeSpan < rule.TimeWindow/2 {
			score += 10.0
		}
	}

	// Pattern matching bonus
	if session.Pattern != nil {
		score += session.Pattern.Confidence * 30.0
	}

	// Risk score factor
	totalRiskScore := 0
	for _, event := range session.Events {
		totalRiskScore += event.RiskScore
	}
	if eventCount > 0 {
		avgRiskScore := float64(totalRiskScore) / float64(eventCount)
		score += avgRiskScore * 0.5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (acs *AuditCorrelationService) shouldCreateCorrelation(session *CorrelationSession, rule *CorrelationRule) bool {
	// Check conditions
	for _, condition := range rule.Conditions {
		if condition.IsRequired && !acs.evaluateCondition(session, condition) {
			return false
		}
	}

	// Check minimum score threshold
	return session.Score >= 50.0 // Default threshold
}

func (acs *AuditCorrelationService) evaluateCondition(session *CorrelationSession, condition CorrelationCondition) bool {
	switch condition.Type {
	case "count":
		eventCount := len(session.Events)
		switch condition.Operator {
		case ">=":
			if count, ok := condition.Value.(int); ok {
				return eventCount >= count
			}
		case ">":
			if count, ok := condition.Value.(int); ok {
				return eventCount > count
			}
		case "=":
			if count, ok := condition.Value.(int); ok {
				return eventCount == count
			}
		}
	case "rate":
		// Events per time unit
		if len(session.Events) < 2 {
			return false
		}
		timeSpan := session.LastActivity.Sub(session.StartTime)
		rate := float64(len(session.Events)) / timeSpan.Minutes()

		switch condition.Operator {
		case ">=":
			if threshold, ok := condition.Value.(float64); ok {
				return rate >= threshold
			}
		}
	}

	return false
}

func (acs *AuditCorrelationService) createCorrelationResult(session *CorrelationSession, rule *CorrelationRule) *CorrelationResult {
	// Create timeline
	var timeline []TimelineEvent
	for _, event := range session.Events {
		timeline = append(timeline, TimelineEvent{
			EventID:     event.ID,
			Timestamp:   event.EventTimestamp,
			EventType:   event.LogName,
			Description: event.Description,
			Importance:  acs.determineEventImportance(event),
			Metadata: map[string]interface{}{
				"risk_score": event.RiskScore,
				"category":   event.Category,
				"severity":   event.Severity,
			},
		})
	}

	// Sort timeline by timestamp
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})

	// Determine severity
	severity := acs.determineCorrelationSeverity(session, rule)

	// Create categories
	categories := []string{rule.RuleID}
	if session.Pattern != nil {
		categories = append(categories, session.Pattern.PatternType)
	}

	result := &CorrelationResult{
		CorrelationID:    fmt.Sprintf("corr_%s_%d", session.SessionID, time.Now().UnixNano()),
		SessionID:        session.SessionID,
		RuleID:           rule.RuleID,
		RuleName:         rule.Name,
		TenantID:         session.TenantID,
		EventCount:       len(session.Events),
		CorrelatedEvents: session.Events,
		Score:            session.Score,
		Confidence:       session.Score / 100.0,
		Pattern:          session.Pattern,
		Timeline:         timeline,
		Summary:          acs.createCorrelationSummary(session, rule),
		Severity:         severity,
		Categories:       categories,
		Tags:             []string{"correlation", rule.RuleID},
		StartTime:        session.StartTime,
		EndTime:          session.LastActivity,
		Duration:         session.LastActivity.Sub(session.StartTime),
		CreatedAt:        time.Now(),
		Metadata: map[string]interface{}{
			"rule_priority": rule.Priority,
			"session_data":  session.CorrelationData,
			"trigger_count": len(session.Triggers),
		},
	}

	return result
}

func (acs *AuditCorrelationService) executeCorrelationActions(session *CorrelationSession, rule *CorrelationRule, result *CorrelationResult) {
	for _, action := range rule.Actions {
		if !action.IsEnabled {
			continue
		}

		if result.Score < action.Threshold {
			continue
		}

		switch action.ActionType {
		case "alert":
			acs.sendCorrelationAlert(result, action)
		case "log":
			acs.logCorrelationResult(result, action)
		case "escalate":
			acs.escalateCorrelation(result, action)
		}
	}
}

func (acs *AuditCorrelationService) sendCorrelationAlert(result *CorrelationResult, action CorrelationAction) {
	alertData := map[string]interface{}{
		"correlation_id": result.CorrelationID,
		"rule_name":      result.RuleName,
		"severity":       result.Severity,
		"score":          result.Score,
		"event_count":    result.EventCount,
		"summary":        result.Summary,
		"action_params":  action.Parameters,
	}

	facades.Log().Warning("CORRELATION ALERT", alertData)
}

func (acs *AuditCorrelationService) logCorrelationResult(result *CorrelationResult, action CorrelationAction) {
	logData := map[string]interface{}{
		"correlation_id": result.CorrelationID,
		"rule_name":      result.RuleName,
		"event_count":    result.EventCount,
		"duration":       result.Duration.String(),
		"score":          result.Score,
	}

	facades.Log().Info("Correlation detected", logData)
}

func (acs *AuditCorrelationService) escalateCorrelation(result *CorrelationResult, action CorrelationAction) {
	// This would implement escalation logic
	facades.Log().Error("CORRELATION ESCALATION", map[string]interface{}{
		"correlation_id":               result.CorrelationID,
		"rule_name":                    result.RuleName,
		"severity":                     result.Severity,
		"requires_immediate_attention": true,
	})
}

func (acs *AuditCorrelationService) determineEventImportance(event *models.ActivityLog) string {
	if event.RiskScore >= 80 {
		return "critical"
	} else if event.RiskScore >= 60 {
		return "high"
	} else if event.RiskScore >= 40 {
		return "medium"
	}
	return "low"
}

func (acs *AuditCorrelationService) determineCorrelationSeverity(session *CorrelationSession, rule *CorrelationRule) string {
	if session.Score >= 90 {
		return "critical"
	} else if session.Score >= 70 {
		return "high"
	} else if session.Score >= 50 {
		return "medium"
	}
	return "low"
}

func (acs *AuditCorrelationService) createCorrelationSummary(session *CorrelationSession, rule *CorrelationRule) string {
	eventCount := len(session.Events)
	duration := session.LastActivity.Sub(session.StartTime)

	return fmt.Sprintf("%s: %d events correlated over %s (Score: %.1f)",
		rule.Name, eventCount, duration.String(), session.Score)
}

func (acs *AuditCorrelationService) startCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		acs.cleanupExpiredSessions()
		acs.cleanupCache()
	}
}

func (acs *AuditCorrelationService) cleanupExpiredSessions() {
	acs.cacheMutex.Lock()
	defer acs.cacheMutex.Unlock()

	now := time.Now()
	for sessionKey, session := range acs.correlationCache {
		if now.Sub(session.LastActivity) > acs.sessionTimeout {
			delete(acs.correlationCache, sessionKey)
		}
	}
}

func (acs *AuditCorrelationService) cleanupCache() {
	acs.cacheMutex.Lock()
	defer acs.cacheMutex.Unlock()

	if len(acs.correlationCache) > acs.maxCacheSize {
		// Remove oldest sessions
		var sessions []*CorrelationSession
		for _, session := range acs.correlationCache {
			sessions = append(sessions, session)
		}

		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].LastActivity.Before(sessions[j].LastActivity)
		})

		// Remove oldest 10% of sessions
		removeCount := len(sessions) / 10
		for i := 0; i < removeCount; i++ {
			sessionKey := fmt.Sprintf("%s_%s", sessions[i].RuleID, sessions[i].TenantID)
			delete(acs.correlationCache, sessionKey)
		}
	}
}

// Supporting services and types

// NewPatternDetector creates a new pattern detector
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		patterns: make(map[string]*EventPattern),
		mutex:    sync.RWMutex{},
	}
}

// DetectPatterns detects patterns in a set of events
func (pd *PatternDetector) DetectPatterns(events []*models.ActivityLog) []*DetectedPattern {
	var patterns []*DetectedPattern

	// Simple pattern detection - multiple failed logins
	failedLogins := 0
	for _, event := range events {
		if event.LogName == "auth.login.failed" {
			failedLogins++
		}
	}

	if failedLogins >= 3 {
		pattern := &DetectedPattern{
			PatternID:   "multiple_failed_logins",
			PatternType: "authentication_attack",
			Name:        "Multiple Failed Login Attempts",
			Description: "Multiple failed login attempts detected",
			Confidence:  0.8,
			Severity:    "medium",
			EventCount:  failedLogins,
			Indicators: []PatternIndicator{
				{
					Type:        "event_count",
					Value:       failedLogins,
					Confidence:  0.9,
					Description: "Number of failed login attempts",
					Source:      "pattern_detector",
				},
			},
			Mitigation: []string{
				"Review user account for compromise",
				"Consider implementing account lockout",
				"Monitor for successful login attempts",
			},
		}
		patterns = append(patterns, pattern)
	}

	return patterns
}

// NewCorrelationRuleEngine creates a new correlation rule engine
func NewCorrelationRuleEngine() *CorrelationRuleEngine {
	return &CorrelationRuleEngine{
		rules: make(map[string]*CorrelationRule),
		mutex: sync.RWMutex{},
	}
}

// Supporting types for analysis reports
type CorrelationAnalysisReport struct {
	ReportID        string                 `json:"report_id"`
	TenantID        string                 `json:"tenant_id"`
	TimeRange       TimeRange              `json:"time_range"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Summary         CorrelationSummary     `json:"summary"`
	TopPatterns     []PatternSummary       `json:"top_patterns"`
	TopRules        []RuleSummary          `json:"top_rules"`
	Trends          []TrendData            `json:"trends"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type CorrelationSummary struct {
	TotalCorrelations int     `json:"total_correlations"`
	UniquePatterns    int     `json:"unique_patterns"`
	HighRiskEvents    int     `json:"high_risk_events"`
	AverageScore      float64 `json:"average_score"`
}

type PatternSummary struct {
	PatternID  string    `json:"pattern_id"`
	Name       string    `json:"name"`
	Frequency  int       `json:"frequency"`
	Confidence float64   `json:"confidence"`
	LastSeen   time.Time `json:"last_seen"`
}

type RuleSummary struct {
	RuleID      string    `json:"rule_id"`
	Name        string    `json:"name"`
	Triggers    int       `json:"triggers"`
	SuccessRate float64   `json:"success_rate"`
	LastTrigger time.Time `json:"last_trigger"`
}

type TrendData struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Metric    string    `json:"metric"`
}
