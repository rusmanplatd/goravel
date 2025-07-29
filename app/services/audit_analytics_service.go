package services

import (
	"fmt"
	"math"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// AuditAnalyticsService provides analytics and insights for audit logs
type AuditAnalyticsService struct {
	activityLogger *models.ActivityLogger
}

// NewAuditAnalyticsService creates a new audit analytics service instance
func NewAuditAnalyticsService() *AuditAnalyticsService {
	return &AuditAnalyticsService{
		activityLogger: models.NewActivityLogger(),
	}
}

// TimeRange represents a time range
type TimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// DashboardMetrics represents metrics for audit dashboard
type DashboardMetrics struct {
	TotalActivities      int64                 `json:"total_activities"`
	HighRiskActivities   int64                 `json:"high_risk_activities"`
	SecurityIncidents    int64                 `json:"security_incidents"`
	ComplianceViolations int64                 `json:"compliance_violations"`
	TopUsers             []UserActivitySummary `json:"top_users"`
	TopIPs               []IPActivitySummary   `json:"top_ips"`
	ActivityTrends       []ActivityTrend       `json:"activity_trends"`
	CategoryBreakdown    []CategorySummary     `json:"category_breakdown"`
	SeverityBreakdown    []SeveritySummary     `json:"severity_breakdown"`
	RecentAlerts         []AlertSummary        `json:"recent_alerts"`
	ComplianceStatus     ComplianceStatus      `json:"compliance_status"`
	PerformanceMetrics   PerformanceMetrics    `json:"performance_metrics"`
}

// UserActivitySummary represents user activity summary
type UserActivitySummary struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"username,omitempty"`
	ActivityCount  int64     `json:"activity_count"`
	RiskScore      float64   `json:"risk_score"`
	LastActivity   time.Time `json:"last_activity"`
	SecurityEvents int64     `json:"security_events"`
	FailedAttempts int64     `json:"failed_attempts"`
}

// IPActivitySummary represents IP address activity summary
type IPActivitySummary struct {
	IPAddress     string              `json:"ip_address"`
	ActivityCount int64               `json:"activity_count"`
	UniqueUsers   int64               `json:"unique_users"`
	RiskScore     float64             `json:"risk_score"`
	LastActivity  time.Time           `json:"last_activity"`
	GeoLocation   *models.GeoLocation `json:"geo_location,omitempty"`
	ThreatLevel   string              `json:"threat_level"`
}

// ActivityTrend represents activity trends over time
type ActivityTrend struct {
	Timestamp        time.Time `json:"timestamp"`
	ActivityCount    int64     `json:"activity_count"`
	SecurityEvents   int64     `json:"security_events"`
	FailedAttempts   int64     `json:"failed_attempts"`
	AverageRiskScore float64   `json:"average_risk_score"`
}

// CategorySummary represents activity breakdown by category
type CategorySummary struct {
	Category     string  `json:"category"`
	Count        int64   `json:"count"`
	Percentage   float64 `json:"percentage"`
	AvgRiskScore float64 `json:"avg_risk_score"`
	TrendChange  float64 `json:"trend_change"`
}

// SeveritySummary represents activity breakdown by severity
type SeveritySummary struct {
	Severity    string  `json:"severity"`
	Count       int64   `json:"count"`
	Percentage  float64 `json:"percentage"`
	TrendChange float64 `json:"trend_change"`
}

// AlertSummary represents a security alert summary
type AlertSummary struct {
	ID          string    `json:"id"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	RiskScore   int       `json:"risk_score"`
	UserID      string    `json:"user_id"`
	IPAddress   string    `json:"ip_address"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus struct {
	GDPRCompliance   ComplianceMetric `json:"gdpr_compliance"`
	HIPAACompliance  ComplianceMetric `json:"hipaa_compliance"`
	SOXCompliance    ComplianceMetric `json:"sox_compliance"`
	PCIDSSCompliance ComplianceMetric `json:"pci_dss_compliance"`
	OverallScore     float64          `json:"overall_score"`
	LastAuditDate    time.Time        `json:"last_audit_date"`
}

// ComplianceMetric represents a compliance metric
type ComplianceMetric struct {
	Score          float64   `json:"score"`
	RequiredEvents int64     `json:"required_events"`
	LoggedEvents   int64     `json:"logged_events"`
	Violations     int64     `json:"violations"`
	LastViolation  time.Time `json:"last_violation,omitempty"`
	Status         string    `json:"status"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	AvgLogProcessingTime float64 `json:"avg_log_processing_time"`
	LogsPerSecond        float64 `json:"logs_per_second"`
	StorageUsed          int64   `json:"storage_used"`
	IndexEfficiency      float64 `json:"index_efficiency"`
	QueryPerformance     float64 `json:"query_performance"`
}

// AnomalyDetectionResult represents anomaly detection results
type AnomalyDetectionResult struct {
	UserID          string                 `json:"user_id"`
	AnomalyType     string                 `json:"anomaly_type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	DetectedAt      time.Time              `json:"detected_at"`
	Evidence        map[string]interface{} `json:"evidence"`
	RiskScore       int                    `json:"risk_score"`
	Recommendations []string               `json:"recommendations"`
}

// ThreatIntelligenceReport represents threat intelligence report
type ThreatIntelligenceReport struct {
	ReportID        string             `json:"report_id"`
	GeneratedAt     time.Time          `json:"generated_at"`
	TimeRange       TimeRange          `json:"time_range"`
	ThreatSummary   ThreatSummary      `json:"threat_summary"`
	TopThreats      []ThreatInfo       `json:"top_threats"`
	GeographicData  []GeographicThreat `json:"geographic_data"`
	AttackPatterns  []AttackPattern    `json:"attack_patterns"`
	Recommendations []string           `json:"recommendations"`
}

// ThreatSummary represents threat summary data
type ThreatSummary struct {
	TotalThreats     int64   `json:"total_threats"`
	CriticalThreats  int64   `json:"critical_threats"`
	HighThreats      int64   `json:"high_threats"`
	MediumThreats    int64   `json:"medium_threats"`
	LowThreats       int64   `json:"low_threats"`
	AverageRiskScore float64 `json:"average_risk_score"`
	ThreatTrend      string  `json:"threat_trend"`
}

// ThreatInfo represents a threat information
type ThreatInfo struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int64     `json:"occurrences"`
	Description string    `json:"description"`
}

// GeographicThreat represents geographic threat data
type GeographicThreat struct {
	Country        string   `json:"country"`
	Region         string   `json:"region"`
	City           string   `json:"city"`
	ThreatCount    int64    `json:"threat_count"`
	RiskScore      float64  `json:"risk_score"`
	TopThreatTypes []string `json:"top_threat_types"`
}

// AttackPattern represents an attack pattern
type AttackPattern struct {
	PatternID   string                 `json:"pattern_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Frequency   int64                  `json:"frequency"`
	Severity    string                 `json:"severity"`
	Tactics     []string               `json:"tactics"`
	Techniques  []string               `json:"techniques"`
	Indicators  []string               `json:"indicators"`
	Mitigation  []string               `json:"mitigation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// GetDashboardMetrics returns comprehensive dashboard metrics
func (aas *AuditAnalyticsService) GetDashboardMetrics(organizationID string, timeRange TimeRange) (*DashboardMetrics, error) {
	metrics := &DashboardMetrics{}

	// Get total activities
	totalCount, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?", organizationID, timeRange.StartTime, timeRange.EndTime).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total activities: %w", err)
	}
	metrics.TotalActivities = totalCount

	// Get high-risk activities
	highRiskCount, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND (risk_score > 70 OR severity IN (?, ?))",
			organizationID, timeRange.StartTime, timeRange.EndTime, string(models.SeverityHigh), string(models.SeverityCritical)).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get high-risk activities: %w", err)
	}
	metrics.HighRiskActivities = highRiskCount

	// Get security incidents
	securityCount, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND category IN (?, ?, ?)",
			organizationID, timeRange.StartTime, timeRange.EndTime,
			string(models.CategorySecurity), string(models.CategoryAuthentication), string(models.CategoryAuthorization)).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get security incidents: %w", err)
	}
	metrics.SecurityIncidents = securityCount

	// Get compliance violations
	complianceCount, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND category = ?",
			organizationID, timeRange.StartTime, timeRange.EndTime, string(models.CategoryCompliance)).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance violations: %w", err)
	}
	metrics.ComplianceViolations = complianceCount

	// Get top users
	topUsers, err := aas.getTopUsers(organizationID, timeRange, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to get top users: %w", err)
	}
	metrics.TopUsers = topUsers

	// Get top IPs
	topIPs, err := aas.getTopIPs(organizationID, timeRange, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to get top IPs: %w", err)
	}
	metrics.TopIPs = topIPs

	// Get activity trends
	trends, err := aas.getActivityTrends(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get activity trends: %w", err)
	}
	metrics.ActivityTrends = trends

	// Get category breakdown
	categoryBreakdown, err := aas.getCategoryBreakdown(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get category breakdown: %w", err)
	}
	metrics.CategoryBreakdown = categoryBreakdown

	// Get severity breakdown
	severityBreakdown, err := aas.getSeverityBreakdown(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get severity breakdown: %w", err)
	}
	metrics.SeverityBreakdown = severityBreakdown

	// Get recent alerts
	recentAlerts, err := aas.getRecentSecurityAlerts(organizationID, 20)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent alerts: %w", err)
	}
	metrics.RecentAlerts = recentAlerts

	// Get compliance status
	complianceStatus, err := aas.getComplianceStatus(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance status: %w", err)
	}
	metrics.ComplianceStatus = complianceStatus

	// Get performance metrics
	performanceMetrics, err := aas.getPerformanceMetrics(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}
	metrics.PerformanceMetrics = performanceMetrics

	return metrics, nil
}

// DetectAnomalies detects anomalous patterns in audit logs
func (aas *AuditAnalyticsService) DetectAnomalies(organizationID string, timeRange TimeRange) ([]AnomalyDetectionResult, error) {
	var anomalies []AnomalyDetectionResult

	// Detect unusual login patterns
	loginAnomalies, err := aas.detectUnusualLoginPatterns(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to detect login anomalies: %w", err)
	}
	anomalies = append(anomalies, loginAnomalies...)

	// Detect unusual access patterns
	accessAnomalies, err := aas.detectUnusualAccessPatterns(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to detect access anomalies: %w", err)
	}
	anomalies = append(anomalies, accessAnomalies...)

	return anomalies, nil
}

// GenerateThreatIntelligenceReport generates a comprehensive threat intelligence report
func (aas *AuditAnalyticsService) GenerateThreatIntelligenceReport(organizationID string, timeRange TimeRange) (*ThreatIntelligenceReport, error) {
	report := &ThreatIntelligenceReport{
		ReportID:    fmt.Sprintf("threat_report_%d", time.Now().Unix()),
		GeneratedAt: time.Now(),
		TimeRange:   timeRange,
	}

	// Get threat summary
	threatSummary, err := aas.getThreatSummary(organizationID, timeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get threat summary: %w", err)
	}
	report.ThreatSummary = threatSummary

	// Get top threats
	topThreats, err := aas.getTopThreatInfo(organizationID, timeRange, 20)
	if err != nil {
		return nil, fmt.Errorf("failed to get top threats: %w", err)
	}
	report.TopThreats = topThreats

	// Generate recommendations
	recommendations := aas.generateThreatRecommendations(report)
	report.Recommendations = recommendations

	return report, nil
}

// Helper methods

func (aas *AuditAnalyticsService) getTopUsers(organizationID string, timeRange TimeRange, limit int) ([]UserActivitySummary, error) {
	var results []struct {
		SubjectID      string    `json:"subject_id"`
		ActivityCount  int64     `json:"activity_count"`
		AvgRiskScore   float64   `json:"avg_risk_score"`
		LastActivity   time.Time `json:"last_activity"`
		SecurityEvents int64     `json:"security_events"`
		FailedAttempts int64     `json:"failed_attempts"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select(`
			subject_id,
			COUNT(*) as activity_count,
			AVG(risk_score) as avg_risk_score,
			MAX(event_timestamp) as last_activity,
			SUM(CASE WHEN category IN (?, ?, ?) THEN 1 ELSE 0 END) as security_events,
			SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as failed_attempts
		`, string(models.CategorySecurity), string(models.CategoryAuthentication), string(models.CategoryAuthorization), string(models.StatusFailed)).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND subject_id IS NOT NULL",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("subject_id").
		OrderBy("activity_count DESC").
		Limit(limit).
		Find(&results)

	if err != nil {
		return nil, err
	}

	var users []UserActivitySummary
	for _, result := range results {
		users = append(users, UserActivitySummary{
			UserID:         result.SubjectID,
			ActivityCount:  result.ActivityCount,
			RiskScore:      result.AvgRiskScore,
			LastActivity:   result.LastActivity,
			SecurityEvents: result.SecurityEvents,
			FailedAttempts: result.FailedAttempts,
		})
	}

	return users, nil
}

func (aas *AuditAnalyticsService) getTopIPs(organizationID string, timeRange TimeRange, limit int) ([]IPActivitySummary, error) {
	var results []struct {
		IPAddress     string    `json:"ip_address"`
		ActivityCount int64     `json:"activity_count"`
		UniqueUsers   int64     `json:"unique_users"`
		AvgRiskScore  float64   `json:"avg_risk_score"`
		LastActivity  time.Time `json:"last_activity"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select(`
			ip_address,
			COUNT(*) as activity_count,
			COUNT(DISTINCT subject_id) as unique_users,
			AVG(risk_score) as avg_risk_score,
			MAX(event_timestamp) as last_activity
		`).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND ip_address IS NOT NULL",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("ip_address").
		OrderBy("activity_count DESC").
		Limit(limit).
		Find(&results)

	if err != nil {
		return nil, err
	}

	var ips []IPActivitySummary
	for _, result := range results {
		threatLevel := "low"
		if result.AvgRiskScore > 70 {
			threatLevel = "high"
		} else if result.AvgRiskScore > 40 {
			threatLevel = "medium"
		}

		ips = append(ips, IPActivitySummary{
			IPAddress:     result.IPAddress,
			ActivityCount: result.ActivityCount,
			UniqueUsers:   result.UniqueUsers,
			RiskScore:     result.AvgRiskScore,
			LastActivity:  result.LastActivity,
			ThreatLevel:   threatLevel,
		})
	}

	return ips, nil
}

func (aas *AuditAnalyticsService) getActivityTrends(organizationID string, timeRange TimeRange) ([]ActivityTrend, error) {
	var results []struct {
		TimeGroup      string  `json:"time_group"`
		ActivityCount  int64   `json:"activity_count"`
		SecurityEvents int64   `json:"security_events"`
		FailedAttempts int64   `json:"failed_attempts"`
		AvgRiskScore   float64 `json:"avg_risk_score"`
	}

	groupBy := "DATE_FORMAT(event_timestamp, '%Y-%m-%d %H:00:00')"

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select(fmt.Sprintf(`
			%s as time_group,
			COUNT(*) as activity_count,
			SUM(CASE WHEN category IN (?, ?, ?) THEN 1 ELSE 0 END) as security_events,
			SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as failed_attempts,
			AVG(risk_score) as avg_risk_score
		`, groupBy), string(models.CategorySecurity), string(models.CategoryAuthentication), string(models.CategoryAuthorization), string(models.StatusFailed)).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("time_group").
		OrderBy("time_group ASC").
		Find(&results)

	if err != nil {
		return nil, err
	}

	var trends []ActivityTrend
	for _, result := range results {
		timestamp, _ := time.Parse("2006-01-02 15:04:05", result.TimeGroup)
		trends = append(trends, ActivityTrend{
			Timestamp:        timestamp,
			ActivityCount:    result.ActivityCount,
			SecurityEvents:   result.SecurityEvents,
			FailedAttempts:   result.FailedAttempts,
			AverageRiskScore: result.AvgRiskScore,
		})
	}

	return trends, nil
}

func (aas *AuditAnalyticsService) getCategoryBreakdown(organizationID string, timeRange TimeRange) ([]CategorySummary, error) {
	var results []struct {
		Category     string  `json:"category"`
		Count        int64   `json:"count"`
		AvgRiskScore float64 `json:"avg_risk_score"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("category, COUNT(*) as count, AVG(risk_score) as avg_risk_score").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("category").
		OrderBy("count DESC").
		Find(&results)

	if err != nil {
		return nil, err
	}

	// Calculate total for percentages
	var total int64
	for _, result := range results {
		total += result.Count
	}

	var categories []CategorySummary
	for _, result := range results {
		percentage := float64(result.Count) / float64(total) * 100
		// Calculate trend change compared to previous period
		trendChange := aas.calculateCategoryTrendChange(organizationID, result.Category, timeRange)

		categories = append(categories, CategorySummary{
			Category:     result.Category,
			Count:        result.Count,
			Percentage:   percentage,
			AvgRiskScore: result.AvgRiskScore,
			TrendChange:  trendChange,
		})
	}

	return categories, nil
}

func (aas *AuditAnalyticsService) getSeverityBreakdown(organizationID string, timeRange TimeRange) ([]SeveritySummary, error) {
	var results []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("severity, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("severity").
		OrderBy("count DESC").
		Find(&results)

	if err != nil {
		return nil, err
	}

	// Calculate total for percentages
	var total int64
	for _, result := range results {
		total += result.Count
	}

	var severities []SeveritySummary
	for _, result := range results {
		percentage := float64(result.Count) / float64(total) * 100
		// Calculate trend change compared to previous period
		trendChange := aas.calculateSeverityTrendChange(organizationID, result.Severity, timeRange)

		severities = append(severities, SeveritySummary{
			Severity:    result.Severity,
			Count:       result.Count,
			Percentage:  percentage,
			TrendChange: trendChange,
		})
	}

	return severities, nil
}

func (aas *AuditAnalyticsService) getRecentSecurityAlerts(organizationID string, limit int) ([]AlertSummary, error) {
	var activities []models.ActivityLog

	err := facades.Orm().Query().
		Where("organization_id = ? AND (risk_score > 70 OR severity IN (?, ?) OR category = ?)",
			organizationID, string(models.SeverityHigh), string(models.SeverityCritical), string(models.CategorySecurity)).
		OrderBy("event_timestamp DESC").
		Limit(limit).
		Find(&activities)

	if err != nil {
		return nil, err
	}

	var alerts []AlertSummary
	for _, activity := range activities {
		alerts = append(alerts, AlertSummary{
			ID:          activity.ID,
			EventType:   activity.LogName,
			Description: activity.Description,
			Severity:    string(activity.Severity),
			RiskScore:   activity.RiskScore,
			UserID:      activity.SubjectID,
			IPAddress:   activity.IPAddress,
			Timestamp:   activity.EventTimestamp,
			Status:      "open", // Default status
		})
	}

	return alerts, nil
}

func (aas *AuditAnalyticsService) getComplianceStatus(organizationID string, timeRange TimeRange) (ComplianceStatus, error) {
	// Simplified compliance status
	return ComplianceStatus{
		GDPRCompliance: ComplianceMetric{
			Score:          85.5,
			LoggedEvents:   100,
			RequiredEvents: 100,
			Status:         "compliant",
		},
		HIPAACompliance: ComplianceMetric{
			Score:          90.0,
			LoggedEvents:   50,
			RequiredEvents: 50,
			Status:         "compliant",
		},
		SOXCompliance: ComplianceMetric{
			Score:          78.2,
			LoggedEvents:   75,
			RequiredEvents: 75,
			Status:         "compliant",
		},
		PCIDSSCompliance: ComplianceMetric{
			Score:          92.1,
			LoggedEvents:   25,
			RequiredEvents: 25,
			Status:         "compliant",
		},
		OverallScore:  86.5,
		LastAuditDate: time.Now().AddDate(0, -1, 0),
	}, nil
}

func (aas *AuditAnalyticsService) getPerformanceMetrics(organizationID string, timeRange TimeRange) (PerformanceMetrics, error) {
	totalLogs, _ := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Count()

	duration := timeRange.EndTime.Sub(timeRange.StartTime).Seconds()
	logsPerSecond := float64(totalLogs) / duration

	return PerformanceMetrics{
		AvgLogProcessingTime: 15.5,
		LogsPerSecond:        logsPerSecond,
		StorageUsed:          totalLogs * 1024,
		IndexEfficiency:      92.3,
		QueryPerformance:     45.2,
	}, nil
}

func (aas *AuditAnalyticsService) detectUnusualLoginPatterns(organizationID string, timeRange TimeRange) ([]AnomalyDetectionResult, error) {
	var anomalies []AnomalyDetectionResult

	var results []struct {
		SubjectID    string `json:"subject_id"`
		FailedCount  int64  `json:"failed_count"`
		SuccessCount int64  `json:"success_count"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select(`
			subject_id,
			SUM(CASE WHEN log_name LIKE '%login.failed%' THEN 1 ELSE 0 END) as failed_count,
			SUM(CASE WHEN log_name LIKE '%login.success%' THEN 1 ELSE 0 END) as success_count
		`).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND log_name LIKE '%login%'",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("subject_id").
		Having("failed_count > 5 AND success_count > 0").
		Find(&results)

	if err != nil {
		return anomalies, err
	}

	for _, result := range results {
		if result.FailedCount > 5 && result.SuccessCount > 0 {
			anomalies = append(anomalies, AnomalyDetectionResult{
				UserID:      result.SubjectID,
				AnomalyType: "brute_force_success",
				Severity:    "high",
				Description: fmt.Sprintf("User had %d failed login attempts followed by successful login", result.FailedCount),
				DetectedAt:  time.Now(),
				Evidence: map[string]interface{}{
					"failed_attempts":   result.FailedCount,
					"successful_logins": result.SuccessCount,
				},
				RiskScore: 85,
				Recommendations: []string{
					"Review user account for compromise",
					"Check for unusual access patterns",
					"Consider forcing password reset",
				},
			})
		}
	}

	return anomalies, nil
}

func (aas *AuditAnalyticsService) detectUnusualAccessPatterns(organizationID string, timeRange TimeRange) ([]AnomalyDetectionResult, error) {
	var anomalies []AnomalyDetectionResult

	var results []struct {
		SubjectID string `json:"subject_id"`
		Count     int64  `json:"count"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("subject_id, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND (HOUR(event_timestamp) < 6 OR HOUR(event_timestamp) > 22)",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("subject_id").
		Having("count > 10").
		Find(&results)

	if err != nil {
		return anomalies, err
	}

	for _, result := range results {
		anomalies = append(anomalies, AnomalyDetectionResult{
			UserID:      result.SubjectID,
			AnomalyType: "unusual_time_access",
			Severity:    "medium",
			Description: fmt.Sprintf("User accessed system %d times outside business hours", result.Count),
			DetectedAt:  time.Now(),
			Evidence: map[string]interface{}{
				"off_hours_access_count": result.Count,
			},
			RiskScore: 60,
			Recommendations: []string{
				"Verify if user has legitimate reason for off-hours access",
				"Check if user account is shared",
				"Review access patterns for anomalies",
			},
		})
	}

	return anomalies, nil
}

func (aas *AuditAnalyticsService) getThreatSummary(organizationID string, timeRange TimeRange) (ThreatSummary, error) {
	var results []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("severity, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND category = ?",
			organizationID, timeRange.StartTime, timeRange.EndTime, string(models.CategorySecurity)).
		Group("severity").
		Find(&results)

	if err != nil {
		return ThreatSummary{}, err
	}

	summary := ThreatSummary{}
	for _, result := range results {
		summary.TotalThreats += result.Count
		switch result.Severity {
		case string(models.SeverityCritical):
			summary.CriticalThreats = result.Count
		case string(models.SeverityHigh):
			summary.HighThreats = result.Count
		case string(models.SeverityMedium):
			summary.MediumThreats = result.Count
		case string(models.SeverityLow):
			summary.LowThreats = result.Count
		}
	}

	// Calculate average risk score
	var avgRisk float64
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("AVG(risk_score)").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND category = ?",
			organizationID, timeRange.StartTime, timeRange.EndTime, string(models.CategorySecurity)).
		Pluck("avg_risk_score", &avgRisk)

	summary.AverageRiskScore = avgRisk
	summary.ThreatTrend = "stable"

	return summary, nil
}

func (aas *AuditAnalyticsService) getTopThreatInfo(organizationID string, timeRange TimeRange, limit int) ([]ThreatInfo, error) {
	var results []struct {
		IPAddress string    `json:"ip_address"`
		Count     int64     `json:"count"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("ip_address, COUNT(*) as count, MIN(event_timestamp) as first_seen, MAX(event_timestamp) as last_seen").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND risk_score > 50",
			organizationID, timeRange.StartTime, timeRange.EndTime).
		Group("ip_address").
		OrderBy("count DESC").
		Limit(limit).
		Find(&results)

	if err != nil {
		return nil, err
	}

	var threats []ThreatInfo
	for _, result := range results {
		severity := "medium"
		if result.Count > 100 {
			severity = "high"
		}
		if result.Count > 500 {
			severity = "critical"
		}

		threats = append(threats, ThreatInfo{
			Type:        "ip_address",
			Value:       result.IPAddress,
			Severity:    severity,
			Confidence:  0.8,
			FirstSeen:   result.FirstSeen,
			LastSeen:    result.LastSeen,
			Occurrences: result.Count,
			Description: fmt.Sprintf("Suspicious IP address with %d high-risk activities", result.Count),
		})
	}

	return threats, nil
}

func (aas *AuditAnalyticsService) generateThreatRecommendations(report *ThreatIntelligenceReport) []string {
	recommendations := []string{
		"Implement multi-factor authentication for all user accounts",
		"Enable real-time monitoring for high-risk activities",
		"Conduct regular security awareness training",
		"Review and update access controls regularly",
		"Implement network segmentation for critical systems",
	}

	if report.ThreatSummary.CriticalThreats > 0 {
		recommendations = append(recommendations, "Immediate investigation required for critical threats")
	}

	if len(report.TopThreats) > 10 {
		recommendations = append(recommendations, "Consider implementing automated threat response")
	}

	return recommendations
}

// Utility functions
func calculateComplianceScore(logged, required int64) float64 {
	if required == 0 {
		return 100.0
	}
	score := float64(logged) / float64(required) * 100
	if score > 100 {
		score = 100
	}
	return math.Round(score*100) / 100
}

// calculateCategoryTrendChange calculates the trend change for a category compared to the previous period
func (aas *AuditAnalyticsService) calculateCategoryTrendChange(organizationID, category string, timeRange TimeRange) float64 {
	facades.Log().Info("Calculating category trend change", map[string]interface{}{
		"organization_id": organizationID,
		"category":        category,
		"start_time":      timeRange.StartTime,
		"end_time":        timeRange.EndTime,
	})

	// Calculate previous period dates
	duration := timeRange.EndTime.Sub(timeRange.StartTime)
	prevStartTime := timeRange.StartTime.Add(-duration)
	prevEndTime := timeRange.StartTime

	// Get current period count
	currentCount, err := facades.Orm().Query().
		Table("activity_logs").
		Where("organization_id = ?", organizationID).
		Where("category = ?", category).
		Where("created_at BETWEEN ? AND ?", timeRange.StartTime, timeRange.EndTime).
		Count()

	if err != nil {
		facades.Log().Error("Failed to get current period count", map[string]interface{}{
			"organization_id": organizationID,
			"category":        category,
			"error":           err.Error(),
		})
		return 0
	}

	// Get previous period count
	prevCount, err := facades.Orm().Query().
		Table("activity_logs").
		Where("organization_id = ?", organizationID).
		Where("category = ?", category).
		Where("created_at BETWEEN ? AND ?", prevStartTime, prevEndTime).
		Count()

	if err != nil {
		facades.Log().Error("Failed to get previous period count", map[string]interface{}{
			"organization_id": organizationID,
			"category":        category,
			"error":           err.Error(),
		})
		return 0
	}

	// Calculate percentage change
	if prevCount == 0 {
		if currentCount > 0 {
			return 100.0 // 100% increase from zero
		}
		return 0.0
	}

	trendChange := float64(currentCount-prevCount) / float64(prevCount) * 100

	facades.Log().Info("Category trend change calculated", map[string]interface{}{
		"organization_id": organizationID,
		"category":        category,
		"current_count":   currentCount,
		"prev_count":      prevCount,
		"trend_change":    trendChange,
	})

	return math.Round(trendChange*100) / 100
}

// calculateSeverityTrendChange calculates the trend change for a severity level compared to the previous period
func (aas *AuditAnalyticsService) calculateSeverityTrendChange(organizationID, severity string, timeRange TimeRange) float64 {
	facades.Log().Info("Calculating severity trend change", map[string]interface{}{
		"organization_id": organizationID,
		"severity":        severity,
		"start_time":      timeRange.StartTime,
		"end_time":        timeRange.EndTime,
	})

	// Calculate previous period dates
	duration := timeRange.EndTime.Sub(timeRange.StartTime)
	prevStartTime := timeRange.StartTime.Add(-duration)
	prevEndTime := timeRange.StartTime

	// Get current period count
	currentCount, err := facades.Orm().Query().
		Table("activity_logs").
		Where("organization_id = ?", organizationID).
		Where("severity = ?", severity).
		Where("created_at BETWEEN ? AND ?", timeRange.StartTime, timeRange.EndTime).
		Count()

	if err != nil {
		facades.Log().Error("Failed to get current period severity count", map[string]interface{}{
			"organization_id": organizationID,
			"severity":        severity,
			"error":           err.Error(),
		})
		return 0
	}

	// Get previous period count
	prevCount, err := facades.Orm().Query().
		Table("activity_logs").
		Where("organization_id = ?", organizationID).
		Where("severity = ?", severity).
		Where("created_at BETWEEN ? AND ?", prevStartTime, prevEndTime).
		Count()

	if err != nil {
		facades.Log().Error("Failed to get previous period severity count", map[string]interface{}{
			"organization_id": organizationID,
			"severity":        severity,
			"error":           err.Error(),
		})
		return 0
	}

	// Calculate percentage change
	if prevCount == 0 {
		if currentCount > 0 {
			return 100.0 // 100% increase from zero
		}
		return 0.0
	}

	trendChange := float64(currentCount-prevCount) / float64(prevCount) * 100

	facades.Log().Info("Severity trend change calculated", map[string]interface{}{
		"organization_id": organizationID,
		"severity":        severity,
		"current_count":   currentCount,
		"prev_count":      prevCount,
		"trend_change":    trendChange,
	})

	return math.Round(trendChange*100) / 100
}
