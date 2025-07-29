package models

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/goravel/framework/facades"
)

// ActivityLogSeverity represents the severity level of an activity
type ActivityLogSeverity string

const (
	SeverityInfo     ActivityLogSeverity = "info"
	SeverityLow      ActivityLogSeverity = "low"
	SeverityMedium   ActivityLogSeverity = "medium"
	SeverityHigh     ActivityLogSeverity = "high"
	SeverityCritical ActivityLogSeverity = "critical"
)

// ActivityLogCategory represents the category of an activity
type ActivityLogCategory string

const (
	CategoryAuthentication ActivityLogCategory = "authentication"
	CategoryAuthorization  ActivityLogCategory = "authorization"
	CategoryDataAccess     ActivityLogCategory = "data_access"
	CategoryDataModify     ActivityLogCategory = "data_modify"
	CategorySecurity       ActivityLogCategory = "security"
	CategorySystem         ActivityLogCategory = "system"
	CategoryUser           ActivityLogCategory = "user"
	CategoryAdmin          ActivityLogCategory = "admin"
	CategoryCompliance     ActivityLogCategory = "compliance"
	CategoryPerformance    ActivityLogCategory = "performance"
)

// ActivityLogStatus represents the status of an activity
type ActivityLogStatus string

const (
	StatusSuccess ActivityLogStatus = "success"
	StatusFailed  ActivityLogStatus = "failed"
	StatusPending ActivityLogStatus = "pending"
	StatusWarning ActivityLogStatus = "warning"
	StatusError   ActivityLogStatus = "error"
)

// ActivityLog represents an activity log entry
// @Description Activity log model for audit trail and activity tracking
type ActivityLog struct {
	BaseModel

	// Log name/category
	// @example user_login
	LogName string `gorm:"index;not null" json:"log_name" example:"user_login" validate:"required,max:100"`

	// Activity description
	// @example User logged in successfully
	Description string `gorm:"not null" json:"description" example:"User logged in successfully" validate:"required,max:500"`

	// Event category for grouping related activities
	// @example authentication
	Category ActivityLogCategory `gorm:"index;not null;default:'system'" json:"category" example:"authentication" validate:"required"`

	// Severity level of the activity
	// @example medium
	Severity ActivityLogSeverity `gorm:"index;not null;default:'info'" json:"severity" example:"medium" validate:"required"`

	// Status of the activity
	// @example success
	Status ActivityLogStatus `gorm:"index;not null;default:'success'" json:"status" example:"success" validate:"required"`

	// Subject type (model name)
	// @example User
	SubjectType string `gorm:"index" json:"subject_type" example:"User" validate:"max:100"`

	// Subject ID (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	SubjectID string `gorm:"index;type:char(26)" json:"subject_id" example:"01HXYZ123456789ABCDEFGHIJK" validate:"max:26"`

	// Causer type (who performed the action)
	// @example User
	CauserType string `gorm:"index" json:"causer_type" example:"User" validate:"max:100"`

	// Causer ID (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	CauserID string `gorm:"index;type:char(26)" json:"causer_id" example:"01HXYZ123456789ABCDEFGHIJK" validate:"max:26"`

	// IP address of the request
	// @example 192.168.1.1
	IPAddress string `gorm:"index" json:"ip_address" example:"192.168.1.1" validate:"max:45"`

	// User agent string
	// @example Mozilla/5.0...
	UserAgent string `gorm:"type:text" json:"user_agent" example:"Mozilla/5.0..." validate:"max:1000"`

	// Request path
	// @example /api/v1/users
	RequestPath string `gorm:"index" json:"request_path" example:"/api/v1/users" validate:"max:500"`

	// HTTP method
	// @example POST
	RequestMethod string `gorm:"index" json:"request_method" example:"POST" validate:"max:10"`

	// HTTP status code
	// @example 200
	StatusCode int `gorm:"index" json:"status_code" example:"200"`

	// Request duration in milliseconds
	// @example 150
	Duration int64 `json:"duration" example:"150"`

	// Session ID
	// @example session_abc123
	SessionID string `gorm:"index;type:char(36)" json:"session_id" example:"session_abc123" validate:"max:36"`

	// Request ID for tracing
	// @example req_abc123
	RequestID string `gorm:"index;type:char(36)" json:"request_id" example:"req_abc123" validate:"max:36"`

	// Geographic location data
	// @example {"country": "US", "city": "New York"}
	GeoLocation json.RawMessage `gorm:"type:json" json:"geo_location" example:"{\"country\": \"US\", \"city\": \"New York\"}"`

	// Device information
	// @example {"type": "desktop", "os": "Windows"}
	DeviceInfo json.RawMessage `gorm:"type:json" json:"device_info" example:"{\"type\": \"desktop\", \"os\": \"Windows\"}"`

	// Risk score (0-100)
	// @example 25
	RiskScore int `gorm:"index;default:0" json:"risk_score" example:"25" validate:"min:0,max:100"`

	// Threat level
	// @example low
	ThreatLevel string `gorm:"index" json:"threat_level" example:"low" validate:"max:20"`

	// Tags for categorization
	// @example ["login", "success", "mobile"]
	Tags json.RawMessage `gorm:"type:json" json:"tags" example:"[\"login\", \"success\", \"mobile\"]"`

	// Additional properties as JSON
	// @example {"previous_value":"old","new_value":"new"}
	Properties json.RawMessage `gorm:"type:json" json:"properties" example:"{\"previous_value\":\"old\",\"new_value\":\"new\"}"`

	// Compliance flags
	// @example {"gdpr": true, "hipaa": false}
	ComplianceFlags json.RawMessage `gorm:"type:json" json:"compliance_flags" example:"{\"gdpr\": true, \"hipaa\": false}"`

	// Event timestamp (can be different from created_at for delayed logging)
	// @example 2024-01-15T10:30:00Z
	EventTimestamp time.Time `gorm:"index;not null;default:CURRENT_TIMESTAMP" json:"event_timestamp" example:"2024-01-15T10:30:00Z"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"index;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK" validate:"max:26"`

	// Relationships
	// @Description Organization this activity belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description User who performed the action (if causer is a user)
	CauserUser *User `gorm:"foreignKey:CauserID;references:ID" json:"causer_user,omitempty"`

	// @Description User who is the subject of the action (if subject is a user)
	SubjectUser *User `gorm:"foreignKey:SubjectID;references:ID" json:"subject_user,omitempty"`
}

// TableName returns the table name for the ActivityLog model
func (ActivityLog) TableName() string {
	return "activity_logs"
}

// BeforeCreate hook to set default values
func (al *ActivityLog) BeforeCreate() error {
	if al.EventTimestamp.IsZero() {
		al.EventTimestamp = time.Now()
	}
	if al.Category == "" {
		al.Category = CategorySystem
	}
	if al.Severity == "" {
		al.Severity = SeverityInfo
	}
	if al.Status == "" {
		al.Status = StatusSuccess
	}
	return nil
}

// IsHighRisk returns true if the activity is considered high risk
func (al *ActivityLog) IsHighRisk() bool {
	return al.RiskScore > 70 || al.Severity == SeverityCritical || al.Severity == SeverityHigh
}

// IsSecurity returns true if the activity is security-related
func (al *ActivityLog) IsSecurity() bool {
	return al.Category == CategorySecurity || al.Category == CategoryAuthentication || al.Category == CategoryAuthorization
}

// GetPropertiesMap returns properties as a map
func (al *ActivityLog) GetPropertiesMap() (map[string]interface{}, error) {
	if al.Properties == nil {
		return make(map[string]interface{}), nil
	}

	var props map[string]interface{}
	err := json.Unmarshal(al.Properties, &props)
	return props, err
}

// SetPropertiesMap sets properties from a map
func (al *ActivityLog) SetPropertiesMap(props map[string]interface{}) error {
	if props == nil {
		al.Properties = nil
		return nil
	}

	data, err := json.Marshal(props)
	if err != nil {
		return err
	}

	al.Properties = data
	return nil
}

// GetTagsSlice returns tags as a slice
func (al *ActivityLog) GetTagsSlice() ([]string, error) {
	if al.Tags == nil {
		return []string{}, nil
	}

	var tags []string
	err := json.Unmarshal(al.Tags, &tags)
	return tags, err
}

// SetTagsSlice sets tags from a slice
func (al *ActivityLog) SetTagsSlice(tags []string) error {
	if tags == nil {
		al.Tags = nil
		return nil
	}

	data, err := json.Marshal(tags)
	if err != nil {
		return err
	}

	al.Tags = data
	return nil
}

// ActivityLogger provides methods for logging activities
type ActivityLogger struct{}

// NewActivityLogger creates a new activity logger instance
func NewActivityLogger() *ActivityLogger {
	return &ActivityLogger{}
}

// LogActivity creates a new activity log entry with full context
func (al *ActivityLogger) LogActivity(activity *ActivityLog) error {
	// Set default event timestamp if not provided
	if activity.EventTimestamp.IsZero() {
		activity.EventTimestamp = time.Now()
	}

	// Validate required fields
	if activity.Description == "" {
		return fmt.Errorf("description is required")
	}

	return facades.Orm().Query().Create(activity)
}

// Log creates a new activity log entry
func (al *ActivityLogger) Log(description string, subject interface{}, causer interface{}, properties map[string]interface{}, organizationId string) error {
	activity := &ActivityLog{
		Description:    description,
		OrganizationID: organizationId,
		Category:       CategorySystem,
		Severity:       SeverityInfo,
		Status:         StatusSuccess,
	}

	// Set subject information
	if subject != nil {
		activity.SubjectType = reflect.TypeOf(subject).String()
		if subjectModel, ok := subject.(interface{ GetID() string }); ok {
			activity.SubjectID = subjectModel.GetID()
		}
	}

	// Set causer information
	if causer != nil {
		activity.CauserType = reflect.TypeOf(causer).String()
		if causerModel, ok := causer.(interface{ GetID() string }); ok {
			activity.CauserID = causerModel.GetID()
		}
	}

	// Set properties
	if err := activity.SetPropertiesMap(properties); err != nil {
		return err
	}

	return al.LogActivity(activity)
}

// LogWithName creates a new activity log entry with a specific log name
func (al *ActivityLogger) LogWithName(logName, description string, subject interface{}, causer interface{}, properties map[string]interface{}, organizationId string) error {
	activity := &ActivityLog{
		LogName:        logName,
		Description:    description,
		OrganizationID: organizationId,
		Category:       CategorySystem,
		Severity:       SeverityInfo,
		Status:         StatusSuccess,
	}

	// Set subject information
	if subject != nil {
		activity.SubjectType = reflect.TypeOf(subject).String()
		if subjectModel, ok := subject.(interface{ GetID() string }); ok {
			activity.SubjectID = subjectModel.GetID()
		}
	}

	// Set causer information
	if causer != nil {
		activity.CauserType = reflect.TypeOf(causer).String()
		if causerModel, ok := causer.(interface{ GetID() string }); ok {
			activity.CauserID = causerModel.GetID()
		}
	}

	// Set properties
	if err := activity.SetPropertiesMap(properties); err != nil {
		return err
	}

	return al.LogActivity(activity)
}

// LogSecurityEvent creates a security-related activity log entry
func (al *ActivityLogger) LogSecurityEvent(logName, description string, severity ActivityLogSeverity, properties map[string]interface{}, organizationId string) error {
	activity := &ActivityLog{
		LogName:        logName,
		Description:    description,
		Category:       CategorySecurity,
		Severity:       severity,
		Status:         StatusWarning,
		OrganizationID: organizationId,
	}

	if err := activity.SetPropertiesMap(properties); err != nil {
		return err
	}

	return al.LogActivity(activity)
}

// GetActivitiesForSubject retrieves activities for a specific subject
func (al *ActivityLogger) GetActivitiesForSubject(subject interface{}, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog
	subjectType := reflect.TypeOf(subject).String()

	var subjectID string
	if subjectModel, ok := subject.(interface{ GetID() string }); ok {
		subjectID = subjectModel.GetID()
	}

	err := facades.Orm().Query().
		Where("subject_type = ? AND subject_id = ? AND organization_id = ?", subjectType, subjectID, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesForCauser retrieves activities caused by a specific user
func (al *ActivityLogger) GetActivitiesForCauser(causer interface{}, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog
	causerType := reflect.TypeOf(causer).String()

	var causerID string
	if causerModel, ok := causer.(interface{ GetID() string }); ok {
		causerID = causerModel.GetID()
	}

	err := facades.Orm().Query().
		Where("causer_type = ? AND causer_id = ? AND organization_id = ?", causerType, causerID, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesByLogName retrieves activities by log name
func (al *ActivityLogger) GetActivitiesByLogName(logName, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("log_name = ? AND organization_id = ?", logName, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesInDateRange retrieves activities within a date range
func (al *ActivityLogger) GetActivitiesInDateRange(startDate, endDate time.Time, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("event_timestamp BETWEEN ? AND ? AND organization_id = ?", startDate, endDate, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesByCategory retrieves activities by category
func (al *ActivityLogger) GetActivitiesByCategory(category ActivityLogCategory, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("category = ? AND organization_id = ?", category, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesBySeverity retrieves activities by severity level
func (al *ActivityLogger) GetActivitiesBySeverity(severity ActivityLogSeverity, organizationId string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("severity = ? AND organization_id = ?", severity, organizationId).
		Order("event_timestamp DESC").
		Find(&activities)

	return activities, err
}

// GetHighRiskActivities retrieves high-risk activities
func (al *ActivityLogger) GetHighRiskActivities(organizationId string, limit int) ([]ActivityLog, error) {
	var activities []ActivityLog

	query := facades.Orm().Query().
		Where("organization_id = ? AND (risk_score > 70 OR severity IN (?, ?))", organizationId, SeverityHigh, SeverityCritical).
		Order("event_timestamp DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&activities)
	return activities, err
}

// GetSecurityActivities retrieves security-related activities
func (al *ActivityLogger) GetSecurityActivities(organizationId string, since time.Time, limit int) ([]ActivityLog, error) {
	var activities []ActivityLog

	query := facades.Orm().Query().
		Where("organization_id = ? AND category IN (?, ?, ?) AND event_timestamp >= ?",
			organizationId, CategorySecurity, CategoryAuthentication, CategoryAuthorization, since).
		Order("event_timestamp DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&activities)
	return activities, err
}

// GetActivityStats returns activity statistics
func (al *ActivityLogger) GetActivityStats(organizationId string, since time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total activities
	totalCount, err := facades.Orm().Query().
		Model(&ActivityLog{}).
		Where("organization_id = ? AND event_timestamp >= ?", organizationId, since).
		Count()
	if err != nil {
		return nil, err
	}
	stats["total_activities"] = totalCount

	// Activities by category
	var categoryStats []struct {
		Category string `json:"category"`
		Count    int64  `json:"count"`
	}
	err = facades.Orm().Query().
		Model(&ActivityLog{}).
		Select("category, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp >= ?", organizationId, since).
		Group("category").
		Find(&categoryStats)
	if err != nil {
		return nil, err
	}
	stats["by_category"] = categoryStats

	// Activities by severity
	var severityStats []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	err = facades.Orm().Query().
		Model(&ActivityLog{}).
		Select("severity, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp >= ?", organizationId, since).
		Group("severity").
		Find(&severityStats)
	if err != nil {
		return nil, err
	}
	stats["by_severity"] = severityStats

	// High-risk activities count
	highRiskCount, err := facades.Orm().Query().
		Model(&ActivityLog{}).
		Where("organization_id = ? AND event_timestamp >= ? AND (risk_score > 70 OR severity IN (?, ?))",
			organizationId, since, SeverityHigh, SeverityCritical).
		Count()
	if err != nil {
		return nil, err
	}
	stats["high_risk_count"] = highRiskCount

	return stats, nil
}
