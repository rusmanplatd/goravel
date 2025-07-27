package models

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/goravel/framework/facades"
)

// ActivityLog represents an activity log entry
// @Description Activity log model for audit trail and activity tracking
type ActivityLog struct {
	BaseModel

	// Log name/category
	// @example user_login
	LogName string `gorm:"index" json:"log_name" example:"user_login"`

	// Activity description
	// @example User logged in successfully
	Description string `json:"description" example:"User logged in successfully"`

	// Subject type (model name)
	// @example User
	SubjectType string `gorm:"index" json:"subject_type" example:"User"`

	// Subject ID (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	SubjectID string `gorm:"index;type:char(26)" json:"subject_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Causer type (who performed the action)
	// @example User
	CauserType string `gorm:"index" json:"causer_type" example:"User"`

	// Causer ID (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	CauserID string `gorm:"index;type:char(26)" json:"causer_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Additional properties as JSON
	// @example {"ip_address":"192.168.1.1","user_agent":"Mozilla/5.0..."}
	Properties json.RawMessage `gorm:"type:json" json:"properties" example:"{\"ip_address\":\"192.168.1.1\",\"user_agent\":\"Mozilla/5.0...\"}"`

	// Tenant ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"index;type:char(26)" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Tenant this activity belongs to
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

// ActivityLogger provides methods for logging activities
type ActivityLogger struct{}

// NewActivityLogger creates a new activity logger instance
func NewActivityLogger() *ActivityLogger {
	return &ActivityLogger{}
}

// Log creates a new activity log entry
func (al *ActivityLogger) Log(description string, subject interface{}, causer interface{}, properties map[string]interface{}, tenantID string) error {
	activity := &ActivityLog{
		Description: description,
		TenantID:    tenantID,
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
	if properties != nil {
		propsJSON, err := json.Marshal(properties)
		if err != nil {
			return err
		}
		activity.Properties = propsJSON
	}

	return facades.Orm().Query().Create(activity)
}

// LogWithName creates a new activity log entry with a specific log name
func (al *ActivityLogger) LogWithName(logName, description string, subject interface{}, causer interface{}, properties map[string]interface{}, tenantID string) error {
	activity := &ActivityLog{
		LogName:     logName,
		Description: description,
		TenantID:    tenantID,
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
	if properties != nil {
		propsJSON, err := json.Marshal(properties)
		if err != nil {
			return err
		}
		activity.Properties = propsJSON
	}

	return facades.Orm().Query().Create(activity)
}

// GetActivitiesForSubject retrieves activities for a specific subject
func (al *ActivityLogger) GetActivitiesForSubject(subject interface{}, tenantID string) ([]ActivityLog, error) {
	var activities []ActivityLog
	subjectType := reflect.TypeOf(subject).String()

	var subjectID string
	if subjectModel, ok := subject.(interface{ GetID() string }); ok {
		subjectID = subjectModel.GetID()
	}

	err := facades.Orm().Query().
		Where("subject_type = ? AND subject_id = ? AND tenant_id = ?", subjectType, subjectID, tenantID).
		Order("created_at DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesForCauser retrieves activities caused by a specific user
func (al *ActivityLogger) GetActivitiesForCauser(causer interface{}, tenantID string) ([]ActivityLog, error) {
	var activities []ActivityLog
	causerType := reflect.TypeOf(causer).String()

	var causerID string
	if causerModel, ok := causer.(interface{ GetID() string }); ok {
		causerID = causerModel.GetID()
	}

	err := facades.Orm().Query().
		Where("causer_type = ? AND causer_id = ? AND tenant_id = ?", causerType, causerID, tenantID).
		Order("created_at DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesByLogName retrieves activities by log name
func (al *ActivityLogger) GetActivitiesByLogName(logName, tenantID string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("log_name = ? AND tenant_id = ?", logName, tenantID).
		Order("created_at DESC").
		Find(&activities)

	return activities, err
}

// GetActivitiesInDateRange retrieves activities within a date range
func (al *ActivityLogger) GetActivitiesInDateRange(startDate, endDate time.Time, tenantID string) ([]ActivityLog, error) {
	var activities []ActivityLog

	err := facades.Orm().Query().
		Where("created_at BETWEEN ? AND ? AND tenant_id = ?", startDate, endDate, tenantID).
		Order("created_at DESC").
		Find(&activities)

	return activities, err
}
