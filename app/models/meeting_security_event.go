package models

import (
	"encoding/json"
	"time"
)

// MeetingSecurityEvent represents a security event in a meeting
// @Description Security event model for meeting monitoring and audit
type MeetingSecurityEvent struct {
	BaseModel
	// Meeting ID where the event occurred
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who triggered the event (nullable for system events)
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID *string `json:"user_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Type of security event
	// @example unauthorized_access_attempt
	EventType string `gorm:"not null" json:"event_type" example:"unauthorized_access_attempt"`

	// Event severity level
	// @example warning
	Severity string `gorm:"not null" json:"severity" example:"warning"`

	// Human-readable description of the event
	// @example User attempted to join without proper permissions
	Description string `gorm:"not null" json:"description" example:"User attempted to join without proper permissions"`

	// Additional event details as JSON
	// @example {"attempt_count":3,"blocked_ip":"192.168.1.100"}
	Details *string `gorm:"type:text" json:"details,omitempty" example:"{\"attempt_count\":3,\"blocked_ip\":\"192.168.1.100\"}"`

	// IP address of the user
	// @example 192.168.1.100
	IPAddress *string `json:"ip_address,omitempty" example:"192.168.1.100"`

	// User agent string
	// @example Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
	UserAgent *string `json:"user_agent,omitempty" example:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`

	// Device information as JSON
	// @example {"type":"desktop","browser":"Chrome","os":"Windows"}
	DeviceInfo *string `gorm:"type:text" json:"device_info,omitempty" example:"{\"type\":\"desktop\",\"browser\":\"Chrome\",\"os\":\"Windows\"}"`

	// Action taken in response to the event
	// @example blocked_access
	ActionTaken *string `json:"action_taken,omitempty" example:"blocked_access"`

	// Whether event requires admin attention
	// @example true
	RequiresAttention bool `gorm:"default:false" json:"requires_attention" example:"true"`

	// Admin who resolved the event
	// @example 01HXYZ123456789ABCDEFGHIJK
	ResolvedBy *string `json:"resolved_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When event was resolved
	// @example 2024-01-15T10:45:00Z
	ResolvedAt *time.Time `json:"resolved_at,omitempty" example:"2024-01-15T10:45:00Z"`

	// Notes about resolution
	// @example False positive - user had valid permissions
	ResolutionNotes *string `gorm:"type:text" json:"resolution_notes,omitempty" example:"False positive - user had valid permissions"`

	// Relationships
	// @Description Meeting where event occurred
	Meeting CalendarEvent `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User who triggered the event
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Admin who resolved the event
	ResolvedByUser *User `gorm:"foreignKey:ResolvedBy" json:"resolved_by_user,omitempty"`
}

// TableName specifies the table name for MeetingSecurityEvent
func (MeetingSecurityEvent) TableName() string {
	return "meeting_security_events"
}

// GetDetails returns the details as a map
func (e *MeetingSecurityEvent) GetDetails() map[string]interface{} {
	var details map[string]interface{}
	if e.Details != nil && *e.Details != "" {
		json.Unmarshal([]byte(*e.Details), &details)
	}
	return details
}

// SetDetails sets the details from a map
func (e *MeetingSecurityEvent) SetDetails(details map[string]interface{}) error {
	if details == nil {
		e.Details = nil
		return nil
	}

	data, err := json.Marshal(details)
	if err != nil {
		return err
	}

	detailsStr := string(data)
	e.Details = &detailsStr
	return nil
}

// GetDeviceInfo returns the device info as a map
func (e *MeetingSecurityEvent) GetDeviceInfo() map[string]interface{} {
	var deviceInfo map[string]interface{}
	if e.DeviceInfo != nil && *e.DeviceInfo != "" {
		json.Unmarshal([]byte(*e.DeviceInfo), &deviceInfo)
	}
	return deviceInfo
}

// SetDeviceInfo sets the device info from a map
func (e *MeetingSecurityEvent) SetDeviceInfo(deviceInfo map[string]interface{}) error {
	if deviceInfo == nil {
		e.DeviceInfo = nil
		return nil
	}

	data, err := json.Marshal(deviceInfo)
	if err != nil {
		return err
	}

	deviceInfoStr := string(data)
	e.DeviceInfo = &deviceInfoStr
	return nil
}

// IsResolved returns true if the event has been resolved
func (e *MeetingSecurityEvent) IsResolved() bool {
	return e.ResolvedAt != nil
}

// IsCritical returns true if the event is critical severity
func (e *MeetingSecurityEvent) IsCritical() bool {
	return e.Severity == "critical"
}

// IsHigh returns true if the event is high severity
func (e *MeetingSecurityEvent) IsHigh() bool {
	return e.Severity == "error"
}

// IsMedium returns true if the event is medium severity
func (e *MeetingSecurityEvent) IsMedium() bool {
	return e.Severity == "warning"
}

// IsLow returns true if the event is low severity
func (e *MeetingSecurityEvent) IsLow() bool {
	return e.Severity == "info"
}

// Resolve marks the event as resolved
func (e *MeetingSecurityEvent) Resolve(resolvedBy, notes string) {
	e.ResolvedBy = &resolvedBy
	e.ResolutionNotes = &notes
	now := time.Now()
	e.ResolvedAt = &now
	e.RequiresAttention = false
}

// MarkAsRequiringAttention marks the event as requiring admin attention
func (e *MeetingSecurityEvent) MarkAsRequiringAttention() {
	e.RequiresAttention = true
}
