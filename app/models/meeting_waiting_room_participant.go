package models

import (
	"encoding/json"
	"time"
)

// MeetingWaitingRoomParticipant represents a participant in a meeting's waiting room
// @Description Waiting room participant model for meeting security
type MeetingWaitingRoomParticipant struct {
	BaseModel
	// Meeting ID this participant is waiting for
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID of the participant
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Participant name
	// @example John Doe
	Name string `gorm:"not null" json:"name" example:"John Doe"`

	// Participant email
	// @example john.doe@example.com
	Email string `gorm:"not null" json:"email" example:"john.doe@example.com"`

	// Time when user joined waiting room
	// @example 2024-01-15T10:30:00Z
	JoinTime time.Time `gorm:"not null" json:"join_time" example:"2024-01-15T10:30:00Z"`

	// Device information as JSON
	// @example {"type":"desktop","browser":"Chrome","os":"Windows"}
	DeviceInfo *string `gorm:"type:text" json:"device_info,omitempty" example:"{\"type\":\"desktop\",\"browser\":\"Chrome\",\"os\":\"Windows\"}"`

	// Reason for joining meeting
	// @example I'm here for the quarterly review meeting
	RequestReason *string `gorm:"type:text" json:"request_reason,omitempty" example:"I'm here for the quarterly review meeting"`

	// Waiting room status
	// @example waiting
	Status string `gorm:"not null;default:waiting" json:"status" example:"waiting"`

	// Host who approved/denied the participant
	// @example 01HXYZ123456789ABCDEFGHIJK
	ApprovedBy *string `json:"approved_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When status was last changed
	// @example 2024-01-15T10:35:00Z
	StatusChangedAt *time.Time `json:"status_changed_at,omitempty" example:"2024-01-15T10:35:00Z"`

	// Reason for denial if applicable
	// @example Meeting is at capacity
	DenialReason *string `gorm:"type:text" json:"denial_reason,omitempty" example:"Meeting is at capacity"`

	// Additional metadata as JSON
	// @example {"retry_count":2,"last_attempt":"2024-01-15T10:25:00Z"}
	Metadata *string `gorm:"type:text" json:"metadata,omitempty" example:"{\"retry_count\":2,\"last_attempt\":\"2024-01-15T10:25:00Z\"}"`

	// Relationships
	// @Description User waiting to join
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Meeting being joined
	Meeting CalendarEvent `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description Host who approved/denied
	ApprovedByUser *User `gorm:"foreignKey:ApprovedBy" json:"approved_by_user,omitempty"`
}

// TableName specifies the table name for MeetingWaitingRoomParticipant
func (MeetingWaitingRoomParticipant) TableName() string {
	return "meeting_waiting_room_participants"
}

// GetDeviceInfo returns the device info as a map
func (p *MeetingWaitingRoomParticipant) GetDeviceInfo() map[string]interface{} {
	var deviceInfo map[string]interface{}
	if p.DeviceInfo != nil && *p.DeviceInfo != "" {
		json.Unmarshal([]byte(*p.DeviceInfo), &deviceInfo)
	}
	return deviceInfo
}

// SetDeviceInfo sets the device info from a map
func (p *MeetingWaitingRoomParticipant) SetDeviceInfo(deviceInfo map[string]interface{}) error {
	if deviceInfo == nil {
		p.DeviceInfo = nil
		return nil
	}

	data, err := json.Marshal(deviceInfo)
	if err != nil {
		return err
	}

	deviceInfoStr := string(data)
	p.DeviceInfo = &deviceInfoStr
	return nil
}

// GetMetadata returns the metadata as a map
func (p *MeetingWaitingRoomParticipant) GetMetadata() map[string]interface{} {
	var metadata map[string]interface{}
	if p.Metadata != nil && *p.Metadata != "" {
		json.Unmarshal([]byte(*p.Metadata), &metadata)
	}
	return metadata
}

// SetMetadata sets the metadata from a map
func (p *MeetingWaitingRoomParticipant) SetMetadata(metadata map[string]interface{}) error {
	if metadata == nil {
		p.Metadata = nil
		return nil
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	metadataStr := string(data)
	p.Metadata = &metadataStr
	return nil
}

// IsWaiting returns true if participant is still waiting
func (p *MeetingWaitingRoomParticipant) IsWaiting() bool {
	return p.Status == "waiting"
}

// IsApproved returns true if participant was approved
func (p *MeetingWaitingRoomParticipant) IsApproved() bool {
	return p.Status == "approved"
}

// IsDenied returns true if participant was denied
func (p *MeetingWaitingRoomParticipant) IsDenied() bool {
	return p.Status == "denied"
}

// Approve approves the participant
func (p *MeetingWaitingRoomParticipant) Approve(approvedBy string) {
	p.Status = "approved"
	p.ApprovedBy = &approvedBy
	now := time.Now()
	p.StatusChangedAt = &now
}

// Deny denies the participant
func (p *MeetingWaitingRoomParticipant) Deny(approvedBy, reason string) {
	p.Status = "denied"
	p.ApprovedBy = &approvedBy
	p.DenialReason = &reason
	now := time.Now()
	p.StatusChangedAt = &now
}
