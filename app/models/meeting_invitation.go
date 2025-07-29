package models

import (
	"time"
)

// MeetingInvitation represents a meeting invitation record
type MeetingInvitation struct {
	BaseModel

	// Meeting ID that this invitation is for
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who sent the invitation
	// @example "01HXYZ123456789ABCDEFGHIJK"
	SentBy string `gorm:"not null" json:"sent_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Recipient user ID (for internal users)
	// @example "01HXYZ123456789ABCDEFGHIJK"
	RecipientID *string `json:"recipient_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Recipient email address (for external users)
	// @example "external@example.com"
	Email *string `json:"email,omitempty" example:"external@example.com"`

	// Display name of the recipient
	// @example "John Doe"
	DisplayName *string `json:"display_name,omitempty" example:"John Doe"`

	// Role for the invitation (attendee, presenter, co-organizer)
	// @example "attendee"
	Role string `gorm:"default:'attendee'" json:"role" example:"attendee"`

	// Invitation status (sent, delivered, accepted, declined, tentative, expired)
	// @example "sent"
	Status string `gorm:"default:'sent'" json:"status" example:"sent"`

	// Custom message included with the invitation
	// @example "Please join us for the weekly team standup meeting"
	CustomMessage string `json:"custom_message,omitempty" example:"Please join us for the weekly team standup meeting"`

	// Response message from the recipient
	// @example "Looking forward to it!"
	ResponseMessage string `json:"response_message,omitempty" example:"Looking forward to it!"`

	// When the invitation was sent
	// @example "2024-01-14T09:00:00Z"
	SentAt *time.Time `json:"sent_at,omitempty" example:"2024-01-14T09:00:00Z"`

	// When the recipient responded
	// @example "2024-01-14T10:00:00Z"
	RespondedAt *time.Time `json:"responded_at,omitempty" example:"2024-01-14T10:00:00Z"`

	// Invitation expiry time
	// @example "2024-01-15T09:00:00Z"
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-15T09:00:00Z"`

	// Whether calendar invitation was sent
	// @example true
	CalendarInvitationSent bool `gorm:"default:false" json:"calendar_invitation_sent" example:"true"`

	// Whether email notification was sent
	// @example true
	EmailNotificationSent bool `gorm:"default:false" json:"email_notification_sent" example:"true"`

	// Number of reminder emails sent
	// @example 2
	RemindersSent int `gorm:"default:0" json:"reminders_sent" example:"2"`

	// Additional metadata for the invitation
	// @example {"source": "api", "client_version": "1.0.0"}
	Metadata map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty" example:"{\"source\": \"api\", \"client_version\": \"1.0.0\"}"`

	// Relationships
	// @Description Meeting this invitation is for
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User who sent the invitation
	Sender *User `gorm:"foreignKey:SentBy" json:"sender,omitempty"`

	// @Description Recipient user (for internal users)
	Recipient *User `gorm:"foreignKey:RecipientID" json:"recipient,omitempty"`
}

// TableName returns the table name for MeetingInvitation
func (MeetingInvitation) TableName() string {
	return "meeting_invitations"
}

// IsExpired checks if the invitation has expired
func (mi *MeetingInvitation) IsExpired() bool {
	if mi.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*mi.ExpiresAt)
}

// IsAccepted checks if the invitation was accepted
func (mi *MeetingInvitation) IsAccepted() bool {
	return mi.Status == "accepted"
}

// IsDeclined checks if the invitation was declined
func (mi *MeetingInvitation) IsDeclined() bool {
	return mi.Status == "declined"
}

// IsPending checks if the invitation is still pending
func (mi *MeetingInvitation) IsPending() bool {
	return mi.Status == "sent" || mi.Status == "delivered"
}

// GetRecipientIdentifier returns the best identifier for the recipient
func (mi *MeetingInvitation) GetRecipientIdentifier() string {
	if mi.RecipientID != nil && *mi.RecipientID != "" {
		return *mi.RecipientID
	}
	if mi.Email != nil && *mi.Email != "" {
		return *mi.Email
	}
	if mi.DisplayName != nil && *mi.DisplayName != "" {
		return *mi.DisplayName
	}
	return "Unknown"
}

// CanSendReminder checks if a reminder can be sent
func (mi *MeetingInvitation) CanSendReminder() bool {
	return !mi.IsExpired() && mi.IsPending() && mi.RemindersSent < 3
}

// ToTeamsFormat converts the invitation to Teams-compatible format
func (mi *MeetingInvitation) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":                     mi.ID,
		"meetingId":              mi.MeetingID,
		"sentBy":                 mi.SentBy,
		"recipientId":            mi.RecipientID,
		"email":                  mi.Email,
		"displayName":            mi.DisplayName,
		"role":                   mi.Role,
		"status":                 mi.Status,
		"customMessage":          mi.CustomMessage,
		"responseMessage":        mi.ResponseMessage,
		"sentAt":                 mi.SentAt,
		"respondedAt":            mi.RespondedAt,
		"expiresAt":              mi.ExpiresAt,
		"calendarInvitationSent": mi.CalendarInvitationSent,
		"emailNotificationSent":  mi.EmailNotificationSent,
		"remindersSent":          mi.RemindersSent,
		"isExpired":              mi.IsExpired(),
		"isAccepted":             mi.IsAccepted(),
		"isDeclined":             mi.IsDeclined(),
		"isPending":              mi.IsPending(),
		"recipientIdentifier":    mi.GetRecipientIdentifier(),
		"canSendReminder":        mi.CanSendReminder(),
		"metadata":               mi.Metadata,
		"createdAt":              mi.CreatedAt,
		"updatedAt":              mi.UpdatedAt,
	}
}
