package models

import (
	"time"

	"github.com/goravel/framework/database/orm"
)

type Notification struct {
	orm.Model
	ID             string                 `json:"id" gorm:"primaryKey;type:ulid"`
	Type           string                 `json:"type" gorm:"not null"`
	Data           map[string]interface{} `json:"data" gorm:"type:json"`
	NotifiableID   string                 `json:"notifiable_id" gorm:"not null"`
	NotifiableType string                 `json:"notifiable_type" gorm:"not null"`
	Channel        string                 `json:"channel" gorm:"default:database"`
	ReadAt         *time.Time             `json:"read_at"`
	SentAt         *time.Time             `json:"sent_at"`
	FailedAt       *time.Time             `json:"failed_at"`
	FailureReason  *string                `json:"failure_reason"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	DeletedAt      *time.Time             `json:"deleted_at" gorm:"index"`

	// Relationships
	Notifiable interface{} `json:"notifiable" gorm:"-"`
}

// TableName specifies the table name for the Notification model
func (n *Notification) TableName() string {
	return "notifications"
}

// IsRead checks if the notification has been read
func (n *Notification) IsRead() bool {
	return n.ReadAt != nil
}

// MarkAsRead marks the notification as read
func (n *Notification) MarkAsRead() {
	now := time.Now()
	n.ReadAt = &now
}

// MarkAsUnread marks the notification as unread
func (n *Notification) MarkAsUnread() {
	n.ReadAt = nil
}

// MarkAsSent marks the notification as sent
func (n *Notification) MarkAsSent() {
	now := time.Now()
	n.SentAt = &now
}

// MarkAsFailed marks the notification as failed
func (n *Notification) MarkAsFailed(reason string) {
	now := time.Now()
	n.FailedAt = &now
	n.FailureReason = &reason
}

// GetData retrieves the notification data
func (n *Notification) GetData() map[string]interface{} {
	return n.Data
}

// SetData sets the notification data
func (n *Notification) SetData(data map[string]interface{}) {
	n.Data = data
}

// GetNotifiable retrieves the notifiable entity
func (n *Notification) GetNotifiable() interface{} {
	return n.Notifiable
}

// SetNotifiable sets the notifiable entity
func (n *Notification) SetNotifiable(notifiable interface{}) {
	n.Notifiable = notifiable
}
