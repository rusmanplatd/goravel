package models

import (
	"time"
)

// Notification represents a system notification
// @Description Notification model for system notifications and alerts
type Notification struct {
	BaseModel

	// Notification type
	// @example user_registered
	Type string `json:"type" gorm:"not null" example:"user_registered"`

	// Notification data (JSON)
	// @example {"message":"Welcome to the platform","user_name":"John Doe"}
	Data map[string]interface{} `json:"data" gorm:"type:json" example:"{\"message\":\"Welcome to the platform\",\"user_name\":\"John Doe\"}"`

	// Notifiable entity ID (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	NotifiableID string `json:"notifiable_id" gorm:"not null" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Notifiable entity type
	// @example User
	NotifiableType string `json:"notifiable_type" gorm:"not null" example:"User"`

	// Notification channel
	// @example email
	Channel string `json:"channel" gorm:"default:database" example:"email"`

	// When notification was read
	// @example 2024-01-15T10:30:00Z
	ReadAt *time.Time `json:"read_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// When notification was sent
	// @example 2024-01-15T10:30:00Z
	SentAt *time.Time `json:"sent_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// When notification failed
	// @example 2024-01-15T10:30:00Z
	FailedAt *time.Time `json:"failed_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Failure reason
	// @example SMTP connection failed
	FailureReason *string `json:"failure_reason,omitempty" example:"SMTP connection failed"`

	// Delivery tracking fields
	// Delivery status (pending, sent, delivered, failed, read)
	// @example pending
	DeliveryStatus string `json:"delivery_status" gorm:"default:pending" example:"pending"`

	// Number of delivery attempts
	// @example 1
	DeliveryAttempts int `json:"delivery_attempts" gorm:"default:0" example:"1"`

	// Last delivery attempt time
	// @example 2024-01-15T10:30:00Z
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// When notification was delivered
	// @example 2024-01-15T10:30:00Z
	DeliveredAt *time.Time `json:"delivered_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Notification priority (low, normal, high, urgent)
	// @example normal
	Priority string `json:"priority" gorm:"default:normal" example:"normal"`

	// Notification expiration time
	// @example 2024-01-15T10:30:00Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Additional metadata (JSON)
	// @example {"campaign_id":"abc123","source":"api"}
	Metadata map[string]interface{} `json:"metadata" gorm:"type:json" example:"{\"campaign_id\":\"abc123\",\"source\":\"api\"}"`

	// Relationships
	// @Description The entity that should receive this notification
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
	n.DeliveryStatus = "read"
}

// MarkAsUnread marks the notification as unread
func (n *Notification) MarkAsUnread() {
	n.ReadAt = nil
	if n.DeliveryStatus == "read" {
		n.DeliveryStatus = "delivered"
	}
}

// MarkAsSent marks the notification as sent
func (n *Notification) MarkAsSent() {
	now := time.Now()
	n.SentAt = &now
	n.DeliveryStatus = "sent"
	n.LastAttemptAt = &now
}

// MarkAsDelivered marks the notification as delivered
func (n *Notification) MarkAsDelivered() {
	now := time.Now()
	n.DeliveredAt = &now
	n.DeliveryStatus = "delivered"
}

// MarkAsFailed marks the notification as failed
func (n *Notification) MarkAsFailed(reason string) {
	now := time.Now()
	n.FailedAt = &now
	n.FailureReason = &reason
	n.DeliveryStatus = "failed"
	n.LastAttemptAt = &now
}

// IncrementAttempts increments the delivery attempt counter
func (n *Notification) IncrementAttempts() {
	n.DeliveryAttempts++
	now := time.Now()
	n.LastAttemptAt = &now
}

// IsExpired checks if the notification has expired
func (n *Notification) IsExpired() bool {
	if n.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*n.ExpiresAt)
}

// SetExpiration sets the notification expiration time
func (n *Notification) SetExpiration(duration time.Duration) {
	expiresAt := time.Now().Add(duration)
	n.ExpiresAt = &expiresAt
}

// GetData retrieves the notification data
func (n *Notification) GetData() map[string]interface{} {
	return n.Data
}

// SetData sets the notification data
func (n *Notification) SetData(data map[string]interface{}) {
	n.Data = data
}

// GetMetadata retrieves the notification metadata
func (n *Notification) GetMetadata() map[string]interface{} {
	if n.Metadata == nil {
		n.Metadata = make(map[string]interface{})
	}
	return n.Metadata
}

// SetMetadata sets the notification metadata
func (n *Notification) SetMetadata(metadata map[string]interface{}) {
	n.Metadata = metadata
}

// AddMetadata adds a key-value pair to the notification metadata
func (n *Notification) AddMetadata(key string, value interface{}) {
	if n.Metadata == nil {
		n.Metadata = make(map[string]interface{})
	}
	n.Metadata[key] = value
}

// GetNotifiable retrieves the notifiable entity
func (n *Notification) GetNotifiable() interface{} {
	return n.Notifiable
}

// SetNotifiable sets the notifiable entity
func (n *Notification) SetNotifiable(notifiable interface{}) {
	n.Notifiable = notifiable
}

// CanRetry checks if the notification can be retried based on attempts and expiration
func (n *Notification) CanRetry(maxAttempts int) bool {
	if n.IsExpired() {
		return false
	}
	if n.DeliveryStatus == "delivered" || n.DeliveryStatus == "read" {
		return false
	}
	return n.DeliveryAttempts < maxAttempts
}

// GetPriorityWeight returns a numeric weight for the priority (higher = more urgent)
func (n *Notification) GetPriorityWeight() int {
	switch n.Priority {
	case "urgent":
		return 4
	case "high":
		return 3
	case "normal":
		return 2
	case "low":
		return 1
	default:
		return 2
	}
}
