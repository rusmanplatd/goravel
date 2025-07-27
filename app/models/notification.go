package models

import (
	"time"
)

type Notification struct {
	BaseModel
	Type           string                 `json:"type" gorm:"not null"`
	Data           map[string]interface{} `json:"data" gorm:"type:json"`
	NotifiableID   string                 `json:"notifiable_id" gorm:"not null"`
	NotifiableType string                 `json:"notifiable_type" gorm:"not null"`
	Channel        string                 `json:"channel" gorm:"default:database"`
	ReadAt         *time.Time             `json:"read_at"`
	SentAt         *time.Time             `json:"sent_at"`
	FailedAt       *time.Time             `json:"failed_at"`
	FailureReason  *string                `json:"failure_reason"`

	// Delivery tracking fields
	DeliveryStatus   string                 `json:"delivery_status" gorm:"default:pending"` // pending, sent, delivered, failed, read
	DeliveryAttempts int                    `json:"delivery_attempts" gorm:"default:0"`
	LastAttemptAt    *time.Time             `json:"last_attempt_at"`
	DeliveredAt      *time.Time             `json:"delivered_at"`
	Priority         string                 `json:"priority" gorm:"default:normal"` // low, normal, high, urgent
	ExpiresAt        *time.Time             `json:"expires_at"`
	Metadata         map[string]interface{} `json:"metadata" gorm:"type:json"`

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
