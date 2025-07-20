package models

import (
	"time"

	"github.com/goravel/framework/database/orm"
)

// PushSubscription represents a web push subscription
type PushSubscription struct {
	orm.Model
	ID              string     `json:"id" gorm:"primaryKey;type:ulid"`
	UserID          string     `json:"user_id" gorm:"not null"`
	Endpoint        string     `json:"endpoint" gorm:"not null;size:500"`
	P256dhKey       string     `json:"p256dh_key" gorm:"not null;size:255"`
	AuthToken       string     `json:"auth_token" gorm:"not null;size:255"`
	ContentEncoding string     `json:"content_encoding" gorm:"default:aes128gcm;size:20"`
	IsActive        bool       `json:"is_active" gorm:"default:true"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	DeletedAt       *time.Time `json:"deleted_at" gorm:"index"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for the PushSubscription model
func (p *PushSubscription) TableName() string {
	return "push_subscriptions"
}

// IsValid checks if the push subscription is valid
func (p *PushSubscription) IsValid() bool {
	return p.IsActive && p.Endpoint != "" && p.P256dhKey != "" && p.AuthToken != ""
}

// Deactivate marks the subscription as inactive
func (p *PushSubscription) Deactivate() {
	p.IsActive = false
}

// Activate marks the subscription as active
func (p *PushSubscription) Activate() {
	p.IsActive = true
}

// GetSubscriptionInfo returns the subscription information for web push
func (p *PushSubscription) GetSubscriptionInfo() map[string]interface{} {
	return map[string]interface{}{
		"endpoint": p.Endpoint,
		"keys": map[string]interface{}{
			"p256dh": p.P256dhKey,
			"auth":   p.AuthToken,
		},
		"contentEncoding": p.ContentEncoding,
	}
}
