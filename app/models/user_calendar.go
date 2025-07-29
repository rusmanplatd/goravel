package models

import (
	"time"
)

// UserCalendar represents a user's calendar with customization options
// @Description User calendar model with color coding and visibility settings
type UserCalendar struct {
	BaseModel
	// Calendar name
	// @example Personal
	Name string `gorm:"not null" json:"name" example:"Personal"`

	// Calendar description
	// @example My personal events and appointments
	Description string `json:"description" example:"My personal events and appointments"`

	// Calendar color for UI display
	// @example #1976d2
	Color string `gorm:"default:'#1976d2'" json:"color" example:"#1976d2"`

	// Calendar type (personal, work, family, etc.)
	// @example personal
	Type string `gorm:"default:'personal'" json:"type" example:"personal"`

	// Whether the calendar is visible
	// @example true
	IsVisible bool `gorm:"default:true" json:"is_visible" example:"true"`

	// Whether the calendar is the default calendar
	// @example false
	IsDefault bool `gorm:"default:false" json:"is_default" example:"false"`

	// Calendar timezone
	// @example UTC
	Timezone string `gorm:"default:'UTC'" json:"timezone" example:"UTC"`

	// Calendar visibility level (private, public, domain)
	// @example private
	Visibility string `gorm:"default:'private'" json:"visibility" example:"private"`

	// Whether notifications are enabled for this calendar
	// @example true
	NotificationsEnabled bool `gorm:"default:true" json:"notifications_enabled" example:"true"`

	// Default reminder settings for new events (JSON format)
	// @example {"email": 15, "push": 30}
	DefaultReminders string `json:"default_reminders" example:"{\"email\": 15, \"push\": 30}"`

	// External calendar integration settings (JSON format)
	// @example {"provider": "google", "calendar_id": "primary"}
	ExternalSettings string `json:"external_settings,omitempty" example:"{\"provider\": \"google\", \"calendar_id\": \"primary\"}"`

	// Last sync timestamp for external calendars
	// @example 2024-01-15T10:00:00Z
	LastSyncAt *time.Time `json:"last_sync_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Sync status (none, syncing, synced, error)
	// @example synced
	SyncStatus string `gorm:"default:'none'" json:"sync_status" example:"synced"`

	// Sync error message if any
	// @example
	SyncError string `json:"sync_error,omitempty"`

	// Calendar sort order for display
	// @example 1
	SortOrder int `gorm:"default:0" json:"sort_order" example:"1"`

	// Owner user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Calendar owner
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Calendar events
	Events []CalendarEvent `gorm:"foreignKey:CalendarID" json:"events,omitempty"`

	// @Description Calendar sharing settings
	Shares []CalendarShare `gorm:"foreignKey:CalendarID" json:"shares,omitempty"`
}

// CalendarSubscription represents a subscription to another user's calendar
// @Description Calendar subscription model for accessing shared calendars
type CalendarSubscription struct {
	BaseModel
	// Subscriber user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	SubscriberID string `gorm:"not null" json:"subscriber_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Calendar being subscribed to
	// @example 01HXYZ123456789ABCDEFGHIJK
	CalendarID string `gorm:"not null" json:"calendar_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Subscription name (can be different from original calendar name)
	// @example John's Work Calendar
	Name string `json:"name" example:"John's Work Calendar"`

	// Custom color for this subscription
	// @example #388e3c
	Color string `json:"color" example:"#388e3c"`

	// Whether the subscription is visible
	// @example true
	IsVisible bool `gorm:"default:true" json:"is_visible" example:"true"`

	// Permission level (view, edit)
	// @example view
	Permission string `gorm:"default:'view'" json:"permission" example:"view"`

	// Whether notifications are enabled for this subscription
	// @example false
	NotificationsEnabled bool `gorm:"default:false" json:"notifications_enabled" example:"false"`

	// Subscription status (active, paused, expired)
	// @example active
	Status string `gorm:"default:'active'" json:"status" example:"active"`

	// When the subscription was accepted
	// @example 2024-01-15T10:00:00Z
	AcceptedAt *time.Time `json:"accepted_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Subscription expiration date
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Subscriber user
	Subscriber *User `gorm:"foreignKey:SubscriberID" json:"subscriber,omitempty"`

	// @Description Subscribed calendar
	Calendar *UserCalendar `gorm:"foreignKey:CalendarID" json:"calendar,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// CalendarIntegration represents external calendar integrations
// @Description External calendar integration settings (Google, Outlook, etc.)
type CalendarIntegration struct {
	BaseModel
	// Provider name (google, outlook, apple, etc.)
	// @example google
	Provider string `gorm:"not null" json:"provider" example:"google"`

	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// External account identifier
	// @example user@gmail.com
	ExternalAccountID string `gorm:"not null" json:"external_account_id" example:"user@gmail.com"`

	// OAuth access token (encrypted)
	AccessToken string `json:"-"`

	// OAuth refresh token (encrypted)
	RefreshToken string `json:"-"`

	// Token expiration time
	// @example 2024-01-15T11:00:00Z
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty" example:"2024-01-15T11:00:00Z"`

	// Integration status (active, expired, error, disabled)
	// @example active
	Status string `gorm:"default:'active'" json:"status" example:"active"`

	// Last sync timestamp
	// @example 2024-01-15T10:00:00Z
	LastSyncAt *time.Time `json:"last_sync_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Sync frequency in minutes
	// @example 15
	SyncFrequency int `gorm:"default:15" json:"sync_frequency" example:"15"`

	// Whether two-way sync is enabled
	// @example true
	TwoWaySync bool `gorm:"default:false" json:"two_way_sync" example:"true"`

	// Sync settings (JSON format)
	// @example {"import_events": true, "export_events": true, "conflict_resolution": "external_wins"}
	SyncSettings string `json:"sync_settings" example:"{\"import_events\": true, \"export_events\": true, \"conflict_resolution\": \"external_wins\"}"`

	// Last error message if any
	// @example
	LastError string `json:"last_error,omitempty"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Integration owner
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}
