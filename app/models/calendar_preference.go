package models

import (
	"time"
)

// CalendarPreference represents user calendar preferences and settings
// @Description User calendar preferences model for customizing calendar behavior
type CalendarPreference struct {
	BaseModel
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Default calendar view (day, week, month, year, agenda)
	// @example week
	DefaultView string `gorm:"default:'week'" json:"default_view" example:"week"`

	// Week starts on (0=Sunday, 1=Monday)
	// @example 1
	WeekStartsOn int `gorm:"default:1" json:"week_starts_on" example:"1"`

	// Default event duration in minutes
	// @example 60
	DefaultEventDuration int `gorm:"default:60" json:"default_event_duration" example:"60"`

	// Working hours start time
	// @example 09:00
	WorkingHoursStart string `gorm:"default:'09:00'" json:"working_hours_start" example:"09:00"`

	// Working hours end time
	// @example 17:00
	WorkingHoursEnd string `gorm:"default:'17:00'" json:"working_hours_end" example:"17:00"`

	// Working days (JSON array of day numbers, 0=Sunday)
	// @example [1,2,3,4,5]
	WorkingDays string `gorm:"default:'[1,2,3,4,5]'" json:"working_days" example:"[1,2,3,4,5]"`

	// Time format (12h or 24h)
	// @example 24h
	TimeFormat string `gorm:"default:'24h'" json:"time_format" example:"24h"`

	// Date format
	// @example YYYY-MM-DD
	DateFormat string `gorm:"default:'YYYY-MM-DD'" json:"date_format" example:"YYYY-MM-DD"`

	// Default timezone
	// @example UTC
	Timezone string `gorm:"default:'UTC'" json:"timezone" example:"UTC"`

	// Language/locale
	// @example en-US
	Language string `gorm:"default:'en-US'" json:"language" example:"en-US"`

	// Show weekends in calendar views
	// @example true
	ShowWeekends bool `gorm:"default:true" json:"show_weekends" example:"true"`

	// Show declined events
	// @example false
	ShowDeclinedEvents bool `gorm:"default:false" json:"show_declined_events" example:"false"`

	// Default event visibility
	// @example private
	DefaultEventVisibility string `gorm:"default:'private'" json:"default_event_visibility" example:"private"`

	// Default reminder settings (JSON format)
	// @example {"email": 15, "popup": 10}
	DefaultReminders string `gorm:"default:'{\"popup\": 10}'" json:"default_reminders" example:"{\"email\": 15, \"popup\": 10}"`

	// Auto-accept meeting invitations
	// @example false
	AutoAcceptInvitations bool `gorm:"default:false" json:"auto_accept_invitations" example:"false"`

	// Show event details in month view
	// @example true
	ShowEventDetailsInMonth bool `gorm:"default:true" json:"show_event_details_in_month" example:"true"`

	// Enable keyboard shortcuts
	// @example true
	EnableKeyboardShortcuts bool `gorm:"default:true" json:"enable_keyboard_shortcuts" example:"true"`

	// Enable drag and drop
	// @example true
	EnableDragAndDrop bool `gorm:"default:true" json:"enable_drag_and_drop" example:"true"`

	// Enable quick add
	// @example true
	EnableQuickAdd bool `gorm:"default:true" json:"enable_quick_add" example:"true"`

	// Compact view mode
	// @example false
	CompactView bool `gorm:"default:false" json:"compact_view" example:"false"`

	// Show lunar calendar
	// @example false
	ShowLunarCalendar bool `gorm:"default:false" json:"show_lunar_calendar" example:"false"`

	// Color theme (light, dark, auto)
	// @example auto
	ColorTheme string `gorm:"default:'auto'" json:"color_theme" example:"auto"`

	// Custom CSS for calendar styling
	// @example
	CustomCSS string `json:"custom_css,omitempty"`

	// Notification preferences (JSON format)
	// @example {"email": true, "push": true, "sms": false}
	NotificationPreferences string `gorm:"default:'{\"email\": true, \"push\": false}'" json:"notification_preferences" example:"{\"email\": true, \"push\": true, \"sms\": false}"`

	// Calendar sync preferences (JSON format)
	// @example {"auto_sync": true, "sync_frequency": 15}
	SyncPreferences string `gorm:"default:'{\"auto_sync\": false}'" json:"sync_preferences" example:"{\"auto_sync\": true, \"sync_frequency\": 15}"`

	// Privacy settings (JSON format)
	// @example {"show_free_busy": true, "allow_invitations": true}
	PrivacySettings string `gorm:"default:'{\"show_free_busy\": true}'" json:"privacy_settings" example:"{\"show_free_busy\": true, \"allow_invitations\": true}"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description User who owns these preferences
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// CalendarKeyboardShortcut represents custom keyboard shortcuts
// @Description Custom keyboard shortcuts for calendar actions
type CalendarKeyboardShortcut struct {
	BaseModel
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Action name
	// @example create_event
	Action string `gorm:"not null" json:"action" example:"create_event"`

	// Key combination (e.g., "Ctrl+N", "C", "Shift+D")
	// @example Ctrl+N
	KeyCombination string `gorm:"not null" json:"key_combination" example:"Ctrl+N"`

	// Description of the action
	// @example Create new event
	Description string `json:"description" example:"Create new event"`

	// Whether the shortcut is enabled
	// @example true
	IsEnabled bool `gorm:"default:true" json:"is_enabled" example:"true"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description User who owns this shortcut
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// CalendarViewState represents saved view states
// @Description Saved calendar view states for quick restoration
type CalendarViewState struct {
	BaseModel
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// State name
	// @example My Work Week
	Name string `gorm:"not null" json:"name" example:"My Work Week"`

	// View type (day, week, month, year, agenda)
	// @example week
	ViewType string `gorm:"not null" json:"view_type" example:"week"`

	// View configuration (JSON format)
	// @example {"visible_calendars": ["work", "personal"], "date_range": "2024-01-15"}
	Configuration string `json:"configuration" example:"{\"visible_calendars\": [\"work\", \"personal\"], \"date_range\": \"2024-01-15\"}"`

	// Whether this is the default view state
	// @example false
	IsDefault bool `gorm:"default:false" json:"is_default" example:"false"`

	// Last used timestamp
	// @example 2024-01-15T10:00:00Z
	LastUsedAt *time.Time `json:"last_used_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description User who owns this view state
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}
