package models

import (
	"time"
)

// CalendarShare represents a shared calendar relationship
// @Description Calendar sharing configuration with permissions and access control
type CalendarShare struct {
	BaseModel
	// Owner of the calendar
	// @example 01HXYZ123456789ABCDEFGHIJK
	OwnerID string `gorm:"not null" json:"owner_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User who has access to the calendar
	// @example 01HXYZ123456789ABCDEFGHIJL
	SharedWithID string `gorm:"not null" json:"shared_with_id" example:"01HXYZ123456789ABCDEFGHIJL"`

	// Share name/title
	// @example John's Work Calendar
	ShareName string `gorm:"not null" json:"share_name" example:"John's Work Calendar"`

	// Share description
	// @example Access to John's work schedule for coordination
	Description string `json:"description" example:"Access to John's work schedule for coordination"`

	// Permission level (view, edit, manage)
	// @example view
	Permission string `gorm:"not null;default:'view'" json:"permission" example:"view"`

	// Whether the share is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether to show free/busy only or full details
	// @example false
	ShowFreeBusyOnly bool `gorm:"default:false" json:"show_free_busy_only" example:"false"`

	// Event types to share (JSON array)
	// @example ["meeting", "appointment"]
	SharedEventTypes string `json:"shared_event_types" example:"[\"meeting\", \"appointment\"]"`

	// Time range for sharing (JSON object with start/end times)
	// @example {"start_hour": 9, "end_hour": 17}
	TimeRestrictions string `json:"time_restrictions" example:"{\"start_hour\": 9, \"end_hour\": 17}"`

	// Share expiration date
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// When the share was accepted
	// @example 2024-01-15T10:00:00Z
	AcceptedAt *time.Time `json:"accepted_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Notification preferences as JSON
	// @example {"email_on_changes": true, "push_notifications": false}
	NotificationSettings string `json:"notification_settings" example:"{\"email_on_changes\": true, \"push_notifications\": false}"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Calendar owner
	Owner *User `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`

	// @Description User with shared access
	SharedWith *User `gorm:"foreignKey:SharedWithID" json:"shared_with,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// CalendarDelegate represents a delegation relationship
// @Description Calendar delegation for managing another user's calendar
type CalendarDelegate struct {
	BaseModel
	// Principal user (calendar owner)
	// @example 01HXYZ123456789ABCDEFGHIJK
	PrincipalID string `gorm:"not null" json:"principal_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Delegate user (who can act on behalf)
	// @example 01HXYZ123456789ABCDEFGHIJL
	DelegateID string `gorm:"not null" json:"delegate_id" example:"01HXYZ123456789ABCDEFGHIJL"`

	// Delegation title
	// @example Executive Assistant Delegation
	Title string `gorm:"not null" json:"title" example:"Executive Assistant Delegation"`

	// Delegation description
	// @example Full calendar management delegation for executive assistant
	Description string `json:"description" example:"Full calendar management delegation for executive assistant"`

	// Permission level (view, schedule, manage, full)
	// @example manage
	Permission string `gorm:"not null;default:'schedule'" json:"permission" example:"manage"`

	// Whether delegation is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether delegate can act on behalf in meetings
	// @example true
	CanActOnBehalf bool `gorm:"default:false" json:"can_act_on_behalf" example:"true"`

	// Whether delegate receives copies of meeting invitations
	// @example true
	ReceiveMeetingCopies bool `gorm:"default:false" json:"receive_meeting_copies" example:"true"`

	// Whether delegate can see private events
	// @example false
	CanSeePrivateEvents bool `gorm:"default:false" json:"can_see_private_events" example:"false"`

	// Allowed actions as JSON array
	// @example ["create_events", "modify_events", "delete_events", "respond_to_invitations"]
	AllowedActions string `json:"allowed_actions" example:"[\"create_events\", \"modify_events\", \"delete_events\", \"respond_to_invitations\"]"`

	// Time restrictions for delegation (JSON object)
	// @example {"business_hours_only": true, "start_hour": 8, "end_hour": 18}
	TimeRestrictions string `json:"time_restrictions" example:"{\"business_hours_only\": true, \"start_hour\": 8, \"end_hour\": 18}"`

	// Delegation start date
	// @example 2024-01-15T00:00:00Z
	StartDate time.Time `gorm:"not null" json:"start_date" example:"2024-01-15T00:00:00Z"`

	// Delegation end date
	// @example 2024-12-31T23:59:59Z
	EndDate *time.Time `json:"end_date,omitempty" example:"2024-12-31T23:59:59Z"`

	// When the delegation was accepted
	// @example 2024-01-15T10:00:00Z
	AcceptedAt *time.Time `json:"accepted_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Notification preferences as JSON
	// @example {"notify_on_changes": true, "daily_summary": true}
	NotificationSettings string `json:"notification_settings" example:"{\"notify_on_changes\": true, \"daily_summary\": true}"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Principal user (calendar owner)
	Principal *User `gorm:"foreignKey:PrincipalID" json:"principal,omitempty"`

	// @Description Delegate user
	Delegate *User `gorm:"foreignKey:DelegateID" json:"delegate,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Delegation activities log
	Activities []DelegationActivity `gorm:"foreignKey:DelegationID" json:"activities,omitempty"`
}

// DelegationActivity represents an activity performed by a delegate
// @Description Log of actions performed by delegates on behalf of principals
type DelegationActivity struct {
	BaseModel
	// Delegation ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DelegationID string `gorm:"not null" json:"delegation_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Activity type (create_event, modify_event, delete_event, respond_invitation, etc.)
	// @example create_event
	ActivityType string `gorm:"not null" json:"activity_type" example:"create_event"`

	// Activity description
	// @example Created meeting "Weekly Team Sync" for 2024-01-15 10:00 AM
	Description string `gorm:"not null" json:"description" example:"Created meeting \"Weekly Team Sync\" for 2024-01-15 10:00 AM"`

	// Related event ID (if applicable)
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID *string `json:"event_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Activity metadata as JSON
	// @example {"event_title": "Weekly Team Sync", "participants": 5, "duration": 60}
	Metadata string `json:"metadata" example:"{\"event_title\": \"Weekly Team Sync\", \"participants\": 5, \"duration\": 60}"`

	// Whether the principal was notified
	// @example true
	PrincipalNotified bool `gorm:"default:false" json:"principal_notified" example:"true"`

	// When the principal was notified
	// @example 2024-01-15T10:05:00Z
	NotifiedAt *time.Time `json:"notified_at,omitempty" example:"2024-01-15T10:05:00Z"`

	// Relationships
	// @Description Associated delegation
	Delegation *CalendarDelegate `gorm:"foreignKey:DelegationID" json:"delegation,omitempty"`

	// @Description Related event (if applicable)
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`
}

// CalendarPermission represents granular permissions for calendar access
// @Description Granular permission system for calendar features
type CalendarPermission struct {
	BaseModel
	// Resource type (calendar, event, template, etc.)
	// @example calendar
	ResourceType string `gorm:"not null" json:"resource_type" example:"calendar"`

	// Resource ID (calendar ID, event ID, etc.)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ResourceID string `gorm:"not null" json:"resource_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who has the permission
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission name (view, create, edit, delete, share, delegate)
	// @example edit
	Permission string `gorm:"not null" json:"permission" example:"edit"`

	// Whether the permission is granted (true) or denied (false)
	// @example true
	IsGranted bool `gorm:"default:true" json:"is_granted" example:"true"`

	// Permission source (direct, inherited, delegated, shared)
	// @example shared
	Source string `gorm:"not null" json:"source" example:"shared"`

	// Source ID (share ID, delegation ID, etc.)
	// @example 01HXYZ123456789ABCDEFGHIJK
	SourceID *string `json:"source_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission constraints as JSON
	// @example {"time_restrictions": {"start": "09:00", "end": "17:00"}, "event_types": ["meeting"]}
	Constraints string `json:"constraints" example:"{\"time_restrictions\": {\"start\": \"09:00\", \"end\": \"17:00\"}, \"event_types\": [\"meeting\"]}"`

	// Permission expiration date
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description User with the permission
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// SharedCalendarView represents a view of shared calendars for a user
// @Description Aggregated view of all calendars shared with a user
type SharedCalendarView struct {
	// User ID
	UserID string `json:"user_id"`

	// Owned calendars (where user is the owner)
	OwnedCalendars []CalendarShare `json:"owned_calendars"`

	// Shared calendars (where user has access)
	SharedCalendars []CalendarShare `json:"shared_calendars"`

	// Active delegations (where user is the delegate)
	ActiveDelegations []CalendarDelegate `json:"active_delegations"`

	// Delegated calendars (where user is the principal)
	DelegatedCalendars []CalendarDelegate `json:"delegated_calendars"`

	// Summary statistics
	TotalSharedCalendars int `json:"total_shared_calendars"`
	TotalDelegations     int `json:"total_delegations"`
}
