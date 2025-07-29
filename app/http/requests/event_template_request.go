package requests

import (
	"time"
)

// CreateEventTemplateRequest represents the request for creating an event template
// @Description Request model for creating a new event template
type CreateEventTemplateRequest struct {
	// Template name
	// @example Weekly Team Standup
	Name string `json:"name" binding:"required" example:"Weekly Team Standup" validate:"required"`

	// Template description
	// @example Standard weekly team standup meeting template
	Description string `json:"description" example:"Standard weekly team standup meeting template"`

	// Template category (meeting, appointment, reminder, etc.)
	// @example meeting
	Category string `json:"category" example:"meeting"`

	// Template type (personal, team, organization)
	// @example team
	Type string `json:"type" example:"team"`

	// Default event duration in minutes
	// @example 30
	DefaultDuration int `json:"default_duration" binding:"required" example:"30" validate:"required"`

	// Default event color
	// @example #3B82F6
	DefaultColor string `json:"default_color" example:"#3B82F6"`

	// Default location
	// @example Conference Room A
	DefaultLocation string `json:"default_location" example:"Conference Room A"`

	// Template settings as JSON
	// @example {"allow_conflicts": false, "require_confirmation": true, "auto_schedule": false}
	Settings string `json:"settings" example:"{\"allow_conflicts\": false, \"require_confirmation\": true, \"auto_schedule\": false}"`

	// Default recurrence rule
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	DefaultRecurrenceRule string `json:"default_recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// Default reminder settings
	// @example {"email": 15, "push": 30}
	DefaultReminderSettings string `json:"default_reminder_settings" example:"{\"email\": 15, \"push\": 30}"`

	// Default participant roles as JSON
	// @example [{"role": "organizer", "required": true}, {"role": "attendee", "required": false}]
	DefaultParticipantRoles string `json:"default_participant_roles" example:"[{\"role\": \"organizer\", \"required\": true}, {\"role\": \"attendee\", \"required\": false}]"`

	// Template tags for categorization
	// @example ["standup", "agile", "team"]
	Tags string `json:"tags" example:"[\"standup\", \"agile\", \"team\"]"`

	// Whether template is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Whether template is public (can be used by others)
	// @example false
	IsPublic bool `json:"is_public" example:"false"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// UpdateEventTemplateRequest represents the request for updating an event template
// @Description Request model for updating an existing event template
type UpdateEventTemplateRequest struct {
	// Template name
	// @example Weekly Team Standup
	Name string `json:"name" example:"Weekly Team Standup"`

	// Template description
	// @example Standard weekly team standup meeting template
	Description string `json:"description" example:"Standard weekly team standup meeting template"`

	// Template category (meeting, appointment, reminder, etc.)
	// @example meeting
	Category string `json:"category" example:"meeting"`

	// Template type (personal, team, organization)
	// @example team
	Type string `json:"type" example:"team"`

	// Default event duration in minutes
	// @example 30
	DefaultDuration int `json:"default_duration" example:"30"`

	// Default event color
	// @example #3B82F6
	DefaultColor string `json:"default_color" example:"#3B82F6"`

	// Default location
	// @example Conference Room A
	DefaultLocation string `json:"default_location" example:"Conference Room A"`

	// Template settings as JSON
	// @example {"allow_conflicts": false, "require_confirmation": true, "auto_schedule": false}
	Settings string `json:"settings" example:"{\"allow_conflicts\": false, \"require_confirmation\": true, \"auto_schedule\": false}"`

	// Default recurrence rule
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	DefaultRecurrenceRule string `json:"default_recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// Default reminder settings
	// @example {"email": 15, "push": 30}
	DefaultReminderSettings string `json:"default_reminder_settings" example:"{\"email\": 15, \"push\": 30}"`

	// Default participant roles as JSON
	// @example [{"role": "organizer", "required": true}, {"role": "attendee", "required": false}]
	DefaultParticipantRoles string `json:"default_participant_roles" example:"[{\"role\": \"organizer\", \"required\": true}, {\"role\": \"attendee\", \"required\": false}]"`

	// Template tags for categorization
	// @example ["standup", "agile", "team"]
	Tags string `json:"tags" example:"[\"standup\", \"agile\", \"team\"]"`

	// Whether template is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Whether template is public (can be used by others)
	// @example false
	IsPublic bool `json:"is_public" example:"false"`
}

// CreateEventFromTemplateRequest represents the request for creating an event from a template
// @Description Request model for creating a calendar event from an existing template
type CreateEventFromTemplateRequest struct {
	// Event title (overrides template name if provided)
	// @example Team Standup - Sprint 15
	Title string `json:"title" example:"Team Standup - Sprint 15"`

	// Event description (overrides template description if provided)
	// @example Sprint 15 planning and retrospective
	Description string `json:"description" example:"Sprint 15 planning and retrospective"`

	// Event start time
	// @example 2024-01-15T10:00:00Z
	StartTime time.Time `json:"start_time" binding:"required" example:"2024-01-15T10:00:00Z" validate:"required"`

	// Event end time (optional, calculated from template duration if not provided)
	// @example 2024-01-15T10:30:00Z
	EndTime *time.Time `json:"end_time" example:"2024-01-15T10:30:00Z"`

	// Event location (overrides template location if provided)
	// @example Conference Room B
	Location string `json:"location" example:"Conference Room B"`

	// Event color (overrides template color if provided)
	// @example #EF4444
	Color string `json:"color" example:"#EF4444"`

	// Whether the event is all-day
	// @example false
	IsAllDay bool `json:"is_all_day" example:"false"`

	// Whether the event is recurring
	// @example true
	IsRecurring bool `json:"is_recurring" example:"true"`

	// Recurrence rule (overrides template recurrence if provided)
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	RecurrenceRule string `json:"recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// End date for recurring events
	// @example 2024-12-31T23:59:59Z
	RecurrenceUntil *time.Time `json:"recurrence_until" example:"2024-12-31T23:59:59Z"`

	// Event timezone
	// @example UTC
	Timezone string `json:"timezone" example:"UTC"`

	// Reminder settings (overrides template reminders if provided)
	// @example {"email": 10, "push": 15}
	ReminderSettings string `json:"reminder_settings" example:"{\"email\": 10, \"push\": 15}"`

	// Participant user IDs
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	ParticipantIDs []string `json:"participant_ids" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]"`

	// User ID creating the event
	// @example 01HXYZ123456789ABCDEFGHIJK
	CreatedBy string `json:"created_by" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}
