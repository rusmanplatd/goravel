package requests

import (
	"time"
)

// CreateCalendarEventRequest represents the request for creating a calendar event
// @Description Request model for creating a new calendar event
type CreateCalendarEventRequest struct {
	// Event title
	// @example Team Meeting
	Title string `json:"title" binding:"required" example:"Team Meeting" validate:"required"`

	// Event description
	// @example Weekly team sync to discuss project progress
	Description string `json:"description" example:"Weekly team sync to discuss project progress"`

	// Event start time
	// @example 2024-01-15T10:00:00Z
	StartTime time.Time `json:"start_time" binding:"required" example:"2024-01-15T10:00:00Z" validate:"required"`

	// Event end time
	// @example 2024-01-15T11:00:00Z
	EndTime time.Time `json:"end_time" binding:"required" example:"2024-01-15T11:00:00Z" validate:"required"`

	// Event location
	// @example Conference Room A
	Location string `json:"location" example:"Conference Room A"`

	// Event color for calendar display
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Event type (meeting, appointment, reminder, etc.)
	// @example meeting
	Type string `json:"type" example:"meeting"`

	// Whether the event is all-day
	// @example false
	IsAllDay bool `json:"is_all_day" example:"false"`

	// Whether the event is recurring
	// @example false
	IsRecurring bool `json:"is_recurring" example:"false"`

	// Recurrence rule (RRULE format)
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	RecurrenceRule string `json:"recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// End date for recurring events
	// @example 2024-12-31T23:59:59Z
	RecurrenceUntil *time.Time `json:"recurrence_until" example:"2024-12-31T23:59:59Z"`

	// Event timezone
	// @example UTC
	Timezone string `json:"timezone" example:"UTC"`

	// Event status (scheduled, confirmed, cancelled, completed)
	// @example scheduled
	Status string `json:"status" example:"scheduled"`

	// Tenant ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `json:"tenant_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Participant user IDs
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	ParticipantIDs []string `json:"participant_ids" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]"`

	// Reminder settings (JSON format: {"email": 15, "push": 30, "sms": 60})
	// @example {"email": 15, "push": 30, "sms": 60}
	ReminderSettings string `json:"reminder_settings" example:"{\"email\": 15, \"push\": 30, \"sms\": 60}"`

	// Meeting details (optional)
	Meeting *CreateMeetingRequest `json:"meeting"`
}

// UpdateCalendarEventRequest represents the request for updating a calendar event
// @Description Request model for updating an existing calendar event
type UpdateCalendarEventRequest struct {
	// Event title
	// @example Team Meeting
	Title string `json:"title" example:"Team Meeting"`

	// Event description
	// @example Weekly team sync to discuss project progress
	Description string `json:"description" example:"Weekly team sync to discuss project progress"`

	// Event start time
	// @example 2024-01-15T10:00:00Z
	StartTime *time.Time `json:"start_time" example:"2024-01-15T10:00:00Z"`

	// Event end time
	// @example 2024-01-15T11:00:00Z
	EndTime *time.Time `json:"end_time" example:"2024-01-15T11:00:00Z"`

	// Event location
	// @example Conference Room A
	Location string `json:"location" example:"Conference Room A"`

	// Event color for calendar display
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Event type (meeting, appointment, reminder, etc.)
	// @example meeting
	Type string `json:"type" example:"meeting"`

	// Whether the event is all-day
	// @example false
	IsAllDay bool `json:"is_all_day" example:"false"`

	// Whether the event is recurring
	// @example false
	IsRecurring bool `json:"is_recurring" example:"false"`

	// Recurrence rule (RRULE format)
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	RecurrenceRule string `json:"recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// End date for recurring events
	// @example 2024-12-31T23:59:59Z
	RecurrenceUntil *time.Time `json:"recurrence_until" example:"2024-12-31T23:59:59Z"`

	// Event timezone
	// @example UTC
	Timezone string `json:"timezone" example:"UTC"`

	// Event status (scheduled, confirmed, cancelled, completed)
	// @example scheduled
	Status string `json:"status" example:"scheduled"`

	// Reminder settings (JSON format: {"email": 15, "push": 30, "sms": 60})
	// @example {"email": 15, "push": 30, "sms": 60}
	ReminderSettings string `json:"reminder_settings" example:"{\"email\": 15, \"push\": 30, \"sms\": 60}"`

	// Meeting details (optional)
	Meeting *UpdateMeetingRequest `json:"meeting"`
}

// CreateMeetingRequest represents the request for creating meeting details
// @Description Request model for creating meeting details for a calendar event
type CreateMeetingRequest struct {
	// Meeting type (video, audio, in-person, hybrid)
	// @example video
	MeetingType string `json:"meeting_type" example:"video"`

	// Meeting platform (zoom, teams, meet, etc.)
	// @example zoom
	Platform string `json:"platform" example:"zoom"`

	// Meeting URL
	// @example https://zoom.us/j/123456789
	MeetingURL string `json:"meeting_url" example:"https://zoom.us/j/123456789"`

	// Meeting ID
	// @example 123456789
	MeetingID string `json:"meeting_id" example:"123456789"`

	// Meeting passcode
	// @example 123456
	Passcode string `json:"passcode" example:"123456"`

	// Meeting notes
	// @example Agenda: 1. Project updates 2. Q&A
	MeetingNotes string `json:"meeting_notes" example:"Agenda: 1. Project updates 2. Q&A"`

	// Whether to record the meeting
	// @example false
	RecordMeeting bool `json:"record_meeting" example:"false"`

	// Whether participants can join before host
	// @example true
	AllowJoinBeforeHost bool `json:"allow_join_before_host" example:"true"`

	// Whether to mute participants on entry
	// @example false
	MuteParticipantsOnEntry bool `json:"mute_participants_on_entry" example:"false"`

	// Waiting room setting
	// @example enabled
	WaitingRoom string `json:"waiting_room" example:"enabled"`

	// Meeting status (scheduled, in-progress, completed, cancelled)
	// @example scheduled
	Status string `json:"status" example:"scheduled"`

	// Meeting attendance count
	// @example 5
	AttendanceCount int `json:"attendance_count" example:"5"`

	// Meeting notes taken during the meeting
	// @example Key decisions: 1. Project timeline approved 2. Budget increased by 10%
	MeetingMinutes string `json:"meeting_minutes" example:"Key decisions: 1. Project timeline approved 2. Budget increased by 10%"`
}

// UpdateMeetingRequest represents the request for updating meeting details
// @Description Request model for updating meeting details for a calendar event
type UpdateMeetingRequest struct {
	// Meeting type (video, audio, in-person, hybrid)
	// @example video
	MeetingType string `json:"meeting_type" example:"video"`

	// Meeting platform (zoom, teams, meet, etc.)
	// @example zoom
	Platform string `json:"platform" example:"zoom"`

	// Meeting URL
	// @example https://zoom.us/j/123456789
	MeetingURL string `json:"meeting_url" example:"https://zoom.us/j/123456789"`

	// Meeting ID
	// @example 123456789
	MeetingID string `json:"meeting_id" example:"123456789"`

	// Meeting passcode
	// @example 123456
	Passcode string `json:"passcode" example:"123456"`

	// Meeting notes
	// @example Agenda: 1. Project updates 2. Q&A
	MeetingNotes string `json:"meeting_notes" example:"Agenda: 1. Project updates 2. Q&A"`

	// Whether to record the meeting
	// @example false
	RecordMeeting bool `json:"record_meeting" example:"false"`

	// Whether participants can join before host
	// @example true
	AllowJoinBeforeHost bool `json:"allow_join_before_host" example:"true"`

	// Whether to mute participants on entry
	// @example false
	MuteParticipantsOnEntry bool `json:"mute_participants_on_entry" example:"false"`

	// Waiting room setting
	// @example enabled
	WaitingRoom string `json:"waiting_room" example:"enabled"`

	// Meeting status (scheduled, in-progress, completed, cancelled)
	// @example scheduled
	Status string `json:"status" example:"scheduled"`

	// Meeting attendance count
	// @example 5
	AttendanceCount int `json:"attendance_count" example:"5"`

	// Meeting notes taken during the meeting
	// @example Key decisions: 1. Project timeline approved 2. Budget increased by 10%
	MeetingMinutes string `json:"meeting_minutes" example:"Key decisions: 1. Project timeline approved 2. Budget increased by 10%"`
}

// AddParticipantRequest represents the request for adding a participant to an event
// @Description Request model for adding a participant to a calendar event
type AddParticipantRequest struct {
	// User ID to add as participant
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Participant role (attendee, organizer, presenter, etc.)
	// @example attendee
	Role string `json:"role" example:"attendee"`

	// Whether the participant is required
	// @example true
	IsRequired bool `json:"is_required" example:"true"`

	// Whether to send reminder to this participant
	// @example true
	SendReminder bool `json:"send_reminder" example:"true"`
}

// UpdateParticipantResponseRequest represents the request for updating participant response
// @Description Request model for updating a participant's response to an event
type UpdateParticipantResponseRequest struct {
	// Response status (pending, accepted, declined, tentative)
	// @example accepted
	ResponseStatus string `json:"response_status" binding:"required" example:"accepted" validate:"required"`

	// Response comment
	// @example I'll be 5 minutes late
	ResponseComment string `json:"response_comment" example:"I'll be 5 minutes late"`
}

// EventFilterRequest represents the request for filtering calendar events
// @Description Request model for filtering calendar events by various criteria
type EventFilterRequest struct {
	// Start date for filtering
	// @example 2024-01-01T00:00:00Z
	StartDate *time.Time `json:"start_date" example:"2024-01-01T00:00:00Z"`

	// End date for filtering
	// @example 2024-12-31T23:59:59Z
	EndDate *time.Time `json:"end_date" example:"2024-12-31T23:59:59Z"`

	// Event type filter
	// @example meeting
	Type string `json:"type" example:"meeting"`

	// Event status filter
	// @example scheduled
	Status string `json:"status" example:"scheduled"`

	// Whether to include recurring events
	// @example true
	IncludeRecurring bool `json:"include_recurring" example:"true"`

	// User ID to filter events by participant
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParticipantID string `json:"participant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Creator ID to filter events by creator
	// @example 01HXYZ123456789ABCDEFGHIJK
	CreatorID string `json:"creator_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// CreateReminderRequest represents the request for creating event reminders
// @Description Request model for creating reminders for a calendar event
type CreateReminderRequest struct {
	// User ID to send reminder to
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Reminder type (email, push, sms)
	// @example email
	Type string `json:"type" binding:"required" example:"email" validate:"required"`

	// Minutes before event to send reminder
	// @example 15
	MinutesBefore int `json:"minutes_before" binding:"required" example:"15" validate:"required"`
}

// UpdateMeetingStatusRequest represents the request for updating meeting status
// @Description Request model for updating meeting status
type UpdateMeetingStatusRequest struct {
	// Meeting status (scheduled, in-progress, completed, cancelled)
	// @example in-progress
	Status string `json:"status" binding:"required" example:"in-progress" validate:"required"`

	// Meeting attendance count
	// @example 5
	AttendanceCount int `json:"attendance_count" example:"5"`

	// Meeting notes taken during the meeting
	// @example Key decisions: 1. Project timeline approved 2. Budget increased by 10%
	MeetingMinutes string `json:"meeting_minutes" example:"Key decisions: 1. Project timeline approved 2. Budget increased by 10%"`

	// Recording URL
	// @example https://zoom.us/recording/123456789
	RecordingURL string `json:"recording_url" example:"https://zoom.us/recording/123456789"`
}

// CheckConflictsRequest represents the request for checking event conflicts
// @Description Request model for checking scheduling conflicts
type CheckConflictsRequest struct {
	// Start time for conflict check
	// @example 2024-01-15T10:00:00Z
	StartTime time.Time `json:"start_time" binding:"required" example:"2024-01-15T10:00:00Z" validate:"required"`

	// End time for conflict check
	// @example 2024-01-15T11:00:00Z
	EndTime time.Time `json:"end_time" binding:"required" example:"2024-01-15T11:00:00Z" validate:"required"`

	// User IDs to check conflicts for
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	UserIDs []string `json:"user_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`

	// Event ID to exclude from conflict check (for updates)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ExcludeEventID string `json:"exclude_event_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// ExportCalendarRequest represents the request for exporting calendar events
// @Description Request model for exporting calendar events to iCal format
type ExportCalendarRequest struct {
	// Start date for export
	// @example 2024-01-01T00:00:00Z
	StartDate time.Time `json:"start_date" binding:"required" example:"2024-01-01T00:00:00Z" validate:"required"`

	// End date for export
	// @example 2024-12-31T23:59:59Z
	EndDate time.Time `json:"end_date" binding:"required" example:"2024-12-31T23:59:59Z" validate:"required"`

	// User ID to export events for
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Whether to include recurring events
	// @example true
	IncludeRecurring bool `json:"include_recurring" example:"true"`

	// Event types to include
	// @example ["meeting", "appointment"]
	EventTypes []string `json:"event_types" example:"[\"meeting\", \"appointment\"]"`
}
