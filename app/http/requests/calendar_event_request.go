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

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

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

// EventSuggestionsRequest represents the request for getting event scheduling suggestions
// @Description Request model for getting AI-powered scheduling suggestions
type EventSuggestionsRequest struct {
	// Participant user IDs
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	ParticipantIDs []string `json:"participant_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`

	// Preferred start time for searching
	// @example 2024-01-15T09:00:00Z
	PreferredStartTime time.Time `json:"preferred_start_time" binding:"required" example:"2024-01-15T09:00:00Z" validate:"required"`

	// Preferred end time for searching
	// @example 2024-01-15T17:00:00Z
	PreferredEndTime time.Time `json:"preferred_end_time" binding:"required" example:"2024-01-15T17:00:00Z" validate:"required"`

	// Event duration
	// @example 1h30m
	Duration time.Duration `json:"duration" binding:"required" example:"1h30m" validate:"required"`

	// Minimum availability rate (0.0 to 1.0)
	// @example 0.8
	MinAvailabilityRate float64 `json:"min_availability_rate" example:"0.8"`

	// Event type for context
	// @example meeting
	EventType string `json:"event_type" example:"meeting"`

	// Preferred time zones
	// @example ["America/New_York", "Europe/London"]
	PreferredTimezones []string `json:"preferred_timezones" example:"[\"America/New_York\", \"Europe/London\"]"`

	// Working hours start (24-hour format)
	// @example 9
	WorkingHoursStart int `json:"working_hours_start" example:"9"`

	// Working hours end (24-hour format)
	// @example 17
	WorkingHoursEnd int `json:"working_hours_end" example:"17"`

	// Include weekends in suggestions
	// @example false
	IncludeWeekends bool `json:"include_weekends" example:"false"`
}

// BulkUpdateEventsRequest represents the request for bulk updating calendar events
// @Description Request model for bulk updating multiple calendar events
type BulkUpdateEventsRequest struct {
	// Event IDs to update
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	EventIDs []string `json:"event_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`

	// Fields to update
	Updates BulkEventUpdates `json:"updates"`

	// Time adjustment settings
	TimeAdjustment *TimeAdjustment `json:"time_adjustment,omitempty"`
}

// BulkEventUpdates represents the fields that can be updated in bulk
type BulkEventUpdates struct {
	// Event title
	// @example Updated Meeting Title
	Title string `json:"title" example:"Updated Meeting Title"`

	// Event description
	// @example Updated meeting description
	Description string `json:"description" example:"Updated meeting description"`

	// Event location
	// @example Updated Conference Room
	Location string `json:"location" example:"Updated Conference Room"`

	// Event color
	// @example #EF4444
	Color string `json:"color" example:"#EF4444"`

	// Event status
	// @example confirmed
	Status string `json:"status" example:"confirmed"`

	// Event type
	// @example workshop
	Type string `json:"type" example:"workshop"`
}

// TimeAdjustment represents time adjustment settings for bulk operations
type TimeAdjustment struct {
	// Adjustment type: "offset" or "set_duration"
	// @example offset
	Type string `json:"type" example:"offset"`

	// Duration for the adjustment
	// @example 1h30m
	Duration time.Duration `json:"duration" example:"1h30m"`
}

// BulkDeleteEventsRequest represents the request for bulk deleting calendar events
// @Description Request model for bulk deleting multiple calendar events
type BulkDeleteEventsRequest struct {
	// Event IDs to delete
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	EventIDs []string `json:"event_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`

	// Whether to delete recurring series (for recurring events)
	// @example false
	DeleteSeries bool `json:"delete_series" example:"false"`

	// Reason for deletion (optional)
	// @example Meeting cancelled due to schedule conflicts
	Reason string `json:"reason" example:"Meeting cancelled due to schedule conflicts"`
}

// BulkRescheduleEventsRequest represents the request for bulk rescheduling calendar events
// @Description Request model for bulk rescheduling multiple calendar events
type BulkRescheduleEventsRequest struct {
	// Event IDs to reschedule
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	EventIDs []string `json:"event_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`

	// Reschedule type: "offset", "set_start", "set_both"
	// @example offset
	RescheduleType string `json:"reschedule_type" binding:"required" example:"offset" validate:"required"`

	// Time offset for "offset" type
	// @example 2h
	TimeOffset time.Duration `json:"time_offset" example:"2h"`

	// New start time for "set_start" and "set_both" types
	// @example 2024-01-15T14:00:00Z
	NewStartTime time.Time `json:"new_start_time" example:"2024-01-15T14:00:00Z"`

	// New end time for "set_both" type
	// @example 2024-01-15T15:00:00Z
	NewEndTime time.Time `json:"new_end_time" example:"2024-01-15T15:00:00Z"`

	// Whether to check for conflicts
	// @example true
	CheckConflicts bool `json:"check_conflicts" example:"true"`

	// Whether to allow conflicts
	// @example false
	AllowConflicts bool `json:"allow_conflicts" example:"false"`

	// Whether to reschedule recurring series (for recurring events)
	// @example false
	RescheduleSeries bool `json:"reschedule_series" example:"false"`

	// Reason for rescheduling (optional)
	// @example Moved due to room availability
	Reason string `json:"reason" example:"Moved due to room availability"`
}
