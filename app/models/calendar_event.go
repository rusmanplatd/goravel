package models

import (
	"encoding/json"
	"time"
)

// CalendarEvent represents a calendar event
// @Description Calendar event model with support for recurring events and participants
type CalendarEvent struct {
	BaseModel
	// Event title
	// @example Team Meeting
	Title string `gorm:"not null" json:"title" example:"Team Meeting"`

	// Event description
	// @example Weekly team sync to discuss project progress
	Description string `json:"description" example:"Weekly team sync to discuss project progress"`

	// Event start time
	// @example 2024-01-15T10:00:00Z
	StartTime time.Time `gorm:"not null" json:"start_time" example:"2024-01-15T10:00:00Z"`

	// Event end time
	// @example 2024-01-15T11:00:00Z
	EndTime time.Time `gorm:"not null" json:"end_time" example:"2024-01-15T11:00:00Z"`

	// Event location
	// @example Conference Room A
	Location string `json:"location" example:"Conference Room A"`

	// Event color for calendar display
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Event type (meeting, appointment, reminder, etc.)
	// @example meeting
	Type string `gorm:"default:'event'" json:"type" example:"meeting"`

	// Whether the event is all-day
	// @example false
	IsAllDay bool `gorm:"default:false" json:"is_all_day" example:"false"`

	// Whether the event is recurring
	// @example false
	IsRecurring bool `gorm:"default:false" json:"is_recurring" example:"false"`

	// Recurrence rule (RRULE format)
	// @example FREQ=WEEKLY;INTERVAL=1;BYDAY=MO
	RecurrenceRule string `json:"recurrence_rule" example:"FREQ=WEEKLY;INTERVAL=1;BYDAY=MO"`

	// End date for recurring events
	// @example 2024-12-31T23:59:59Z
	RecurrenceUntil *time.Time `json:"recurrence_until,omitempty" example:"2024-12-31T23:59:59Z"`

	// Event timezone
	// @example UTC
	Timezone string `gorm:"default:'UTC'" json:"timezone" example:"UTC"`

	// Event status (scheduled, confirmed, cancelled, completed)
	// @example scheduled
	Status string `gorm:"default:'scheduled'" json:"status" example:"scheduled"`

	// Calendar type/category for organizing events
	// @example personal
	CalendarType string `gorm:"default:'personal'" json:"calendar_type" example:"personal"`

	// Event visibility (public, private, confidential)
	// @example private
	Visibility string `gorm:"default:'private'" json:"visibility" example:"private"`

	// Quick add natural language input (for future processing)
	// @example "Meeting with John tomorrow at 2pm"
	QuickAddText string `json:"quick_add_text,omitempty" example:"Meeting with John tomorrow at 2pm"`

	// Event priority (low, normal, high, urgent)
	// @example normal
	Priority string `gorm:"default:'normal'" json:"priority" example:"normal"`

	// Whether the event can be edited by attendees
	// @example false
	AllowGuestEdit bool `gorm:"default:false" json:"allow_guest_edit" example:"false"`

	// Whether attendees can invite others
	// @example false
	AllowGuestInvite bool `gorm:"default:false" json:"allow_guest_invite" example:"false"`

	// Whether attendees list is visible to all
	// @example true
	ShowGuestList bool `gorm:"default:true" json:"show_guest_list" example:"true"`

	// Maximum number of attendees
	// @example 50
	MaxAttendees int `gorm:"default:0" json:"max_attendees" example:"50"`

	// Event source (manual, imported, synced)
	// @example manual
	Source string `gorm:"default:'manual'" json:"source" example:"manual"`

	// External event ID for synced events
	// @example google_cal_123456789
	ExternalEventID string `json:"external_event_id,omitempty" example:"google_cal_123456789"`

	// External calendar ID for synced events
	// @example primary
	ExternalCalendarID string `json:"external_calendar_id,omitempty" example:"primary"`

	// Reminder settings (JSON format: {"email": 15, "push": 30, "sms": 60})
	// @example {"email": 15, "push": 30, "sms": 60}
	ReminderSettings string `json:"reminder_settings" example:"{\"email\": 15, \"push\": 30, \"sms\": 60}"`

	// Whether reminders have been sent
	// @example false
	RemindersSent bool `gorm:"default:false" json:"reminders_sent" example:"false"`

	// When reminders were last sent
	// @example 2024-01-15T09:00:00Z
	RemindersSentAt *time.Time `json:"reminders_sent_at,omitempty" example:"2024-01-15T09:00:00Z"`

	// Tenant ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"not null" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent event ID for recurring event instances
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentEventID *string `json:"parent_event_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Template ID if created from template
	// @example 01HXYZ123456789ABCDEFGHIJK
	TemplateID *string `json:"template_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Calendar ID (references UserCalendar)
	// @example 01HXYZ123456789ABCDEFGHIJK
	CalendarID *string `json:"calendar_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Event's associated tenant
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Event's associated calendar
	Calendar *UserCalendar `gorm:"foreignKey:CalendarID" json:"calendar,omitempty"`

	// @Description Parent event for recurring instances
	ParentEvent *CalendarEvent `gorm:"foreignKey:ParentEventID" json:"parent_event,omitempty"`

	// @Description Recurring event instances
	RecurringInstances []CalendarEvent `gorm:"foreignKey:ParentEventID" json:"recurring_instances,omitempty"`

	// @Description Event participants
	Participants []EventParticipant `gorm:"foreignKey:EventID" json:"participants,omitempty"`

	// @Description Associated meeting details
	Meeting *Meeting `gorm:"foreignKey:EventID" json:"meeting,omitempty"`

	// @Description Template used to create this event
	Template *EventTemplate `gorm:"foreignKey:TemplateID" json:"template,omitempty"`
}

// EventParticipant represents a participant in a calendar event
// @Description Event participant with response status and role
type EventParticipant struct {
	BaseModel
	// Event ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID string `gorm:"not null" json:"event_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Participant role (attendee, organizer, presenter, etc.)
	// @example attendee
	Role string `gorm:"default:'attendee'" json:"role" example:"attendee"`

	// Response status (pending, accepted, declined, tentative)
	// @example pending
	ResponseStatus string `gorm:"default:'pending'" json:"response_status" example:"pending"`

	// When the participant responded
	// @example 2024-01-15T09:30:00Z
	RespondedAt *time.Time `json:"responded_at,omitempty" example:"2024-01-15T09:30:00Z"`

	// Response comment
	// @example I'll be 5 minutes late
	ResponseComment string `json:"response_comment" example:"I'll be 5 minutes late"`

	// Whether the participant is required
	// @example true
	IsRequired bool `gorm:"default:true" json:"is_required" example:"true"`

	// Whether to send reminder to this participant
	// @example true
	SendReminder bool `gorm:"default:true" json:"send_reminder" example:"true"`

	// When the reminder was sent
	// @example 2024-01-15T09:00:00Z
	ReminderSentAt *time.Time `json:"reminder_sent_at,omitempty" example:"2024-01-15T09:00:00Z"`

	// Relationships
	// @Description Associated event
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`

	// @Description Participant user
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// Meeting represents meeting-specific details for calendar events
// @Description Meeting details with Microsoft Teams onlineMeeting compatibility
type Meeting struct {
	BaseModel

	// Core meeting properties (Teams-compatible)
	// Associated event ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID string `gorm:"not null" json:"event_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Meeting subject/title
	// @example Team Standup Meeting
	Subject string `json:"subject" example:"Team Standup Meeting"`

	// Meeting start time
	// @example 2024-01-15T10:00:00Z
	StartDateTime *time.Time `json:"start_date_time" example:"2024-01-15T10:00:00Z"`

	// Meeting end time
	// @example 2024-01-15T11:00:00Z
	EndDateTime *time.Time `json:"end_date_time" example:"2024-01-15T11:00:00Z"`

	// Meeting creation time in UTC (read-only)
	// @example 2024-01-15T09:00:00Z
	CreationDateTime *time.Time `json:"creation_date_time,omitempty" example:"2024-01-15T09:00:00Z"`

	// Meeting URL/Join URL (read-only)
	// @example https://teams.microsoft.com/l/meetup-join/...
	JoinWebUrl string `json:"join_web_url" example:"https://teams.microsoft.com/l/meetup-join/..."`

	// Video teleconference ID for external systems (read-only)
	// @example 123456789
	VideoTeleconferenceId string `json:"video_teleconference_id" example:"123456789"`

	// External ID for custom identification
	// @example custom-meeting-001
	ExternalId string `json:"external_id,omitempty" example:"custom-meeting-001"`

	// Teams-specific meeting permissions and settings
	// Whether attendees can turn on their camera
	// @example true
	AllowAttendeeToEnableCamera bool `gorm:"default:true" json:"allow_attendee_to_enable_camera" example:"true"`

	// Whether attendees can turn on their microphone
	// @example true
	AllowAttendeeToEnableMic bool `gorm:"default:true" json:"allow_attendee_to_enable_mic" example:"true"`

	// Whether breakout rooms are enabled
	// @example false
	AllowBreakoutRooms bool `gorm:"default:false" json:"allow_breakout_rooms" example:"false"`

	// Whether copying and sharing meeting content is enabled
	// @example true
	AllowCopyingAndSharingMeetingContent bool `gorm:"default:true" json:"allow_copying_and_sharing_meeting_content" example:"true"`

	// Whether live share is enabled (enabled, disabled, unknownFutureValue)
	// @example enabled
	AllowLiveShare string `gorm:"default:'enabled'" json:"allow_live_share" example:"enabled"`

	// Meeting chat mode (enabled, disabled, limited, unknownFutureValue)
	// @example enabled
	AllowMeetingChat string `gorm:"default:'enabled'" json:"allow_meeting_chat" example:"enabled"`

	// Whether participants can change their name
	// @example true
	AllowParticipantsToChangeName bool `gorm:"default:true" json:"allow_participants_to_change_name" example:"true"`

	// Whether PowerPoint sharing is allowed
	// @example true
	AllowPowerPointSharing bool `gorm:"default:true" json:"allow_power_point_sharing" example:"true"`

	// Whether recording is enabled for the meeting
	// @example false
	AllowRecording bool `gorm:"default:false" json:"allow_recording" example:"false"`

	// Whether Teams reactions are enabled
	// @example true
	AllowTeamworkReactions bool `gorm:"default:true" json:"allow_teamwork_reactions" example:"true"`

	// Whether transcription is enabled
	// @example false
	AllowTranscription bool `gorm:"default:false" json:"allow_transcription" example:"false"`

	// Whether whiteboard is enabled
	// @example true
	AllowWhiteboard bool `gorm:"default:true" json:"allow_whiteboard" example:"true"`

	// Who can be a presenter (everyone, organization, roleIsPresenter, organizer, unknownFutureValue)
	// @example everyone
	AllowedPresenters string `gorm:"default:'everyone'" json:"allowed_presenters" example:"everyone"`

	// Specifies the users who can admit from lobby (organizerAndCoOrganizersAndPresenters, organizerAndCoOrganizers, unknownFutureValue)
	// @example organizerAndCoOrganizers
	AllowedLobbyAdmitters string `gorm:"default:'organizerAndCoOrganizers'" json:"allowed_lobby_admitters" example:"organizerAndCoOrganizers"`

	// Specifies whose identity is anonymized (attendee)
	// @example []
	AnonymizeIdentityForRoles string `json:"anonymize_identity_for_roles,omitempty"`

	// Whether end-to-end encryption is enabled
	// @example false
	IsEndToEndEncryptionEnabled bool `gorm:"default:false" json:"is_end_to_end_encryption_enabled" example:"false"`

	// Whether to announce when callers join or leave
	// @example true
	IsEntryExitAnnounced bool `gorm:"default:true" json:"is_entry_exit_announced" example:"true"`

	// Whether to record the meeting automatically
	// @example false
	RecordAutomatically bool `gorm:"default:false" json:"record_automatically" example:"false"`

	// Meeting chat history sharing mode (all, none, unknownFutureValue)
	// @example all
	ShareMeetingChatHistoryDefault string `gorm:"default:'all'" json:"share_meeting_chat_history_default" example:"all"`

	// Watermark protection settings (enabled, disabled, unknownFutureValue)
	// @example disabled
	WatermarkProtection string `gorm:"default:'disabled'" json:"watermark_protection" example:"disabled"`

	// Meeting template ID for consistent setups
	// @example template-001
	MeetingTemplateId string `json:"meeting_template_id,omitempty" example:"template-001"`

	// Lobby bypass settings (JSON structure)
	// Lobby bypass scope (everyone, organization, organizer)
	// @example organization
	LobbyBypassScope string `gorm:"default:'organization'" json:"lobby_bypass_scope" example:"organization"`

	// Whether dial-in users can bypass the lobby
	// @example false
	IsDialInBypassEnabled bool `gorm:"default:false" json:"is_dial_in_bypass_enabled" example:"false"`

	// Join meeting ID settings (JSON structure)
	// Join meeting ID for dial-in
	// @example 1234567890
	JoinMeetingId string `json:"join_meeting_id" example:"1234567890"`

	// Meeting passcode
	// @example 123456
	Passcode string `json:"passcode,omitempty" example:"123456"`

	// Whether passcode is required for joining
	// @example false
	IsPasscodeRequired bool `gorm:"default:false" json:"is_passcode_required" example:"false"`

	// Audio conferencing settings (JSON structure)
	// Audio conferencing information
	// @example {"tollNumber": "+1-555-0123", "tollFreeNumber": "+1-800-555-0123", "conferenceId": "123456789"}
	AudioConferencingJSON string `gorm:"type:json" json:"-"`

	// Chat information (JSON structure)
	// Chat thread ID and message ID
	// @example {"threadId": "19:meeting_abc123@thread.v2", "messageId": "1234567890"}
	ChatInfoJSON string `gorm:"type:json" json:"-"`

	// Chat restrictions (JSON structure)
	// Meeting chat restrictions configuration
	// @example {"allowedChatTypes": ["all"], "restrictedUsers": []}
	ChatRestrictionsJSON string `gorm:"type:json" json:"-"`

	// Join information in localized format (read-only)
	// @example "Join Microsoft Teams Meeting..."
	JoinInformation string `json:"join_information,omitempty"`

	// Meeting status and tracking
	// Meeting status (scheduled, in_progress, completed, cancelled)
	// @example scheduled
	Status string `gorm:"default:'scheduled'" json:"status" example:"scheduled"`

	// When the meeting actually started
	// @example 2024-01-15T10:00:00Z
	StartedAt *time.Time `json:"started_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// When the meeting actually ended
	// @example 2024-01-15T11:00:00Z
	EndedAt *time.Time `json:"ended_at,omitempty" example:"2024-01-15T11:00:00Z"`

	// Meeting attendance count
	// @example 5
	AttendanceCount int `gorm:"default:0" json:"attendance_count" example:"5"`

	// Whether the meeting has conflicts with other meetings
	// @example false
	HasConflicts bool `gorm:"default:false" json:"has_conflicts" example:"false"`

	// Conflict details (JSON format with conflicting event IDs)
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	ConflictDetails string `json:"conflict_details,omitempty" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]"`

	// Legacy/Additional fields for backward compatibility
	// Meeting type (video, audio, in-person, hybrid)
	// @example video
	MeetingType string `gorm:"default:'video'" json:"meeting_type,omitempty" example:"video"`

	// Meeting platform (teams is default for Teams-compatible meetings)
	// @example teams
	Platform string `gorm:"default:'teams'" json:"platform,omitempty" example:"teams"`

	// Meeting notes/description
	// @example Agenda: 1. Project updates 2. Q&A
	MeetingNotes string `json:"meeting_notes,omitempty" example:"Agenda: 1. Project updates 2. Q&A"`

	// Meeting notes taken during the meeting
	// @example Key decisions: 1. Project timeline approved 2. Budget increased by 10%
	MeetingMinutes string `json:"meeting_minutes,omitempty" example:"Key decisions: 1. Project timeline approved 2. Budget increased by 10%"`

	// Recording URL
	// @example https://teams.microsoft.com/recording/123456789
	RecordingURL string `json:"recording_url,omitempty" example:"https://teams.microsoft.com/recording/123456789"`

	// Relationships
	// @Description Associated calendar event
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`

	// @Description Meeting participants with organizer and attendees
	Participants []MeetingParticipant `gorm:"foreignKey:MeetingID" json:"participants,omitempty"`

	// @Description Meeting chat messages
	ChatMessages []MeetingChat `gorm:"foreignKey:MeetingID" json:"chat_messages,omitempty"`

	// @Description Meeting breakout rooms
	BreakoutRooms []MeetingBreakoutRoom `gorm:"foreignKey:MeetingID" json:"breakout_rooms,omitempty"`

	// @Description Meeting recordings with transcripts and AI insights
	Recordings []MeetingRecording `gorm:"foreignKey:MeetingID" json:"recordings,omitempty"`

	// @Description Meeting transcripts
	Transcripts []MeetingTranscript `gorm:"foreignKey:MeetingID" json:"transcripts,omitempty"`

	// @Description Meeting attendance reports
	AttendanceReports []MeetingAttendanceReport `gorm:"foreignKey:MeetingID" json:"attendance_reports,omitempty"`

	// @Description AI-generated meeting summaries and insights
	AISummaries []MeetingSummary `gorm:"foreignKey:MeetingID" json:"ai_summaries,omitempty"`

	// @Description Meeting metrics and analytics
	Metrics []MeetingMetric `gorm:"foreignKey:MeetingID" json:"metrics,omitempty"`

	// @Description Meeting security events
	SecurityEvents []MeetingSecurityEvent `gorm:"foreignKey:MeetingID" json:"security_events,omitempty"`

	// @Description Meeting polls
	Polls []MeetingPoll `gorm:"foreignKey:MeetingID" json:"polls,omitempty"`

	// @Description Meeting whiteboards
	Whiteboards []MeetingWhiteboard `gorm:"foreignKey:MeetingID" json:"whiteboards,omitempty"`

	// @Description Waiting room participants
	WaitingRoomParticipants []MeetingWaitingRoomParticipant `gorm:"foreignKey:MeetingID" json:"waiting_room_participants,omitempty"`
}

// MeetingTranscript represents a meeting transcript
// @Description Meeting transcript with content and metadata
type MeetingTranscript struct {
	BaseModel
	// Meeting ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Transcript content type (text, vtt, srt)
	// @example text
	ContentType string `gorm:"default:'text'" json:"content_type" example:"text"`

	// Transcript content
	// @example "00:00:10 John: Welcome everyone to today's meeting..."
	Content string `json:"content" example:"00:00:10 John: Welcome everyone to today's meeting..."`

	// Transcript language
	// @example en-US
	Language string `gorm:"default:'en-US'" json:"language" example:"en-US"`

	// Transcript status (processing, completed, failed)
	// @example completed
	Status string `gorm:"default:'processing'" json:"status" example:"completed"`

	// Download URL for the transcript
	// @example https://teams.microsoft.com/transcript/123456789
	DownloadUrl string `json:"download_url" example:"https://teams.microsoft.com/transcript/123456789"`

	// File size in bytes
	// @example 1024
	FileSize int64 `json:"file_size" example:"1024"`

	// Duration in seconds
	// @example 3600
	Duration int `json:"duration" example:"3600"`

	// Relationship
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// MeetingAttendanceReport represents a meeting attendance report
// @Description Meeting attendance report with participant details
type MeetingAttendanceReport struct {
	BaseModel
	// Meeting ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Report title
	// @example Weekly Team Meeting - Attendance Report
	Title string `json:"title" example:"Weekly Team Meeting - Attendance Report"`

	// Total participants count
	// @example 15
	TotalParticipants int `json:"total_participants" example:"15"`

	// Unique participants count (excluding duplicates)
	// @example 12
	UniqueParticipants int `json:"unique_participants" example:"12"`

	// Report generation status (processing, completed, failed)
	// @example completed
	Status string `gorm:"default:'processing'" json:"status" example:"completed"`

	// Download URL for the report
	// @example https://teams.microsoft.com/attendance/123456789
	DownloadUrl string `json:"download_url" example:"https://teams.microsoft.com/attendance/123456789"`

	// Report format (csv, json, pdf)
	// @example csv
	Format string `gorm:"default:'csv'" json:"format" example:"csv"`

	// File size in bytes
	// @example 2048
	FileSize int64 `json:"file_size" example:"2048"`

	// Report data as JSON
	// @example {"participants": [{"name": "John Doe", "join_time": "10:00", "leave_time": "11:00"}]}
	ReportData string `json:"report_data" example:"{\"participants\": [{\"name\": \"John Doe\", \"join_time\": \"10:00\", \"leave_time\": \"11:00\"}]}"`

	// Relationship
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// EventReminder represents a reminder for a calendar event
// @Description Event reminder with delivery status and timing
type EventReminder struct {
	BaseModel
	// Event ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID string `gorm:"not null" json:"event_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID to send reminder to
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Reminder type (email, push, sms)
	// @example email
	Type string `gorm:"not null" json:"type" example:"email"`

	// Minutes before event to send reminder
	// @example 15
	MinutesBefore int `gorm:"not null" json:"minutes_before" example:"15"`

	// When the reminder should be sent
	// @example 2024-01-15T09:45:00Z
	ScheduledAt time.Time `gorm:"not null" json:"scheduled_at" example:"2024-01-15T09:45:00Z"`

	// Whether the reminder has been sent
	// @example false
	Sent bool `gorm:"default:false" json:"sent" example:"false"`

	// When the reminder was sent
	// @example 2024-01-15T09:45:00Z
	SentAt *time.Time `json:"sent_at,omitempty" example:"2024-01-15T09:45:00Z"`

	// Reminder delivery status (pending, sent, failed, cancelled)
	// @example pending
	Status string `gorm:"default:'pending'" json:"status" example:"pending"`

	// Error message if reminder failed
	// @example Failed to send email
	ErrorMessage string `json:"error_message" example:"Failed to send email"`

	// Relationships
	// @Description Associated calendar event
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`

	// @Description User to receive reminder
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// MeetingParticipant represents a participant in a meeting
// @Description Meeting participant with real-time status and controls
type MeetingParticipant struct {
	BaseModel
	// Meeting ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Participant role (host, co-host, presenter, attendee)
	// @example host
	Role string `gorm:"default:'attendee'" json:"role" example:"host"`

	// Participant status (invited, joined, left, removed)
	// @example joined
	Status string `gorm:"default:'invited'" json:"status" example:"joined"`

	// Whether participant is muted
	// @example false
	IsMuted bool `gorm:"default:false" json:"is_muted" example:"false"`

	// Whether participant has video enabled
	// @example true
	IsVideoEnabled bool `gorm:"default:true" json:"is_video_enabled" example:"true"`

	// Whether participant is screen sharing
	// @example false
	IsScreenSharing bool `gorm:"default:false" json:"is_screen_sharing" example:"false"`

	// Whether participant has hand raised
	// @example false
	IsHandRaised bool `gorm:"default:false" json:"is_hand_raised" example:"false"`

	// Whether participant is in waiting room
	// @example false
	IsInWaitingRoom bool `gorm:"default:false" json:"is_in_waiting_room" example:"false"`

	// Whether participant consented to recording
	// @example true
	IsRecordingConsentGiven bool `gorm:"default:false" json:"is_recording_consent_given" example:"true"`

	// WebSocket connection ID
	// @example conn_123456789
	ConnectionID string `json:"connection_id" example:"conn_123456789"`

	// Device type (desktop, mobile, tablet)
	// @example desktop
	DeviceType string `json:"device_type" example:"desktop"`

	// Browser information
	// @example Chrome/91.0.4472.124
	BrowserInfo string `json:"browser_info" example:"Chrome/91.0.4472.124"`

	// IP address
	// @example 192.168.1.100
	IPAddress string `json:"ip_address" example:"192.168.1.100"`

	// When participant joined
	// @example 2024-01-15T10:05:00Z
	JoinedAt *time.Time `json:"joined_at,omitempty" example:"2024-01-15T10:05:00Z"`

	// When participant left
	// @example 2024-01-15T11:00:00Z
	LeftAt *time.Time `json:"left_at,omitempty" example:"2024-01-15T11:00:00Z"`

	// Total time spent in meeting (seconds)
	// @example 3300
	DurationSeconds int `gorm:"default:0" json:"duration_seconds" example:"3300"`

	// Connection quality metrics as JSON
	// @example {"latency": 50, "bandwidth": 1000, "packet_loss": 0.1}
	ConnectionQuality string `json:"connection_quality" example:"{\"latency\": 50, \"bandwidth\": 1000, \"packet_loss\": 0.1}"`

	// Participant permissions as JSON
	// @example {"can_share_screen": true, "can_chat": true, "can_unmute": true}
	Permissions string `json:"permissions" example:"{\"can_share_screen\": true, \"can_chat\": true, \"can_unmute\": true}"`

	// Relationships
	// @Description Associated meeting
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description Participant user
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// MeetingChat represents a chat message in a meeting
// @Description Meeting chat message with real-time delivery
type MeetingChat struct {
	BaseModel
	// Meeting ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Sender ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	SenderID string `gorm:"not null" json:"sender_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Recipient ID for private messages (null for public)
	// @example 01HXYZ123456789ABCDEFGHIJK
	RecipientID *string `json:"recipient_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Message type (text, file, reaction, system)
	// @example text
	MessageType string `gorm:"default:'text'" json:"message_type" example:"text"`

	// Message content
	// @example Hello everyone!
	Content string `json:"content" example:"Hello everyone!"`

	// Message metadata as JSON
	// @example {"reply_to": "01HXYZ123456789ABCDEFGHIJK", "mentions": ["01HXYZ123456789ABCDEFGHIJK"]}
	Metadata string `json:"metadata" example:"{\"reply_to\": \"01HXYZ123456789ABCDEFGHIJK\", \"mentions\": [\"01HXYZ123456789ABCDEFGHIJK\"]}"`

	// File URL for file messages
	// @example https://storage.example.com/files/document.pdf
	FileURL string `json:"file_url" example:"https://storage.example.com/files/document.pdf"`

	// Original file name
	// @example document.pdf
	FileName string `json:"file_name" example:"document.pdf"`

	// File MIME type
	// @example application/pdf
	FileType string `json:"file_type" example:"application/pdf"`

	// File size in bytes
	// @example 1024000
	FileSize int `json:"file_size" example:"1024000"`

	// Whether message is private
	// @example false
	IsPrivate bool `gorm:"default:false" json:"is_private" example:"false"`

	// Whether message is system generated
	// @example false
	IsSystem bool `gorm:"default:false" json:"is_system" example:"false"`

	// Whether message has been edited
	// @example false
	IsEdited bool `gorm:"default:false" json:"is_edited" example:"false"`

	// When message was last edited
	// @example 2024-01-15T10:15:00Z
	EditedAt *time.Time `json:"edited_at,omitempty" example:"2024-01-15T10:15:00Z"`

	// Message status (sent, delivered, read)
	// @example delivered
	Status string `gorm:"default:'sent'" json:"status" example:"delivered"`

	// When message was read
	// @example 2024-01-15T10:16:00Z
	ReadAt *time.Time `json:"read_at,omitempty" example:"2024-01-15T10:16:00Z"`

	// Relationships
	// @Description Associated meeting
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description Message sender
	Sender *User `gorm:"foreignKey:SenderID" json:"sender,omitempty"`

	// @Description Message recipient (for private messages)
	Recipient *User `gorm:"foreignKey:RecipientID" json:"recipient,omitempty"`
}

// MeetingBreakoutRoom represents a breakout room in a meeting
// @Description Meeting breakout room for splitting participants into smaller groups
type MeetingBreakoutRoom struct {
	BaseModel
	// Meeting ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Room name
	// @example Breakout Room 1
	Name string `gorm:"not null" json:"name" example:"Breakout Room 1"`

	// Room description
	// @example Discussion group for project planning
	Description string `json:"description" example:"Discussion group for project planning"`

	// Maximum participants allowed
	// @example 5
	Capacity int `gorm:"default:0" json:"capacity" example:"5"`

	// Room status (active, closed, paused)
	// @example active
	Status string `gorm:"default:'active'" json:"status" example:"active"`

	// Whether to auto-assign participants
	// @example false
	AutoAssign bool `gorm:"default:false" json:"auto_assign" example:"false"`

	// Whether participants can choose rooms
	// @example true
	AllowParticipantsToChoose bool `gorm:"default:true" json:"allow_participants_to_choose" example:"true"`

	// Whether participants can return to main room
	// @example true
	AllowParticipantsToReturn bool `gorm:"default:true" json:"allow_participants_to_return" example:"true"`

	// Time limit in minutes (0 for unlimited)
	// @example 30
	TimeLimitMinutes int `gorm:"default:0" json:"time_limit_minutes" example:"30"`

	// When breakout room started
	// @example 2024-01-15T10:30:00Z
	StartedAt *time.Time `json:"started_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// When breakout room ended
	// @example 2024-01-15T11:00:00Z
	EndedAt *time.Time `json:"ended_at,omitempty" example:"2024-01-15T11:00:00Z"`

	// Room settings as JSON
	// @example {"allow_chat": true, "allow_screen_share": false, "auto_close": true}
	Settings string `json:"settings" example:"{\"allow_chat\": true, \"allow_screen_share\": false, \"auto_close\": true}"`

	// Relationships
	// @Description Associated meeting
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description Breakout room participants
	Participants []BreakoutRoomParticipant `gorm:"foreignKey:BreakoutRoomID" json:"participants,omitempty"`
}

// BreakoutRoomParticipant represents a participant in a breakout room
// @Description Breakout room participant assignment and status
type BreakoutRoomParticipant struct {
	BaseModel
	// Breakout room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	BreakoutRoomID string `gorm:"not null" json:"breakout_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Meeting participant ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingParticipantID string `gorm:"not null" json:"meeting_participant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Assignment type (manual, auto, self-selected)
	// @example manual
	AssignmentType string `gorm:"default:'manual'" json:"assignment_type" example:"manual"`

	// Participant status (assigned, joined, left)
	// @example joined
	Status string `gorm:"default:'assigned'" json:"status" example:"joined"`

	// When participant joined breakout room
	// @example 2024-01-15T10:31:00Z
	JoinedAt *time.Time `json:"joined_at,omitempty" example:"2024-01-15T10:31:00Z"`

	// When participant left breakout room
	// @example 2024-01-15T10:59:00Z
	LeftAt *time.Time `json:"left_at,omitempty" example:"2024-01-15T10:59:00Z"`

	// Time spent in breakout room (seconds)
	// @example 1680
	DurationSeconds int `gorm:"default:0" json:"duration_seconds" example:"1680"`

	// Relationships
	// @Description Associated breakout room
	BreakoutRoom *MeetingBreakoutRoom `gorm:"foreignKey:BreakoutRoomID" json:"breakout_room,omitempty"`

	// @Description Associated meeting participant
	MeetingParticipant *MeetingParticipant `gorm:"foreignKey:MeetingParticipantID" json:"meeting_participant,omitempty"`
}

// EventTemplate represents a reusable event template
// @Description Event template for creating recurring patterns and standardized events
type EventTemplate struct {
	BaseModel
	// Template name
	// @example Weekly Team Standup
	Name string `gorm:"not null" json:"name" example:"Weekly Team Standup"`

	// Template description
	// @example Standard weekly team standup meeting template
	Description string `json:"description" example:"Standard weekly team standup meeting template"`

	// Template category (meeting, appointment, reminder, etc.)
	// @example meeting
	Category string `gorm:"default:'meeting'" json:"category" example:"meeting"`

	// Template type (personal, team, organization)
	// @example team
	Type string `gorm:"default:'personal'" json:"type" example:"team"`

	// Default event duration in minutes
	// @example 30
	DefaultDuration int `gorm:"not null" json:"default_duration" example:"30"`

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
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether template is public (can be used by others)
	// @example false
	IsPublic bool `gorm:"default:false" json:"is_public" example:"false"`

	// Usage count
	// @example 25
	UsageCount int `gorm:"default:0" json:"usage_count" example:"25"`

	// Last used date
	// @example 2024-01-15T10:00:00Z
	LastUsedAt *time.Time `json:"last_used_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Tenant ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"not null" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Template's associated tenant
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Events created from this template
	Events []CalendarEvent `gorm:"foreignKey:TemplateID" json:"events,omitempty"`
}

// Teams-compatible helper structs
// AudioConferencing represents phone access information for online meetings
type AudioConferencing struct {
	TollNumber     string `json:"toll_number,omitempty"`
	TollFreeNumber string `json:"toll_free_number,omitempty"`
	ConferenceId   string `json:"conference_id,omitempty"`
	DialinUrl      string `json:"dialin_url,omitempty"`
}

// ChatInfo represents chat information associated with the meeting
type ChatInfo struct {
	ThreadId  string `json:"thread_id,omitempty"`
	MessageId string `json:"message_id,omitempty"`
}

// ChatRestrictions represents meeting chat restrictions configuration
type ChatRestrictions struct {
	AllowedChatTypes []string `json:"allowed_chat_types,omitempty"`
	RestrictedUsers  []string `json:"restricted_users,omitempty"`
}

// LobbyBypassSettings represents lobby bypass configuration
type LobbyBypassSettings struct {
	Scope                 string `json:"scope"` // everyone, organization, organizer
	IsDialInBypassEnabled bool   `json:"is_dial_in_bypass_enabled"`
}

// JoinMeetingIdSettings represents join meeting ID configuration
type JoinMeetingIdSettings struct {
	JoinMeetingId      string `json:"join_meeting_id,omitempty"`
	Passcode           string `json:"passcode,omitempty"`
	IsPasscodeRequired bool   `json:"is_passcode_required"`
}

// MeetingParticipants represents the participants in a meeting (Teams structure)
type MeetingParticipants struct {
	Organizer    *MeetingParticipant  `json:"organizer,omitempty"`
	Attendees    []MeetingParticipant `json:"attendees,omitempty"`
	Producers    []MeetingParticipant `json:"producers,omitempty"`
	Contributors []MeetingParticipant `json:"contributors,omitempty"`
}

// Helper methods for JSON marshaling/unmarshaling
func (m *Meeting) GetAudioConferencing() *AudioConferencing {
	if m.AudioConferencingJSON == "" {
		return nil
	}
	var ac AudioConferencing
	if err := json.Unmarshal([]byte(m.AudioConferencingJSON), &ac); err != nil {
		return nil
	}
	return &ac
}

func (m *Meeting) SetAudioConferencing(ac *AudioConferencing) error {
	if ac == nil {
		m.AudioConferencingJSON = ""
		return nil
	}
	data, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	m.AudioConferencingJSON = string(data)
	return nil
}

func (m *Meeting) GetChatInfo() *ChatInfo {
	if m.ChatInfoJSON == "" {
		return nil
	}
	var ci ChatInfo
	if err := json.Unmarshal([]byte(m.ChatInfoJSON), &ci); err != nil {
		return nil
	}
	return &ci
}

func (m *Meeting) SetChatInfo(ci *ChatInfo) error {
	if ci == nil {
		m.ChatInfoJSON = ""
		return nil
	}
	data, err := json.Marshal(ci)
	if err != nil {
		return err
	}
	m.ChatInfoJSON = string(data)
	return nil
}

func (m *Meeting) GetChatRestrictions() *ChatRestrictions {
	if m.ChatRestrictionsJSON == "" {
		return nil
	}
	var cr ChatRestrictions
	if err := json.Unmarshal([]byte(m.ChatRestrictionsJSON), &cr); err != nil {
		return nil
	}
	return &cr
}

func (m *Meeting) SetChatRestrictions(cr *ChatRestrictions) error {
	if cr == nil {
		m.ChatRestrictionsJSON = ""
		return nil
	}
	data, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	m.ChatRestrictionsJSON = string(data)
	return nil
}

func (m *Meeting) GetLobbyBypassSettings() *LobbyBypassSettings {
	return &LobbyBypassSettings{
		Scope:                 m.LobbyBypassScope,
		IsDialInBypassEnabled: m.IsDialInBypassEnabled,
	}
}

func (m *Meeting) SetLobbyBypassSettings(lbs *LobbyBypassSettings) {
	if lbs != nil {
		m.LobbyBypassScope = lbs.Scope
		m.IsDialInBypassEnabled = lbs.IsDialInBypassEnabled
	}
}

func (m *Meeting) GetJoinMeetingIdSettings() *JoinMeetingIdSettings {
	return &JoinMeetingIdSettings{
		JoinMeetingId:      m.JoinMeetingId,
		Passcode:           m.Passcode,
		IsPasscodeRequired: m.IsPasscodeRequired,
	}
}

func (m *Meeting) SetJoinMeetingIdSettings(jmis *JoinMeetingIdSettings) {
	if jmis != nil {
		m.JoinMeetingId = jmis.JoinMeetingId
		m.Passcode = jmis.Passcode
		m.IsPasscodeRequired = jmis.IsPasscodeRequired
	}
}

// Teams-compatible JSON representation methods
func (m *Meeting) ToTeamsFormat() map[string]interface{} {
	result := map[string]interface{}{
		"id":                              m.ID,
		"creation_date_time":              m.CreationDateTime,
		"start_date_time":                 m.StartDateTime,
		"end_date_time":                   m.EndDateTime,
		"join_web_url":                    m.JoinWebUrl,
		"subject":                         m.Subject,
		"video_teleconference_id":         m.VideoTeleconferenceId,
		"external_id":                     m.ExternalId,
		"allow_attendee_to_enable_camera": m.AllowAttendeeToEnableCamera,
		"allow_attendee_to_enable_mic":    m.AllowAttendeeToEnableMic,
		"allow_breakout_rooms":            m.AllowBreakoutRooms,
		"allow_copying_and_sharing_meeting_content": m.AllowCopyingAndSharingMeetingContent,
		"allow_live_share":                          m.AllowLiveShare,
		"allow_meeting_chat":                        m.AllowMeetingChat,
		"allow_participants_to_change_name":         m.AllowParticipantsToChangeName,
		"allow_power_point_sharing":                 m.AllowPowerPointSharing,
		"allow_recording":                           m.AllowRecording,
		"allow_teamwork_reactions":                  m.AllowTeamworkReactions,
		"allow_transcription":                       m.AllowTranscription,
		"allow_whiteboard":                          m.AllowWhiteboard,
		"allowed_presenters":                        m.AllowedPresenters,
		"allowed_lobby_admitters":                   m.AllowedLobbyAdmitters,
		"is_end_to_end_encryption_enabled":          m.IsEndToEndEncryptionEnabled,
		"is_entry_exit_announced":                   m.IsEntryExitAnnounced,
		"record_automatically":                      m.RecordAutomatically,
		"share_meeting_chat_history_default":        m.ShareMeetingChatHistoryDefault,
		"watermark_protection":                      m.WatermarkProtection,
		"meeting_template_id":                       m.MeetingTemplateId,
		"lobby_bypass_settings":                     m.GetLobbyBypassSettings(),
		"join_meeting_id_settings":                  m.GetJoinMeetingIdSettings(),
		"audio_conferencing":                        m.GetAudioConferencing(),
		"chat_info":                                 m.GetChatInfo(),
		"chat_restrictions":                         m.GetChatRestrictions(),
		"join_information":                          m.JoinInformation,
	}

	// Add participants in Teams format if loaded
	if len(m.Participants) > 0 {
		participants := MeetingParticipants{
			Attendees: []MeetingParticipant{},
		}

		for _, p := range m.Participants {
			if p.Role == "organizer" {
				participants.Organizer = &p
			} else {
				participants.Attendees = append(participants.Attendees, p)
			}
		}
		result["participants"] = participants
	}

	return result
}
