package models

import (
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

	// Relationships
	// @Description Event's associated tenant
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Parent event for recurring instances
	ParentEvent *CalendarEvent `gorm:"foreignKey:ParentEventID" json:"parent_event,omitempty"`

	// @Description Recurring event instances
	RecurringInstances []CalendarEvent `gorm:"foreignKey:ParentEventID" json:"recurring_instances,omitempty"`

	// @Description Event participants
	Participants []EventParticipant `gorm:"foreignKey:EventID" json:"participants,omitempty"`

	// @Description Associated meeting details
	Meeting *Meeting `gorm:"foreignKey:EventID" json:"meeting,omitempty"`
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
// @Description Meeting details with platform and settings
type Meeting struct {
	BaseModel
	// Associated event ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID string `gorm:"not null" json:"event_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Meeting type (video, audio, in-person, hybrid)
	// @example video
	MeetingType string `gorm:"default:'video'" json:"meeting_type" example:"video"`

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
	RecordMeeting bool `gorm:"default:false" json:"record_meeting" example:"false"`

	// Whether participants can join before host
	// @example true
	AllowJoinBeforeHost bool `gorm:"default:true" json:"allow_join_before_host" example:"true"`

	// Whether to mute participants on entry
	// @example false
	MuteParticipantsOnEntry bool `gorm:"default:false" json:"mute_participants_on_entry" example:"false"`

	// Waiting room setting
	// @example enabled
	WaitingRoom string `gorm:"default:'disabled'" json:"waiting_room" example:"enabled"`

	// When the meeting started
	// @example 2024-01-15T10:00:00Z
	StartedAt *time.Time `json:"started_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// When the meeting ended
	// @example 2024-01-15T11:00:00Z
	EndedAt *time.Time `json:"ended_at,omitempty" example:"2024-01-15T11:00:00Z"`

	// Recording URL
	// @example https://zoom.us/recording/123456789
	RecordingURL string `json:"recording_url" example:"https://zoom.us/recording/123456789"`

	// Meeting status (scheduled, in-progress, completed, cancelled)
	// @example scheduled
	Status string `gorm:"default:'scheduled'" json:"status" example:"scheduled"`

	// Whether the meeting has conflicts with other meetings
	// @example false
	HasConflicts bool `gorm:"default:false" json:"has_conflicts" example:"false"`

	// Conflict details (JSON format with conflicting event IDs)
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	ConflictDetails string `json:"conflict_details" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]"`

	// Meeting attendance count
	// @example 5
	AttendanceCount int `gorm:"default:0" json:"attendance_count" example:"5"`

	// Meeting notes taken during the meeting
	// @example Key decisions: 1. Project timeline approved 2. Budget increased by 10%
	MeetingMinutes string `json:"meeting_minutes" example:"Key decisions: 1. Project timeline approved 2. Budget increased by 10%"`

	// Relationships
	// @Description Associated calendar event
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`

	// @Description Meeting participants
	Participants []MeetingParticipant `gorm:"foreignKey:MeetingID" json:"participants,omitempty"`

	// @Description Meeting chat messages
	ChatMessages []MeetingChat `gorm:"foreignKey:MeetingID" json:"chat_messages,omitempty"`

	// @Description Meeting breakout rooms
	BreakoutRooms []MeetingBreakoutRoom `gorm:"foreignKey:MeetingID" json:"breakout_rooms,omitempty"`
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
