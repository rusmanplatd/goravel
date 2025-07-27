package requests

import (
	"time"
)

// StartRecordingRequest represents a request to start meeting recording
type StartRecordingRequest struct {
	Quality             string   `json:"quality" validate:"required,oneof=low medium high ultra"`
	Format              string   `json:"format" validate:"required,oneof=mp4 webm mp3"`
	IncludeVideo        bool     `json:"include_video"`
	IncludeAudio        bool     `json:"include_audio"`
	IncludeScreenShare  bool     `json:"include_screen_share"`
	SeparateAudioTracks bool     `json:"separate_audio_tracks"`
	AutoTranscribe      bool     `json:"auto_transcribe"`
	GenerateSummary     bool     `json:"generate_summary"`
	LanguageCode        string   `json:"language_code" validate:"required,len=2"`
	RetentionDays       int      `json:"retention_days" validate:"min=1,max=365"`
	AllowedViewers      []string `json:"allowed_viewers"`
	IsPublic            bool     `json:"is_public"`
	WatermarkEnabled    bool     `json:"watermark_enabled"`
	EncryptionEnabled   bool     `json:"encryption_enabled"`
}

// ValidateAccessRequest represents a request to validate meeting access
type ValidateAccessRequest struct {
	DeviceType   string                 `json:"device_type" validate:"required,oneof=desktop mobile tablet"`
	BrowserInfo  string                 `json:"browser_info"`
	Location     map[string]interface{} `json:"location"`
	Capabilities []string               `json:"capabilities"`
}

// ApproveParticipantRequest represents a request to approve a waiting room participant
type ApproveParticipantRequest struct {
	ParticipantID string `json:"participant_id" validate:"required"`
	Message       string `json:"message"`
}

// SendChatMessageRequest represents a request to send a chat message
type SendChatMessageRequest struct {
	Content     string `json:"content" validate:"required,max=1000"`
	MessageType string `json:"message_type" validate:"required,oneof=text emoji file link"`
	RecipientID string `json:"recipient_id"` // Empty for public messages
}

// CreateBreakoutRoomsRequest represents a request to create breakout rooms
type CreateBreakoutRoomsRequest struct {
	Rooms []BreakoutRoomConfig `json:"rooms" validate:"required,min=1,max=20"`
}

// BreakoutRoomConfig represents configuration for a breakout room
type BreakoutRoomConfig struct {
	Name                      string `json:"name" validate:"required,max=100"`
	Description               string `json:"description" validate:"max=500"`
	Capacity                  int    `json:"capacity" validate:"min=2,max=50"`
	TimeLimitMinutes          int    `json:"time_limit_minutes" validate:"min=0,max=480"`
	AutoAssign                bool   `json:"auto_assign"`
	AllowParticipantsToChoose bool   `json:"allow_participants_to_choose"`
	AllowParticipantsToReturn bool   `json:"allow_participants_to_return"`
}

// UpdateParticipantStatusRequest represents a request to update participant status
type UpdateParticipantStatusRequest struct {
	IsMuted         *bool `json:"is_muted"`
	IsVideoEnabled  *bool `json:"is_video_enabled"`
	IsScreenSharing *bool `json:"is_screen_sharing"`
	IsHandRaised    *bool `json:"is_hand_raised"`
}

// JoinMeetingRequest represents a request to join a meeting
type JoinMeetingRequest struct {
	UserID       string            `json:"user_id" validate:"required"`
	ConnectionID string            `json:"connection_id" validate:"required"`
	DeviceInfo   map[string]string `json:"device_info"`
	Passcode     string            `json:"passcode"`
}

// UpdateMeetingSettingsRequest represents a request to update meeting settings
type UpdateMeetingSettingsRequest struct {
	AllowJoinBeforeHost     *bool  `json:"allow_join_before_host"`
	MuteParticipantsOnEntry *bool  `json:"mute_participants_on_entry"`
	WaitingRoom             string `json:"waiting_room" validate:"oneof=enabled disabled auto"`
	RecordMeeting           *bool  `json:"record_meeting"`
	MaxParticipants         *int   `json:"max_participants" validate:"min=2,max=1000"`
}

// CreateMeetingPollRequest represents a request to create a meeting poll
type CreateMeetingPollRequest struct {
	Question    string                 `json:"question" validate:"required,max=200"`
	Options     []string               `json:"options" validate:"required,min=2,max=10"`
	PollType    string                 `json:"poll_type" validate:"required,oneof=single_choice multiple_choice yes_no rating"`
	IsAnonymous bool                   `json:"is_anonymous"`
	Duration    int                    `json:"duration" validate:"min=30,max=3600"` // seconds
	Settings    map[string]interface{} `json:"settings"`
}

// SubmitPollVoteRequest represents a request to submit a poll vote
type SubmitPollVoteRequest struct {
	PollID    string   `json:"poll_id" validate:"required"`
	Responses []string `json:"responses" validate:"required"`
}

// UpdateSecurityPolicyRequest represents a request to update meeting security policy
type UpdateSecurityPolicyRequest struct {
	RequireWaitingRoom     *bool    `json:"require_waiting_room"`
	RequirePassword        *bool    `json:"require_password"`
	AllowAnonymousJoin     *bool    `json:"allow_anonymous_join"`
	MaxParticipants        *int     `json:"max_participants" validate:"min=2,max=10000"`
	AllowedDomains         []string `json:"allowed_domains"`
	BlockedUsers           []string `json:"blocked_users"`
	RequireRegistration    *bool    `json:"require_registration"`
	EnableEndToEndEncrypt  *bool    `json:"enable_e2e_encryption"`
	RecordingPermissions   string   `json:"recording_permissions" validate:"oneof=host all none"`
	ScreenSharePermissions string   `json:"screen_share_permissions" validate:"oneof=host all none"`
	ChatPermissions        string   `json:"chat_permissions" validate:"oneof=host all none"`
	MuteOnEntry            *bool    `json:"mute_on_entry"`
	DisableCamera          *bool    `json:"disable_camera"`
	LockMeeting            *bool    `json:"lock_meeting"`
}

// CreateWhiteboardRequest represents a request to create a meeting whiteboard
type CreateWhiteboardRequest struct {
	Name        string                 `json:"name" validate:"required,max=100"`
	Description string                 `json:"description" validate:"max=500"`
	Template    string                 `json:"template" validate:"oneof=blank grid dots lines"`
	Settings    map[string]interface{} `json:"settings"`
	IsPublic    bool                   `json:"is_public"`
}

// UpdateWhiteboardRequest represents a request to update whiteboard content
type UpdateWhiteboardRequest struct {
	Content   string                 `json:"content" validate:"required"`
	Operation string                 `json:"operation" validate:"required,oneof=add update delete clear"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// InviteParticipantsRequest represents a request to invite participants to a meeting
type InviteParticipantsRequest struct {
	Participants []ParticipantInvite `json:"participants" validate:"required,min=1"`
	Message      string              `json:"message" validate:"max=500"`
	SendEmail    bool                `json:"send_email"`
	SendSMS      bool                `json:"send_sms"`
}

// ParticipantInvite represents a participant invitation
type ParticipantInvite struct {
	Email       string `json:"email" validate:"required,email"`
	Name        string `json:"name" validate:"required,max=100"`
	Role        string `json:"role" validate:"oneof=attendee co-host"`
	PhoneNumber string `json:"phone_number"`
}

// ScheduleMeetingRequest represents a request to schedule a meeting
type ScheduleMeetingRequest struct {
	EventID                 string                 `json:"event_id" validate:"required"`
	MeetingType             string                 `json:"meeting_type" validate:"required,oneof=video audio hybrid in-person"`
	Platform                string                 `json:"platform" validate:"required"`
	MeetingURL              string                 `json:"meeting_url"`
	MeetingID               string                 `json:"meeting_id"`
	Passcode                string                 `json:"passcode"`
	MeetingNotes            string                 `json:"meeting_notes" validate:"max=2000"`
	RecordMeeting           bool                   `json:"record_meeting"`
	AllowJoinBeforeHost     bool                   `json:"allow_join_before_host"`
	MuteParticipantsOnEntry bool                   `json:"mute_participants_on_entry"`
	WaitingRoom             string                 `json:"waiting_room" validate:"oneof=enabled disabled auto"`
	SecuritySettings        map[string]interface{} `json:"security_settings"`
	NotificationSettings    map[string]interface{} `json:"notification_settings"`
}

// GetMeetingAnalyticsRequest represents a request for meeting analytics
type GetMeetingAnalyticsRequest struct {
	StartDate    *time.Time `json:"start_date"`
	EndDate      *time.Time `json:"end_date"`
	Granularity  string     `json:"granularity" validate:"oneof=minute hour day week month"`
	Metrics      []string   `json:"metrics"`
	IncludeUsers bool       `json:"include_users"`
}

// ExportMeetingDataRequest represents a request to export meeting data
type ExportMeetingDataRequest struct {
	Format          string   `json:"format" validate:"required,oneof=json csv pdf"`
	IncludeSections []string `json:"include_sections" validate:"required"`
	DateRange       struct {
		StartDate time.Time `json:"start_date" validate:"required"`
		EndDate   time.Time `json:"end_date" validate:"required"`
	} `json:"date_range"`
	Filters map[string]interface{} `json:"filters"`
}

// BulkOperationRequest represents a request for bulk operations on meetings
type BulkOperationRequest struct {
	MeetingIDs []string               `json:"meeting_ids" validate:"required,min=1,max=100"`
	Operation  string                 `json:"operation" validate:"required,oneof=delete end start mute_all unmute_all"`
	Parameters map[string]interface{} `json:"parameters"`
}

// MeetingTemplateRequest represents a request to create or update a meeting template
type MeetingTemplateRequest struct {
	Name                    string                 `json:"name" validate:"required,max=100"`
	Description             string                 `json:"description" validate:"max=500"`
	MeetingType             string                 `json:"meeting_type" validate:"required,oneof=video audio hybrid in-person"`
	DefaultDuration         int                    `json:"default_duration" validate:"min=15,max=480"` // minutes
	RecordMeeting           bool                   `json:"record_meeting"`
	AllowJoinBeforeHost     bool                   `json:"allow_join_before_host"`
	MuteParticipantsOnEntry bool                   `json:"mute_participants_on_entry"`
	WaitingRoom             string                 `json:"waiting_room" validate:"oneof=enabled disabled auto"`
	SecuritySettings        map[string]interface{} `json:"security_settings"`
	NotificationSettings    map[string]interface{} `json:"notification_settings"`
	IsPublic                bool                   `json:"is_public"`
	Tags                    []string               `json:"tags"`
}

// MeetingFeedbackRequest represents a request to submit meeting feedback
type MeetingFeedbackRequest struct {
	Rating          int                    `json:"rating" validate:"required,min=1,max=5"`
	Comment         string                 `json:"comment" validate:"max=1000"`
	Categories      []string               `json:"categories"`
	IsAnonymous     bool                   `json:"is_anonymous"`
	Suggestions     string                 `json:"suggestions" validate:"max=1000"`
	TechnicalIssues []string               `json:"technical_issues"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ReportIssueRequest represents a request to report a meeting issue
type ReportIssueRequest struct {
	IssueType   string                 `json:"issue_type" validate:"required,oneof=audio video connection recording other"`
	Severity    string                 `json:"severity" validate:"required,oneof=low medium high critical"`
	Description string                 `json:"description" validate:"required,max=1000"`
	Steps       []string               `json:"steps"`
	DeviceInfo  map[string]interface{} `json:"device_info"`
	Timestamp   time.Time              `json:"timestamp"`
	Attachments []string               `json:"attachments"`
}
