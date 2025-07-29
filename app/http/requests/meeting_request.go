package requests

import (
	"goravel/app/models"
	"time"
)

// CreateOnlineMeetingRequest represents the request for creating an online meeting (Teams-compatible)
type CreateOnlineMeetingRequest struct {
	// Meeting subject/title (required)
	// @example "Weekly Team Standup"
	Subject string `json:"subject" binding:"required" example:"Weekly Team Standup"`

	// Meeting start time (required)
	// @example "2024-01-15T10:00:00Z"
	StartDateTime *time.Time `json:"start_date_time" binding:"required" example:"2024-01-15T10:00:00Z"`

	// Meeting end time (required)
	// @example "2024-01-15T11:00:00Z"
	EndDateTime *time.Time `json:"end_date_time" binding:"required" example:"2024-01-15T11:00:00Z"`

	// External ID for custom identification (optional)
	// @example "custom-meeting-001"
	ExternalId *string `json:"external_id,omitempty" example:"custom-meeting-001"`

	// Meeting template ID for consistent setups (optional)
	// @example "template-001"
	MeetingTemplateId *string `json:"meeting_template_id,omitempty" example:"template-001"`

	// Teams-specific meeting permissions and settings (all optional with defaults)
	// Whether attendees can turn on their camera
	// @example true
	AllowAttendeeToEnableCamera *bool `json:"allow_attendee_to_enable_camera,omitempty" example:"true"`

	// Whether attendees can turn on their microphone
	// @example true
	AllowAttendeeToEnableMic *bool `json:"allow_attendee_to_enable_mic,omitempty" example:"true"`

	// Whether breakout rooms are enabled
	// @example false
	AllowBreakoutRooms *bool `json:"allow_breakout_rooms,omitempty" example:"false"`

	// Whether copying and sharing meeting content is enabled
	// @example true
	AllowCopyingAndSharingMeetingContent *bool `json:"allow_copying_and_sharing_meeting_content,omitempty" example:"true"`

	// Whether live share is enabled (enabled, disabled, unknownFutureValue)
	// @example "enabled"
	AllowLiveShare *string `json:"allow_live_share,omitempty" example:"enabled"`

	// Meeting chat mode (enabled, disabled, limited, unknownFutureValue)
	// @example "enabled"
	AllowMeetingChat *string `json:"allow_meeting_chat,omitempty" example:"enabled"`

	// Whether participants can change their name
	// @example true
	AllowParticipantsToChangeName *bool `json:"allow_participants_to_change_name,omitempty" example:"true"`

	// Whether PowerPoint sharing is allowed
	// @example true
	AllowPowerPointSharing *bool `json:"allow_power_point_sharing,omitempty" example:"true"`

	// Whether recording is enabled for the meeting
	// @example false
	AllowRecording *bool `json:"allow_recording,omitempty" example:"false"`

	// Whether Teams reactions are enabled
	// @example true
	AllowTeamworkReactions *bool `json:"allow_teamwork_reactions,omitempty" example:"true"`

	// Whether transcription is enabled
	// @example false
	AllowTranscription *bool `json:"allow_transcription,omitempty" example:"false"`

	// Whether whiteboard is enabled
	// @example true
	AllowWhiteboard *bool `json:"allow_whiteboard,omitempty" example:"true"`

	// Who can be a presenter (everyone, organization, roleIsPresenter, organizer, unknownFutureValue)
	// @example "everyone"
	AllowedPresenters *string `json:"allowed_presenters,omitempty" example:"everyone"`

	// Specifies the users who can admit from lobby (organizerAndCoOrganizersAndPresenters, organizerAndCoOrganizers, unknownFutureValue)
	// @example "organizerAndCoOrganizers"
	AllowedLobbyAdmitters *string `json:"allowed_lobby_admitters,omitempty" example:"organizerAndCoOrganizers"`

	// Whether end-to-end encryption is enabled
	// @example false
	IsEndToEndEncryptionEnabled *bool `json:"is_end_to_end_encryption_enabled,omitempty" example:"false"`

	// Whether to announce when callers join or leave
	// @example true
	IsEntryExitAnnounced *bool `json:"is_entry_exit_announced,omitempty" example:"true"`

	// Whether to record the meeting automatically
	// @example false
	RecordAutomatically *bool `json:"record_automatically,omitempty" example:"false"`

	// Meeting chat history sharing mode (all, none, unknownFutureValue)
	// @example "all"
	ShareMeetingChatHistoryDefault *string `json:"share_meeting_chat_history_default,omitempty" example:"all"`

	// Watermark protection settings (enabled, disabled, unknownFutureValue)
	// @example "disabled"
	WatermarkProtection *string `json:"watermark_protection,omitempty" example:"disabled"`

	// Lobby bypass settings
	// Lobby bypass scope (everyone, organization, organizer)
	// @example "organization"
	LobbyBypassScope *string `json:"lobby_bypass_scope,omitempty" example:"organization"`

	// Whether dial-in users can bypass the lobby
	// @example false
	IsDialInBypassEnabled *bool `json:"is_dial_in_bypass_enabled,omitempty" example:"false"`

	// Join meeting ID settings
	// Whether passcode is required for joining
	// @example false
	IsPasscodeRequired *bool `json:"is_passcode_required,omitempty" example:"false"`

	// Teams-compatible structured data (optional)
	// Audio conferencing settings
	AudioConferencing *models.AudioConferencing `json:"audio_conferencing,omitempty"`

	// Chat information
	ChatInfo *models.ChatInfo `json:"chat_info,omitempty"`

	// Chat restrictions
	ChatRestrictions *models.ChatRestrictions `json:"chat_restrictions,omitempty"`

	// Meeting participants (Teams structure)
	Participants *CreateMeetingParticipantsRequest `json:"participants,omitempty"`

	// NEW TEAMS-LIKE FEATURES
	// Calendar integration settings
	CalendarIntegration *CalendarIntegrationRequest `json:"calendar_integration,omitempty"`

	// Recurring meeting settings
	RecurrencePattern *RecurrencePatternRequest `json:"recurrence_pattern,omitempty"`

	// Meeting invitation settings
	InvitationSettings *InvitationSettingsRequest `json:"invitation_settings,omitempty"`

	// Co-organizer settings
	CoOrganizers []CreateMeetingParticipantRequest `json:"co_organizers,omitempty"`

	// Meeting dial-in settings
	DialInSettings *DialInSettingsRequest `json:"dial_in_settings,omitempty"`

	// Advanced meeting options
	AdvancedOptions *AdvancedMeetingOptionsRequest `json:"advanced_options,omitempty"`
}

// CalendarIntegrationRequest represents calendar integration settings
type CalendarIntegrationRequest struct {
	// Whether to send calendar invitations
	// @example true
	SendCalendarInvitation *bool `json:"send_calendar_invitation,omitempty" example:"true"`

	// Calendar provider (outlook, google, exchange)
	// @example "outlook"
	CalendarProvider *string `json:"calendar_provider,omitempty" example:"outlook"`

	// Meeting location in calendar
	// @example "Microsoft Teams Meeting"
	MeetingLocation *string `json:"meeting_location,omitempty" example:"Microsoft Teams Meeting"`

	// Whether to include meeting agenda in calendar
	// @example true
	IncludeAgenda *bool `json:"include_agenda,omitempty" example:"true"`

	// Meeting agenda content
	// @example "1. Project updates\n2. Q&A session\n3. Next steps"
	Agenda *string `json:"agenda,omitempty" example:"1. Project updates\n2. Q&A session\n3. Next steps"`

	// Meeting reminder settings
	ReminderSettings *ReminderSettingsRequest `json:"reminder_settings,omitempty"`
}

// RecurrencePatternRequest represents recurring meeting settings
type RecurrencePatternRequest struct {
	// Recurrence type (daily, weekly, monthly, yearly)
	// @example "weekly"
	Type string `json:"type" binding:"required" example:"weekly"`

	// Recurrence interval (e.g., every 2 weeks)
	// @example 1
	Interval int `json:"interval" example:"1"`

	// Days of week for weekly recurrence
	// @example ["monday", "wednesday", "friday"]
	DaysOfWeek []string `json:"days_of_week,omitempty" example:"monday,wednesday,friday"`

	// Day of month for monthly recurrence
	// @example 15
	DayOfMonth *int `json:"day_of_month,omitempty" example:"15"`

	// Week of month for monthly recurrence (first, second, third, fourth, last)
	// @example "first"
	WeekOfMonth *string `json:"week_of_month,omitempty" example:"first"`

	// Month for yearly recurrence
	// @example 12
	Month *int `json:"month,omitempty" example:"12"`

	// End date for recurrence
	// @example "2024-12-31T23:59:59Z"
	EndDate *time.Time `json:"end_date,omitempty" example:"2024-12-31T23:59:59Z"`

	// Number of occurrences
	// @example 10
	Occurrences *int `json:"occurrences,omitempty" example:"10"`
}

// InvitationSettingsRequest represents meeting invitation settings
type InvitationSettingsRequest struct {
	// Custom invitation message
	// @example "Join us for the weekly team standup meeting"
	CustomMessage *string `json:"custom_message,omitempty" example:"Join us for the weekly team standup meeting"`

	// Whether to include meeting details in invitation
	// @example true
	IncludeMeetingDetails *bool `json:"include_meeting_details,omitempty" example:"true"`

	// Whether to include dial-in information
	// @example true
	IncludeDialInInfo *bool `json:"include_dial_in_info,omitempty" example:"true"`

	// Whether to require RSVP
	// @example false
	RequireRSVP *bool `json:"require_rsvp,omitempty" example:"false"`

	// RSVP deadline
	// @example "2024-01-14T18:00:00Z"
	RSVPDeadline *time.Time `json:"rsvp_deadline,omitempty" example:"2024-01-14T18:00:00Z"`

	// Whether to send follow-up reminders
	// @example true
	SendReminders *bool `json:"send_reminders,omitempty" example:"true"`
}

// ReminderSettingsRequest represents reminder settings
type ReminderSettingsRequest struct {
	// Reminder times in minutes before meeting
	// @example [15, 60, 1440]
	ReminderTimes []int `json:"reminder_times,omitempty" example:"15,60,1440"`

	// Whether to send email reminders
	// @example true
	EmailReminders *bool `json:"email_reminders,omitempty" example:"true"`

	// Whether to send push notifications
	// @example true
	PushNotifications *bool `json:"push_notifications,omitempty" example:"true"`

	// Whether to send SMS reminders
	// @example false
	SMSReminders *bool `json:"sms_reminders,omitempty" example:"false"`
}

// DialInSettingsRequest represents dial-in conference settings
type DialInSettingsRequest struct {
	// Whether dial-in is enabled
	// @example true
	EnableDialIn *bool `json:"enable_dial_in,omitempty" example:"true"`

	// Conference bridge provider
	// @example "teams"
	Provider *string `json:"provider,omitempty" example:"teams"`

	// Conference ID
	// @example "123456789"
	ConferenceId *string `json:"conference_id,omitempty" example:"123456789"`

	// Toll-free numbers
	TollFreeNumbers []string `json:"toll_free_numbers,omitempty"`

	// Local access numbers by country
	LocalNumbers map[string][]string `json:"local_numbers,omitempty"`

	// Whether to announce caller names
	// @example true
	AnnounceCallerNames *bool `json:"announce_caller_names,omitempty" example:"true"`
}

// AdvancedMeetingOptionsRequest represents advanced meeting options
type AdvancedMeetingOptionsRequest struct {
	// Maximum number of participants
	// @example 300
	MaxParticipants *int `json:"max_participants,omitempty" example:"300"`

	// Meeting timeout in minutes
	// @example 480
	TimeoutMinutes *int `json:"timeout_minutes,omitempty" example:"480"`

	// Whether to enable waiting room
	// @example true
	EnableWaitingRoom *bool `json:"enable_waiting_room,omitempty" example:"true"`

	// Waiting room message
	// @example "Please wait while the host admits you to the meeting"
	WaitingRoomMessage *string `json:"waiting_room_message,omitempty" example:"Please wait while the host admits you to the meeting"`

	// Whether to enable meeting lock
	// @example false
	EnableMeetingLock *bool `json:"enable_meeting_lock,omitempty" example:"false"`

	// Auto-admit settings
	AutoAdmitSettings *AutoAdmitSettingsRequest `json:"auto_admit_settings,omitempty"`

	// Meeting policies
	MeetingPolicies *MeetingPoliciesRequest `json:"meeting_policies,omitempty"`
}

// AutoAdmitSettingsRequest represents auto-admit settings
type AutoAdmitSettingsRequest struct {
	// Auto-admit scope (everyone, organization, invited, none)
	// @example "organization"
	Scope *string `json:"scope,omitempty" example:"organization"`

	// Trusted domains for auto-admit
	TrustedDomains []string `json:"trusted_domains,omitempty"`

	// Whether to auto-admit dial-in users
	// @example false
	DialInUsers *bool `json:"dial_in_users,omitempty" example:"false"`
}

// MeetingPoliciesRequest represents meeting policy settings
type MeetingPoliciesRequest struct {
	// Recording policy (disabled, enabled, required)
	// @example "enabled"
	RecordingPolicy *string `json:"recording_policy,omitempty" example:"enabled"`

	// Transcription policy (disabled, enabled, required)
	// @example "enabled"
	TranscriptionPolicy *string `json:"transcription_policy,omitempty" example:"enabled"`

	// Chat policy (disabled, enabled, moderated)
	// @example "enabled"
	ChatPolicy *string `json:"chat_policy,omitempty" example:"enabled"`

	// Screen sharing policy (disabled, enabled, presenter_only)
	// @example "enabled"
	ScreenSharingPolicy *string `json:"screen_sharing_policy,omitempty" example:"enabled"`

	// File sharing policy (disabled, enabled, moderated)
	// @example "enabled"
	FileSharingPolicy *string `json:"file_sharing_policy,omitempty" example:"enabled"`
}

// CreateMeetingParticipantsRequest represents the participants structure (Teams-compatible)
type CreateMeetingParticipantsRequest struct {
	// Meeting attendees
	Attendees []CreateMeetingParticipantRequest `json:"attendees,omitempty"`

	// Meeting producers (for broadcasts)
	Producers []CreateMeetingParticipantRequest `json:"producers,omitempty"`

	// Meeting contributors (for broadcasts)
	Contributors []CreateMeetingParticipantRequest `json:"contributors,omitempty"`
}

// UpdateOnlineMeetingRequest represents the request for updating an online meeting
type UpdateOnlineMeetingRequest struct {
	// Meeting subject/title
	// @example "Weekly Team Standup - Updated"
	Subject *string `json:"subject,omitempty" example:"Weekly Team Standup - Updated"`

	// Meeting start time
	// @example "2024-01-15T10:00:00Z"
	StartDateTime *time.Time `json:"start_date_time,omitempty" example:"2024-01-15T10:00:00Z"`

	// Meeting end time
	// @example "2024-01-15T11:00:00Z"
	EndDateTime *time.Time `json:"end_date_time,omitempty" example:"2024-01-15T11:00:00Z"`

	// Whether attendees can turn on their camera
	// @example true
	AllowAttendeeToEnableCamera *bool `json:"allow_attendee_to_enable_camera,omitempty" example:"true"`

	// Whether attendees can turn on their microphone
	// @example true
	AllowAttendeeToEnableMic *bool `json:"allow_attendee_to_enable_mic,omitempty" example:"true"`

	// Whether breakout rooms are enabled
	// @example false
	AllowBreakoutRooms *bool `json:"allow_breakout_rooms,omitempty" example:"false"`

	// Whether copying and sharing meeting content is enabled
	// @example true
	AllowCopyingAndSharingMeetingContent *bool `json:"allow_copying_and_sharing_meeting_content,omitempty" example:"true"`

	// Whether live share is enabled (enabled, disabled, unknownFutureValue)
	// @example "enabled"
	AllowLiveShare *string `json:"allow_live_share,omitempty" example:"enabled"`

	// Who can be a presenter (everyone, organization, roleIsPresenter, organizer)
	// @example "everyone"
	AllowedPresenters *string `json:"allowed_presenters,omitempty" example:"everyone"`

	// Meeting chat mode (enabled, disabled, limited)
	// @example "enabled"
	AllowMeetingChat *string `json:"allow_meeting_chat,omitempty" example:"enabled"`

	// Whether participants can change their name
	// @example true
	AllowParticipantsToChangeName *bool `json:"allow_participants_to_change_name,omitempty" example:"true"`

	// Whether PowerPoint sharing is allowed
	// @example true
	AllowPowerPointSharing *bool `json:"allow_power_point_sharing,omitempty" example:"true"`

	// Whether recording is enabled for the meeting
	// @example false
	AllowRecording *bool `json:"allow_recording,omitempty" example:"false"`

	// Whether Teams reactions are enabled
	// @example true
	AllowTeamworkReactions *bool `json:"allow_teamwork_reactions,omitempty" example:"true"`

	// Whether transcription is enabled
	// @example false
	AllowTranscription *bool `json:"allow_transcription,omitempty" example:"false"`

	// Whether whiteboard is enabled
	// @example true
	AllowWhiteboard *bool `json:"allow_whiteboard,omitempty" example:"true"`

	// Whether to announce when callers join or leave
	// @example true
	IsEntryExitAnnounced *bool `json:"is_entry_exit_announced,omitempty" example:"true"`

	// Whether to record the meeting automatically
	// @example false
	RecordAutomatically *bool `json:"record_automatically,omitempty" example:"false"`

	// Lobby bypass scope (everyone, organization, organizer)
	// @example "organization"
	LobbyBypassScope *string `json:"lobby_bypass_scope,omitempty" example:"organization"`

	// Whether dial-in users can bypass the lobby
	// @example false
	IsDialInBypassEnabled *bool `json:"is_dial_in_bypass_enabled,omitempty" example:"false"`

	// Meeting chat history sharing mode (all, none)
	// @example "all"
	ShareMeetingChatHistoryDefault *string `json:"share_meeting_chat_history_default,omitempty" example:"all"`

	// Watermark protection settings (enabled, disabled)
	// @example "disabled"
	WatermarkProtection *string `json:"watermark_protection,omitempty" example:"disabled"`
}

// CreateMeetingParticipantRequest represents a participant to add to the meeting
type CreateMeetingParticipantRequest struct {
	// User ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User identity (email or UPN)
	// @example "user@example.com"
	Identity string `json:"identity,omitempty" example:"user@example.com"`

	// Participant role (organizer, presenter, attendee, producer, contributor)
	// @example "attendee"
	Role string `json:"role,omitempty" example:"attendee"`
}

// NEW TEAMS-LIKE REQUEST STRUCTURES

// CreateMeetingTemplateRequest represents a request to create a meeting template
type CreateMeetingTemplateRequest struct {
	// Template name
	// @example "Weekly Team Standup Template"
	Name string `json:"name" binding:"required" example:"Weekly Team Standup Template"`

	// Template description
	// @example "Standard template for weekly team standup meetings"
	Description *string `json:"description,omitempty" example:"Standard template for weekly team standup meetings"`

	// Template category
	// @example "team_meetings"
	Category *string `json:"category,omitempty" example:"team_meetings"`

	// Default meeting settings
	DefaultSettings *CreateOnlineMeetingRequest `json:"default_settings,omitempty"`

	// Whether template is public
	// @example false
	IsPublic *bool `json:"is_public,omitempty" example:"false"`

	// Template tags
	Tags []string `json:"tags,omitempty"`
}

// SendMeetingInvitationRequest represents a request to send meeting invitations
type SendMeetingInvitationRequest struct {
	// Meeting ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `json:"meeting_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Recipients to invite
	Recipients []InvitationRecipientRequest `json:"recipients" binding:"required"`

	// Custom invitation message
	// @example "Please join us for the weekly team standup meeting"
	CustomMessage *string `json:"custom_message,omitempty" example:"Please join us for the weekly team standup meeting"`

	// Whether to send calendar invitation
	// @example true
	SendCalendarInvitation *bool `json:"send_calendar_invitation,omitempty" example:"true"`

	// Whether to send email notification
	// @example true
	SendEmailNotification *bool `json:"send_email_notification,omitempty" example:"true"`

	// Invitation deadline
	// @example "2024-01-14T18:00:00Z"
	InvitationDeadline *time.Time `json:"invitation_deadline,omitempty" example:"2024-01-14T18:00:00Z"`
}

// InvitationRecipientRequest represents an invitation recipient
type InvitationRecipientRequest struct {
	// User ID (for internal users)
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID *string `json:"user_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Email address (for external users)
	// @example "external@example.com"
	Email *string `json:"email,omitempty" example:"external@example.com"`

	// Display name
	// @example "John Doe"
	DisplayName *string `json:"display_name,omitempty" example:"John Doe"`

	// Participant role
	// @example "attendee"
	Role *string `json:"role,omitempty" example:"attendee"`

	// Whether invitation is required
	// @example false
	Required *bool `json:"required,omitempty" example:"false"`
}

// ManageMeetingLobbyRequest represents a request to manage meeting lobby
type ManageMeetingLobbyRequest struct {
	// Action to perform (admit, reject, admit_all, reject_all)
	// @example "admit"
	Action string `json:"action" binding:"required" example:"admit"`

	// User IDs to perform action on (for admit/reject)
	UserIDs []string `json:"user_ids,omitempty"`

	// Reason for rejection (optional)
	// @example "Meeting is at capacity"
	Reason *string `json:"reason,omitempty" example:"Meeting is at capacity"`
}

// CreateBreakoutRoomRequest represents a request to create breakout rooms
type CreateBreakoutRoomRequest struct {
	// Number of rooms to create
	// @example 3
	RoomCount int `json:"room_count" binding:"required,min=1,max=50" example:"3"`

	// Room assignment method (automatic, manual, self_select)
	// @example "automatic"
	AssignmentMethod string `json:"assignment_method" binding:"required" example:"automatic"`

	// Room duration in minutes
	// @example 30
	DurationMinutes *int `json:"duration_minutes,omitempty" example:"30"`

	// Whether participants can return to main room
	// @example true
	AllowReturnToMain *bool `json:"allow_return_to_main,omitempty" example:"true"`

	// Whether to automatically move participants
	// @example true
	AutoMoveParticipants *bool `json:"auto_move_participants,omitempty" example:"true"`

	// Custom room assignments (for manual assignment)
	RoomAssignments []BreakoutRoomAssignmentRequest `json:"room_assignments,omitempty"`
}

// BreakoutRoomAssignmentRequest represents room assignment for a participant
type BreakoutRoomAssignmentRequest struct {
	// User ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Room number (1-based)
	// @example 1
	RoomNumber int `json:"room_number" binding:"required,min=1" example:"1"`
}

// MeetingReactionRequest represents a request to send a meeting reaction
type MeetingReactionRequest struct {
	// Reaction type (like, love, laugh, surprised, sad, angry, applause, heart)
	// @example "applause"
	ReactionType string `json:"reaction_type" binding:"required" example:"applause"`

	// Duration in seconds (optional, defaults to 3)
	// @example 3
	Duration *int `json:"duration,omitempty" example:"3"`
}

// PollOptionRequest represents a poll option
type PollOptionRequest struct {
	// Option text
	// @example "Bug fixes"
	Text string `json:"text" binding:"required" example:"Bug fixes"`

	// Option description (optional)
	// @example "Focus on resolving existing bugs"
	Description *string `json:"description,omitempty" example:"Focus on resolving existing bugs"`
}

// VotePollRequest represents a request to vote on a poll
type VotePollRequest struct {
	// Selected option IDs
	// @example ["option1", "option2"]
	SelectedOptions []string `json:"selected_options" binding:"required,min=1"`
}

// NEW SCHEDULING AND AVAILABILITY REQUEST STRUCTURES

// CheckAvailabilityRequest represents a request to check participant availability
type CheckAvailabilityRequest struct {
	// Participant email addresses or user IDs
	// @example ["user1@example.com", "user2@example.com"]
	Participants []string `json:"participants" binding:"required,min=1"`

	// Meeting start time
	// @example "2024-01-15T10:00:00Z"
	StartTime time.Time `json:"start_time" binding:"required" example:"2024-01-15T10:00:00Z"`

	// Meeting end time
	// @example "2024-01-15T11:00:00Z"
	EndTime time.Time `json:"end_time" binding:"required" example:"2024-01-15T11:00:00Z"`

	// Time zone for the availability check
	// @example "America/New_York"
	TimeZone *string `json:"time_zone,omitempty" example:"America/New_York"`

	// Include free/busy details
	// @example true
	IncludeDetails *bool `json:"include_details,omitempty" example:"true"`
}

// FindMeetingTimesRequest represents a request to find optimal meeting times
type FindMeetingTimesRequest struct {
	// Required attendees
	// @example ["user1@example.com", "user2@example.com"]
	RequiredAttendees []string `json:"required_attendees" binding:"required,min=1"`

	// Optional attendees
	// @example ["user3@example.com", "user4@example.com"]
	OptionalAttendees []string `json:"optional_attendees,omitempty"`

	// Meeting duration in minutes
	// @example 60
	DurationMinutes int `json:"duration_minutes" binding:"required,min=15,max=480" example:"60"`

	// Time constraints for the meeting
	TimeConstraints *TimeConstraintsRequest `json:"time_constraints,omitempty"`

	// Maximum number of suggestions to return
	// @example 5
	MaxSuggestions *int `json:"max_suggestions,omitempty" example:"5"`

	// Meeting preferences
	MeetingPreferences *MeetingPreferencesRequest `json:"meeting_preferences,omitempty"`
}

// TimeConstraintsRequest represents time constraints for meeting scheduling
type TimeConstraintsRequest struct {
	// Earliest possible start time
	// @example "2024-01-15T09:00:00Z"
	EarliestTime *time.Time `json:"earliest_time,omitempty" example:"2024-01-15T09:00:00Z"`

	// Latest possible start time
	// @example "2024-01-15T17:00:00Z"
	LatestTime *time.Time `json:"latest_time,omitempty" example:"2024-01-15T17:00:00Z"`

	// Preferred days of week (1=Monday, 7=Sunday)
	// @example [1, 2, 3, 4, 5]
	PreferredDays []int `json:"preferred_days,omitempty" example:"1,2,3,4,5"`

	// Working hours start (24-hour format)
	// @example "09:00"
	WorkingHoursStart *string `json:"working_hours_start,omitempty" example:"09:00"`

	// Working hours end (24-hour format)
	// @example "17:00"
	WorkingHoursEnd *string `json:"working_hours_end,omitempty" example:"17:00"`

	// Time zone for constraints
	// @example "America/New_York"
	TimeZone *string `json:"time_zone,omitempty" example:"America/New_York"`
}

// MeetingPreferencesRequest represents meeting scheduling preferences
type MeetingPreferencesRequest struct {
	// Preferred meeting type (video, audio, in-person)
	// @example "video"
	PreferredType *string `json:"preferred_type,omitempty" example:"video"`

	// Minimum gap between meetings in minutes
	// @example 15
	MinimumGap *int `json:"minimum_gap,omitempty" example:"15"`

	// Avoid back-to-back meetings
	// @example true
	AvoidBackToBack *bool `json:"avoid_back_to_back,omitempty" example:"true"`

	// Preferred meeting rooms or resources
	PreferredRooms []string `json:"preferred_rooms,omitempty"`

	// Buffer time before meeting in minutes
	// @example 5
	BufferBefore *int `json:"buffer_before,omitempty" example:"5"`

	// Buffer time after meeting in minutes
	// @example 5
	BufferAfter *int `json:"buffer_after,omitempty" example:"5"`
}

// ScheduleMeetingWithAssistantRequest represents a request to schedule with assistant
type ScheduleMeetingWithAssistantRequest struct {
	// Base meeting request
	*CreateOnlineMeetingRequest

	// Use scheduling assistant
	// @example true
	UseSchedulingAssistant *bool `json:"use_scheduling_assistant,omitempty" example:"true"`

	// Auto-resolve conflicts
	// @example true
	AutoResolveConflicts *bool `json:"auto_resolve_conflicts,omitempty" example:"true"`

	// Send conflict notifications
	// @example true
	SendConflictNotifications *bool `json:"send_conflict_notifications,omitempty" example:"true"`

	// Alternative time suggestions if conflicts exist
	// @example 3
	AlternativeTimeCount *int `json:"alternative_time_count,omitempty" example:"3"`
}

// MEETING ATTENDANCE AND REPORTING REQUEST STRUCTURES

// UpdateAttendanceRequest represents a request to update meeting attendance
type UpdateAttendanceRequest struct {
	// Participant user ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Attendance status (present, absent, late, left_early)
	// @example "present"
	Status string `json:"status" binding:"required" example:"present"`

	// Join time
	// @example "2024-01-15T10:05:00Z"
	JoinTime *time.Time `json:"join_time,omitempty" example:"2024-01-15T10:05:00Z"`

	// Leave time
	// @example "2024-01-15T10:55:00Z"
	LeaveTime *time.Time `json:"leave_time,omitempty" example:"2024-01-15T10:55:00Z"`

	// Duration in meeting (minutes)
	// @example 50
	DurationMinutes *int `json:"duration_minutes,omitempty" example:"50"`

	// Connection quality metrics
	ConnectionQuality *ConnectionQualityRequest `json:"connection_quality,omitempty"`
}

// ConnectionQualityRequest represents connection quality metrics
type ConnectionQualityRequest struct {
	// Audio quality score (1-5)
	// @example 4
	AudioQuality *int `json:"audio_quality,omitempty" example:"4"`

	// Video quality score (1-5)
	// @example 5
	VideoQuality *int `json:"video_quality,omitempty" example:"5"`

	// Network stability score (1-5)
	// @example 4
	NetworkStability *int `json:"network_stability,omitempty" example:"4"`

	// Average latency in milliseconds
	// @example 45
	AverageLatency *int `json:"average_latency,omitempty" example:"45"`

	// Packet loss percentage
	// @example 0.5
	PacketLoss *float64 `json:"packet_loss,omitempty" example:"0.5"`
}

// GenerateAttendanceReportRequest represents a request to generate attendance report
type GenerateAttendanceReportRequest struct {
	// Report format (pdf, csv, json)
	// @example "pdf"
	Format string `json:"format" binding:"required" example:"pdf"`

	// Include detailed metrics
	// @example true
	IncludeMetrics *bool `json:"include_metrics,omitempty" example:"true"`

	// Include connection quality data
	// @example true
	IncludeQualityData *bool `json:"include_quality_data,omitempty" example:"true"`

	// Email report to organizer
	// @example true
	EmailToOrganizer *bool `json:"email_to_organizer,omitempty" example:"true"`

	// Additional email recipients
	AdditionalRecipients []string `json:"additional_recipients,omitempty"`
}

// MEETING CHAT AND FILE SHARING REQUEST STRUCTURES

// SendMeetingChatMessageRequest represents a request to send a chat message
type SendMeetingChatMessageRequest struct {
	// Message content
	// @example "Hello everyone, let's get started!"
	Content string `json:"content" binding:"required,max=4000" example:"Hello everyone, let's get started!"`

	// Message type (text, file, image, link, poll_result)
	// @example "text"
	MessageType *string `json:"message_type,omitempty" example:"text"`

	// Recipient user ID (for private messages)
	// @example "01HXYZ123456789ABCDEFGHIJK"
	RecipientID *string `json:"recipient_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Reply to message ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	ReplyToMessageID *string `json:"reply_to_message_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Message metadata (for rich content)
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Mentions in the message
	Mentions []MentionRequest `json:"mentions,omitempty"`

	// File attachments
	Attachments []FileAttachmentRequest `json:"attachments,omitempty"`
}

// MentionRequest represents a user mention in chat
type MentionRequest struct {
	// Mentioned user ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `json:"user_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Display name
	// @example "John Doe"
	DisplayName string `json:"display_name" binding:"required" example:"John Doe"`

	// Position in message (character index)
	// @example 5
	Position int `json:"position" example:"5"`

	// Length of mention text
	// @example 8
	Length int `json:"length" example:"8"`
}

// FileAttachmentRequest represents a file attachment
type FileAttachmentRequest struct {
	// File name
	// @example "presentation.pptx"
	FileName string `json:"file_name" binding:"required" example:"presentation.pptx"`

	// File size in bytes
	// @example 2048576
	FileSize int64 `json:"file_size" binding:"required" example:"2048576"`

	// File type/MIME type
	// @example "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	FileType string `json:"file_type" binding:"required" example:"application/vnd.openxmlformats-officedocument.presentationml.presentation"`

	// File URL or path
	// @example "https://example.com/files/presentation.pptx"
	FileURL string `json:"file_url" binding:"required" example:"https://example.com/files/presentation.pptx"`

	// Thumbnail URL (for images/videos)
	// @example "https://example.com/thumbnails/presentation_thumb.jpg"
	ThumbnailURL *string `json:"thumbnail_url,omitempty" example:"https://example.com/thumbnails/presentation_thumb.jpg"`

	// File description
	// @example "Q4 Sales Presentation"
	Description *string `json:"description,omitempty" example:"Q4 Sales Presentation"`
}

// MEETING QUALITY AND FEEDBACK REQUEST STRUCTURES

// SubmitMeetingFeedbackRequest represents a request to submit meeting feedback
type SubmitMeetingFeedbackRequest struct {
	// Overall meeting rating (1-5)
	// @example 4
	OverallRating int `json:"overall_rating" binding:"required,min=1,max=5" example:"4"`

	// Audio quality rating (1-5)
	// @example 5
	AudioQuality *int `json:"audio_quality,omitempty,min=1,max=5" example:"5"`

	// Video quality rating (1-5)
	// @example 4
	VideoQuality *int `json:"video_quality,omitempty,min=1,max=5" example:"4"`

	// Meeting organization rating (1-5)
	// @example 5
	OrganizationRating *int `json:"organization_rating,omitempty,min=1,max=5" example:"5"`

	// Content relevance rating (1-5)
	// @example 4
	ContentRelevance *int `json:"content_relevance,omitempty,min=1,max=5" example:"4"`

	// Written feedback
	// @example "Great meeting! The presentation was very informative."
	Comments *string `json:"comments,omitempty,max=2000" example:"Great meeting! The presentation was very informative."`

	// Specific issues encountered
	Issues []string `json:"issues,omitempty"`

	// Suggestions for improvement
	// @example "Could use better lighting in the conference room"
	Suggestions *string `json:"suggestions,omitempty,max=1000" example:"Could use better lighting in the conference room"`

	// Would recommend this meeting format
	// @example true
	WouldRecommend *bool `json:"would_recommend,omitempty" example:"true"`

	// Anonymous feedback
	// @example false
	IsAnonymous *bool `json:"is_anonymous,omitempty" example:"false"`
}

// ReportMeetingIssueRequest represents a request to report a meeting issue
type ReportMeetingIssueRequest struct {
	// Issue category (audio, video, connection, content, other)
	// @example "audio"
	Category string `json:"category" binding:"required" example:"audio"`

	// Issue severity (low, medium, high, critical)
	// @example "medium"
	Severity string `json:"severity" binding:"required" example:"medium"`

	// Issue description
	// @example "Audio kept cutting out during the presentation"
	Description string `json:"description" binding:"required,max=2000" example:"Audio kept cutting out during the presentation"`

	// When the issue occurred
	// @example "2024-01-15T10:30:00Z"
	OccurredAt *time.Time `json:"occurred_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Steps to reproduce
	Steps []string `json:"steps,omitempty"`

	// User's device information
	DeviceInfo *DeviceInfoRequest `json:"device_info,omitempty"`

	// Screenshots or recordings
	Attachments []string `json:"attachments,omitempty"`
}

// DeviceInfoRequest represents device information for issue reporting
type DeviceInfoRequest struct {
	// Operating system
	// @example "Windows 11"
	OS *string `json:"os,omitempty" example:"Windows 11"`

	// Browser name and version
	// @example "Chrome 120.0.0.0"
	Browser *string `json:"browser,omitempty" example:"Chrome 120.0.0.0"`

	// Device type (desktop, laptop, tablet, mobile)
	// @example "laptop"
	DeviceType *string `json:"device_type,omitempty" example:"laptop"`

	// Camera information
	// @example "Logitech C920"
	Camera *string `json:"camera,omitempty" example:"Logitech C920"`

	// Microphone information
	// @example "Blue Yeti"
	Microphone *string `json:"microphone,omitempty" example:"Blue Yeti"`

	// Network connection type (wifi, ethernet, cellular)
	// @example "wifi"
	NetworkType *string `json:"network_type,omitempty" example:"wifi"`
}
