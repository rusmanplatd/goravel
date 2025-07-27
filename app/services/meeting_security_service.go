package services

import (
	"fmt"
	"goravel/app/models"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

// MeetingSecurityService handles meeting security and access control
type MeetingSecurityService struct {
	meetingService *MeetingService
}

// NewMeetingSecurityService creates a new meeting security service
func NewMeetingSecurityService() *MeetingSecurityService {
	return &MeetingSecurityService{
		meetingService: NewMeetingService(),
	}
}

// MeetingSecurityPolicy represents meeting security policies
type MeetingSecurityPolicy struct {
	RequireWaitingRoom     bool     `json:"require_waiting_room"`
	RequirePassword        bool     `json:"require_password"`
	AllowAnonymousJoin     bool     `json:"allow_anonymous_join"`
	MaxParticipants        int      `json:"max_participants"`
	AllowedDomains         []string `json:"allowed_domains"`
	BlockedUsers           []string `json:"blocked_users"`
	RequireRegistration    bool     `json:"require_registration"`
	EnableEndToEndEncrypt  bool     `json:"enable_e2e_encryption"`
	RecordingPermissions   string   `json:"recording_permissions"`    // host, all, none
	ScreenSharePermissions string   `json:"screen_share_permissions"` // host, all, none
	ChatPermissions        string   `json:"chat_permissions"`         // host, all, none
	MuteOnEntry            bool     `json:"mute_on_entry"`
	DisableCamera          bool     `json:"disable_camera"`
	LockMeeting            bool     `json:"lock_meeting"`
}

// WaitingRoomParticipant represents a participant in the waiting room
type WaitingRoomParticipant struct {
	UserID        string                 `json:"user_id"`
	Name          string                 `json:"name"`
	Email         string                 `json:"email"`
	JoinTime      time.Time              `json:"join_time"`
	DeviceInfo    map[string]interface{} `json:"device_info"`
	RequestReason string                 `json:"request_reason,omitempty"`
	Status        string                 `json:"status"` // waiting, approved, denied
}

// MeetingSecurityEvent represents a security-related event
type MeetingSecurityEvent struct {
	ID          string                 `json:"id"`
	MeetingID   string                 `json:"meeting_id"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	UserID      string                 `json:"user_id,omitempty"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
}

// AccessControlResult represents the result of access control check
type AccessControlResult struct {
	Allowed          bool   `json:"allowed"`
	Reason           string `json:"reason,omitempty"`
	Action           string `json:"action"` // allow, deny, waiting_room
	RequiresApproval bool   `json:"requires_approval"`
}

// ApplySecurityPolicy applies security policies to a meeting
func (mss *MeetingSecurityService) ApplySecurityPolicy(meetingID string, policy *models.MeetingSecurityPolicy) error {
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update meeting security settings
	if policy.RequireWaitingRoom {
		meeting.WaitingRoom = "enabled"
	} else {
		meeting.WaitingRoom = "disabled"
	}

	meeting.MuteParticipantsOnEntry = policy.MuteOnEntry

	// Save the policy to database
	if err := facades.Orm().Query().Save(policy); err != nil {
		return fmt.Errorf("failed to save security policy: %v", err)
	}

	// Store additional security policies in metadata
	securityMetadata := map[string]interface{}{
		"max_participants":         policy.MaxParticipants,
		"allowed_domains":          policy.AllowedDomains,
		"blocked_users":            policy.BlockedUsers,
		"require_registration":     policy.RequireRegistration,
		"enable_e2e_encryption":    policy.EnableE2EEncryption,
		"recording_permissions":    policy.RecordingPermissions,
		"screen_share_permissions": policy.ScreenSharePermissions,
		"chat_permissions":         policy.ChatPermissions,
		"disable_camera":           policy.DisableCamera,
		"lock_meeting":             policy.LockMeeting,
	}

	// In a real implementation, you'd store this in a separate security_policies table
	// For now, we'll store it as JSON in a metadata field (if it exists)

	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to apply security policy: %v", err)
	}

	// Log security policy change
	mss.logSecurityEvent(meetingID, "policy_applied", "info", "", "Security policy applied to meeting", securityMetadata)

	return nil
}

// ValidateAccess validates if a user can access a meeting
func (mss *MeetingSecurityService) ValidateAccess(meetingID, userID string, deviceInfo map[string]interface{}) (*AccessControlResult, error) {
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return &AccessControlResult{
			Allowed: false,
			Reason:  "Meeting not found",
			Action:  "deny",
		}, nil
	}

	// Get user information
	var user models.User
	err = facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return &AccessControlResult{
			Allowed: false,
			Reason:  "User not found",
			Action:  "deny",
		}, nil
	}

	// Load security policy (simplified - in reality, you'd load from a security_policies table)
	policy := mss.getSecurityPolicy(meetingID)

	// Check if user is blocked
	if policy.IsUserBlocked(userID) {
		mss.logSecurityEvent(meetingID, "access_denied", "warning", userID, "User is blocked", map[string]interface{}{
			"reason": "blocked_user",
		})
		return &AccessControlResult{
			Allowed: false,
			Reason:  "Access denied: User is blocked",
			Action:  "deny",
		}, nil
	}

	// Check domain restrictions
	if len(policy.AllowedDomains) > 0 && !policy.IsDomainAllowed(mss.extractDomain(user.Email)) {
		mss.logSecurityEvent(meetingID, "access_denied", "warning", userID, "Domain not allowed", map[string]interface{}{
			"user_domain":     mss.extractDomain(user.Email),
			"allowed_domains": policy.AllowedDomains,
		})
		return &AccessControlResult{
			Allowed: false,
			Reason:  "Access denied: Domain not allowed",
			Action:  "deny",
		}, nil
	}

	// Check participant limit
	currentParticipants := mss.getCurrentParticipantCount(meetingID)
	if policy.MaxParticipants > 0 && currentParticipants >= policy.MaxParticipants {
		mss.logSecurityEvent(meetingID, "access_denied", "info", userID, "Meeting at capacity", map[string]interface{}{
			"current_participants": currentParticipants,
			"max_participants":     policy.MaxParticipants,
		})
		return &AccessControlResult{
			Allowed: false,
			Reason:  "Meeting is at maximum capacity",
			Action:  "deny",
		}, nil
	}

	// Check if meeting is locked
	if policy.LockMeeting && !mss.isHost(meetingID, userID) {
		mss.logSecurityEvent(meetingID, "access_denied", "info", userID, "Meeting is locked", nil)
		return &AccessControlResult{
			Allowed: false,
			Reason:  "Meeting is locked",
			Action:  "deny",
		}, nil
	}

	// Check if waiting room is required
	if policy.RequireWaitingRoom && !mss.isHost(meetingID, userID) {
		return &AccessControlResult{
			Allowed:          false,
			Reason:           "Waiting room approval required",
			Action:           "waiting_room",
			RequiresApproval: true,
		}, nil
	}

	// Log successful access validation
	mss.logSecurityEvent(meetingID, "access_granted", "info", userID, "User access validated", map[string]interface{}{
		"device_info": deviceInfo,
	})

	return &AccessControlResult{
		Allowed: true,
		Action:  "allow",
	}, nil
}

// AddToWaitingRoom adds a participant to the waiting room
func (mss *MeetingSecurityService) AddToWaitingRoom(meetingID, userID string, deviceInfo map[string]interface{}, reason string) error {
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Create waiting room entry (in a real implementation, this would be a separate table)
	waitingParticipant := WaitingRoomParticipant{
		UserID:        userID,
		Name:          user.Name,
		Email:         user.Email,
		JoinTime:      time.Now(),
		DeviceInfo:    deviceInfo,
		RequestReason: reason,
		Status:        "waiting",
	}

	// Store in cache or database (simplified implementation)
	// In production, you'd have a waiting_room_participants table

	// Notify host about waiting room participant
	mss.notifyHostAboutWaitingParticipant(meetingID, waitingParticipant)

	// Log waiting room event
	mss.logSecurityEvent(meetingID, "waiting_room_join", "info", userID, "User added to waiting room", map[string]interface{}{
		"reason":      reason,
		"device_info": deviceInfo,
	})

	return nil
}

// ApproveWaitingRoomParticipant approves a participant from waiting room
func (mss *MeetingSecurityService) ApproveWaitingRoomParticipant(meetingID, hostUserID, participantUserID string) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can approve participants")
	}

	// Update waiting room status (simplified)
	// In production, you'd update the waiting_room_participants table

	// Allow participant to join
	mss.logSecurityEvent(meetingID, "waiting_room_approved", "info", hostUserID, "Participant approved from waiting room", map[string]interface{}{
		"approved_user": participantUserID,
	})

	// Notify participant of approval
	mss.notifyParticipantApproval(meetingID, participantUserID, true)

	return nil
}

// DenyWaitingRoomParticipant denies a participant from waiting room
func (mss *MeetingSecurityService) DenyWaitingRoomParticipant(meetingID, hostUserID, participantUserID string, reason string) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can deny participants")
	}

	// Update waiting room status (simplified)
	// In production, you'd update the waiting_room_participants table

	mss.logSecurityEvent(meetingID, "waiting_room_denied", "info", hostUserID, "Participant denied from waiting room", map[string]interface{}{
		"denied_user": participantUserID,
		"reason":      reason,
	})

	// Notify participant of denial
	mss.notifyParticipantApproval(meetingID, participantUserID, false)

	return nil
}

// GetWaitingRoomParticipants returns participants in waiting room
func (mss *MeetingSecurityService) GetWaitingRoomParticipants(meetingID string) ([]WaitingRoomParticipant, error) {
	// In production, you'd query the waiting_room_participants table
	// For now, return empty slice
	return []WaitingRoomParticipant{}, nil
}

// RemoveParticipant removes a participant from the meeting (kick/ban)
func (mss *MeetingSecurityService) RemoveParticipant(meetingID, hostUserID, participantUserID string, reason string, ban bool) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can remove participants")
	}

	// Remove participant from meeting
	err := mss.meetingService.LeaveMeeting(meetingID, participantUserID)
	if err != nil {
		return fmt.Errorf("failed to remove participant: %v", err)
	}

	// If banning, add to blocked users list
	if ban {
		mss.addToBlockedUsers(meetingID, participantUserID)
	}

	eventType := "participant_removed"
	if ban {
		eventType = "participant_banned"
	}

	mss.logSecurityEvent(meetingID, eventType, "warning", hostUserID, "Participant removed from meeting", map[string]interface{}{
		"removed_user": participantUserID,
		"reason":       reason,
		"banned":       ban,
	})

	// Notify participant
	mss.notifyParticipantRemoval(meetingID, participantUserID, reason, ban)

	return nil
}

// MuteParticipant mutes a specific participant
func (mss *MeetingSecurityService) MuteParticipant(meetingID, hostUserID, participantUserID string, mute bool) error {
	// Verify host permissions or self-mute
	if hostUserID != participantUserID && !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can mute other participants")
	}

	// Update participant mute status (this would integrate with LiveKit or similar)
	// For now, we'll just log the event

	action := "unmuted"
	if mute {
		action = "muted"
	}

	mss.logSecurityEvent(meetingID, "participant_"+action, "info", hostUserID, fmt.Sprintf("Participant %s", action), map[string]interface{}{
		"target_user": participantUserID,
		"muted":       mute,
	})

	return nil
}

// DisableParticipantCamera disables a participant's camera
func (mss *MeetingSecurityService) DisableParticipantCamera(meetingID, hostUserID, participantUserID string, disable bool) error {
	// Verify host permissions or self-control
	if hostUserID != participantUserID && !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can control other participants' cameras")
	}

	// Update participant camera status (this would integrate with LiveKit or similar)
	// For now, we'll just log the event

	action := "enabled"
	if disable {
		action = "disabled"
	}

	mss.logSecurityEvent(meetingID, "participant_camera_"+action, "info", hostUserID, fmt.Sprintf("Participant camera %s", action), map[string]interface{}{
		"target_user": participantUserID,
		"disabled":    disable,
	})

	return nil
}

// LockMeeting locks/unlocks a meeting
func (mss *MeetingSecurityService) LockMeeting(meetingID, hostUserID string, lock bool) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can lock meetings")
	}

	// Update meeting lock status
	policy := mss.getSecurityPolicy(meetingID)
	policy.LockMeeting = lock

	err := mss.ApplySecurityPolicy(meetingID, policy)
	if err != nil {
		return fmt.Errorf("failed to update meeting lock status: %v", err)
	}

	action := "unlocked"
	if lock {
		action = "locked"
	}

	mss.logSecurityEvent(meetingID, "meeting_"+action, "info", hostUserID, fmt.Sprintf("Meeting %s", action), map[string]interface{}{
		"locked": lock,
	})

	return nil
}

// GetSecurityEvents returns security events for a meeting
func (mss *MeetingSecurityService) GetSecurityEvents(meetingID string, limit int) ([]MeetingSecurityEvent, error) {
	// In production, you'd query a security_events table
	// For now, return empty slice
	return []MeetingSecurityEvent{}, nil
}

// MonitorMeetingSecurity monitors ongoing security threats
func (mss *MeetingSecurityService) MonitorMeetingSecurity(meetingID string) ([]MeetingSecurityEvent, error) {
	// Simplified monitoring - return basic security status
	participants := mss.getCurrentParticipants(meetingID)

	events := []MeetingSecurityEvent{}

	// Basic monitoring - check for large meetings
	if len(participants) > 50 {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "large_meeting",
			Severity:    "info",
			Description: fmt.Sprintf("Large meeting with %d participants", len(participants)),
			Metadata: map[string]interface{}{
				"participant_count": len(participants),
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	return events, nil
}

// Helper methods

func (mss *MeetingSecurityService) getSecurityPolicy(meetingID string) *models.MeetingSecurityPolicy {
	// Load policy from database
	var policy models.MeetingSecurityPolicy
	err := facades.Orm().Query().Where("meeting_id", meetingID).First(&policy)
	if err != nil {
		// Create default policy if none exists
		defaultPolicy := models.GetDefaultSecurityPolicy()
		defaultPolicy.MeetingID = meetingID

		if createErr := facades.Orm().Query().Create(defaultPolicy); createErr != nil {
			facades.Log().Error("Failed to create default security policy", map[string]interface{}{
				"meeting_id": meetingID,
				"error":      createErr.Error(),
			})
			// Return in-memory default policy
			return defaultPolicy
		}
		return defaultPolicy
	}

	return &policy
}

func (mss *MeetingSecurityService) isUserBlocked(userID string, blockedUsers []string) bool {
	for _, blocked := range blockedUsers {
		if blocked == userID {
			return true
		}
	}
	return false
}

func (mss *MeetingSecurityService) isDomainAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true // No restrictions
	}

	domain := mss.extractDomain(email)
	for _, allowed := range allowedDomains {
		if allowed == domain {
			return true
		}
	}
	return false
}

func (mss *MeetingSecurityService) extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func (mss *MeetingSecurityService) getCurrentParticipantCount(meetingID string) int {
	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id = ? AND status = ?", meetingID, "joined").Find(&participants)
	return len(participants)
}

func (mss *MeetingSecurityService) getCurrentParticipants(meetingID string) []models.MeetingParticipant {
	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id = ? AND status = ?", meetingID, "joined").Find(&participants)
	return participants
}

func (mss *MeetingSecurityService) isHost(meetingID, userID string) bool {
	// Check if user is the host of the meeting
	// This would typically check the calendar event creator or meeting host field
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return false
	}

	// Get the associated calendar event to check creator
	var event models.CalendarEvent
	err = facades.Orm().Query().Where("id", meeting.EventID).First(&event)
	if err != nil {
		return false
	}

	return event.CreatedBy != nil && *event.CreatedBy == userID
}

func (mss *MeetingSecurityService) getRecentJoins(meetingID string, duration time.Duration) []models.MeetingParticipant {
	var participants []models.MeetingParticipant
	since := time.Now().Add(-duration)
	facades.Orm().Query().
		Where("meeting_id = ? AND joined_at >= ?", meetingID, since).
		Find(&participants)
	return participants
}

func (mss *MeetingSecurityService) addToBlockedUsers(meetingID, userID string) {
	// In production, you'd update the security policy or blocked users table
	// For now, we'll just log it
	mss.logSecurityEvent(meetingID, "user_blocked", "warning", "", "User added to blocked list", map[string]interface{}{
		"blocked_user": userID,
	})
}

func (mss *MeetingSecurityService) logSecurityEvent(meetingID, eventType, severity, userID, description string, metadata map[string]interface{}) {
	// In production, you'd store this in a security_events table
	facades.Log().Info("Security Event", map[string]interface{}{
		"meeting_id":  meetingID,
		"event_type":  eventType,
		"severity":    severity,
		"user_id":     userID,
		"description": description,
		"metadata":    metadata,
		"timestamp":   time.Now(),
	})
}

func (mss *MeetingSecurityService) generateEventID() string {
	// Generate a unique event ID
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

func (mss *MeetingSecurityService) notifyHostAboutWaitingParticipant(meetingID string, participant WaitingRoomParticipant) {
	// Send notification to host about waiting room participant
	// This would integrate with your notification system
}

func (mss *MeetingSecurityService) notifyParticipantApproval(meetingID, participantUserID string, approved bool) {
	// Notify participant about approval/denial
	// This would integrate with your notification system
}

func (mss *MeetingSecurityService) notifyParticipantRemoval(meetingID, participantUserID, reason string, banned bool) {
	// Notify participant about removal/ban
	// This would integrate with your notification system
}
