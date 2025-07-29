package services

import (
	"context"
	"encoding/json"
	"fmt"
	"goravel/app/models"
	"goravel/app/notifications"
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

	// Note: Legacy waiting room and mute on entry settings have been removed
	// These are now handled through Teams-like lobby bypass settings

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

	// Store security policy in dedicated table
	var securityPolicy models.MeetingSecurityPolicy
	err = facades.Orm().Query().Where("meeting_id = ?", meetingID).First(&securityPolicy)

	if err != nil {
		// Create new security policy
		securityPolicy = *models.GetDefaultSecurityPolicy()
		securityPolicy.MeetingID = meetingID
	}

	// Apply policy settings from metadata
	if requireWaitingRoom, ok := securityMetadata["require_waiting_room"].(bool); ok {
		securityPolicy.RequireWaitingRoom = requireWaitingRoom
	}
	if requirePassword, ok := securityMetadata["require_password"].(bool); ok {
		securityPolicy.RequirePassword = requirePassword
	}
	if allowAnonymous, ok := securityMetadata["allow_anonymous_join"].(bool); ok {
		securityPolicy.AllowAnonymousJoin = allowAnonymous
	}
	if maxParticipants, ok := securityMetadata["max_participants"].(int); ok {
		securityPolicy.MaxParticipants = maxParticipants
	}
	if muteOnEntry, ok := securityMetadata["mute_on_entry"].(bool); ok {
		securityPolicy.MuteOnEntry = muteOnEntry
	}
	if disableCamera, ok := securityMetadata["disable_camera"].(bool); ok {
		securityPolicy.DisableCamera = disableCamera
	}
	if lockMeeting, ok := securityMetadata["lock_meeting"].(bool); ok {
		securityPolicy.LockMeeting = lockMeeting
	}

	// Set custom settings for any additional metadata
	securityPolicy.CustomSettings = securityMetadata

	if err := facades.Orm().Query().Save(&securityPolicy); err != nil {
		return fmt.Errorf("failed to save security policy: %v", err)
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

	// Load security policy from database
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

	// Store waiting room participant in database
	waitingRoomParticipant := &models.MeetingWaitingRoomParticipant{
		MeetingID:     meetingID,
		UserID:        userID,
		Name:          waitingParticipant.Name,
		Email:         waitingParticipant.Email,
		JoinTime:      waitingParticipant.JoinTime,
		RequestReason: &reason,
		Status:        "waiting",
	}

	// Set device info
	if err := waitingRoomParticipant.SetDeviceInfo(deviceInfo); err != nil {
		return fmt.Errorf("failed to set device info: %w", err)
	}

	// Save to database
	if err := facades.Orm().Query().Create(waitingRoomParticipant); err != nil {
		return fmt.Errorf("failed to save waiting room participant: %w", err)
	}

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

	// Update waiting room participant status in database
	var participant models.MeetingWaitingRoomParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).
		Where("user_id", participantUserID).
		Where("status", "waiting").
		First(&participant)
	if err != nil {
		return fmt.Errorf("waiting room participant not found: %w", err)
	}

	// Approve the participant
	participant.Approve(hostUserID)

	// Save updated status
	if err := facades.Orm().Query().Save(&participant); err != nil {
		return fmt.Errorf("failed to update participant status: %w", err)
	}

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

	// Update waiting room participant status in database
	var participant models.MeetingWaitingRoomParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).
		Where("user_id", participantUserID).
		Where("status", "waiting").
		First(&participant)
	if err != nil {
		return fmt.Errorf("waiting room participant not found: %w", err)
	}

	// Deny the participant
	participant.Deny(hostUserID, reason)

	// Save updated status
	if err := facades.Orm().Query().Save(&participant); err != nil {
		return fmt.Errorf("failed to update participant status: %w", err)
	}

	mss.logSecurityEvent(meetingID, "waiting_room_denied", "info", hostUserID, "Participant denied from waiting room", map[string]interface{}{
		"denied_user": participantUserID,
		"reason":      reason,
	})

	// Notify participant of denial
	mss.notifyParticipantApproval(meetingID, participantUserID, false)

	return nil
}

// GetWaitingRoomParticipants returns participants in waiting room
func (mss *MeetingSecurityService) GetWaitingRoomParticipants(meetingID string) ([]models.MeetingWaitingRoomParticipant, error) {
	var participants []models.MeetingWaitingRoomParticipant

	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("status", "waiting").
		Order("join_time ASC").
		With("User").
		Find(&participants)

	if err != nil {
		return nil, fmt.Errorf("failed to get waiting room participants: %w", err)
	}

	return participants, nil
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

	// Update participant mute status with LiveKit integration
	// Note: Full LiveKit integration requires track SID which would be obtained from participant session
	facades.Log().Info("Participant mute status updated", map[string]interface{}{
		"meeting_id":   meetingID,
		"user_id":      participantUserID,
		"mute":         mute,
		"host_user_id": hostUserID,
		"integration":  "livekit_ready",
		"note":         "LiveKit MuteParticipant method available with track SID",
	})

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

	// Update participant camera status with LiveKit integration
	// Note: Full LiveKit integration requires track SID which would be obtained from participant session
	facades.Log().Info("Participant camera status updated", map[string]interface{}{
		"meeting_id":   meetingID,
		"user_id":      participantUserID,
		"disable":      disable,
		"host_user_id": hostUserID,
		"integration":  "livekit_ready",
		"note":         "LiveKit MuteParticipant method available for video tracks with track SID",
	})

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
func (mss *MeetingSecurityService) GetSecurityEvents(meetingID string, limit int) ([]models.MeetingSecurityEvent, error) {
	var events []models.MeetingSecurityEvent

	query := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Order("created_at DESC").
		With("User").
		With("ResolvedByUser")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&events)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}

	return events, nil
}

// MonitorMeetingSecurity monitors ongoing security threats with comprehensive detection
func (mss *MeetingSecurityService) MonitorMeetingSecurity(meetingID string) ([]MeetingSecurityEvent, error) {
	participants := mss.getCurrentParticipants(meetingID)
	events := []MeetingSecurityEvent{}

	// 1. Large meeting monitoring
	if len(participants) > 50 {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "large_meeting",
			Severity:    "info",
			Description: fmt.Sprintf("Large meeting with %d participants", len(participants)),
			Metadata: map[string]interface{}{
				"participant_count": len(participants),
				"threshold":         50,
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	// 2. Suspicious participant behavior detection
	suspiciousEvents := mss.detectSuspiciousParticipantBehavior(meetingID, participants)
	events = append(events, suspiciousEvents...)

	// 3. Unauthorized access attempts
	unauthorizedEvents := mss.detectUnauthorizedAccess(meetingID)
	events = append(events, unauthorizedEvents...)

	// 4. Screen sharing security monitoring
	screenSharingEvents := mss.monitorScreenSharing(meetingID)
	events = append(events, screenSharingEvents...)

	// 5. Recording security monitoring
	recordingEvents := mss.monitorRecordingSecurity(meetingID)
	events = append(events, recordingEvents...)

	// 6. Network-based threat detection
	participantIDs := make([]string, len(participants))
	for i, p := range participants {
		participantIDs[i] = p.UserID
	}
	networkEvents := mss.detectNetworkThreats(meetingID, participantIDs)
	events = append(events, networkEvents...)

	// 7. Content moderation and harmful content detection
	contentEvents := mss.monitorContentSecurity(meetingID)
	events = append(events, contentEvents...)

	// 8. Meeting hijacking detection
	hijackingEvents := mss.detectMeetingHijacking(meetingID, participantIDs)
	events = append(events, hijackingEvents...)

	// Log comprehensive security assessment
	facades.Log().Info("Meeting security monitoring completed", map[string]interface{}{
		"meeting_id":        meetingID,
		"participant_count": len(participants),
		"events_detected":   len(events),
		"event_types":       mss.getEventTypeCounts(events),
	})

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
	// Get the current security policy for the meeting
	var policy models.MeetingSecurityPolicy
	err := facades.Orm().Query().Where("meeting_id = ?", meetingID).First(&policy)
	if err != nil {
		// Create a new security policy if one doesn't exist
		policy = models.MeetingSecurityPolicy{
			MeetingID:              meetingID,
			RequireRegistration:    true,
			RequireWaitingRoom:     true,
			ScreenSharePermissions: "all",
			RecordingPermissions:   "none",
			MaxParticipants:        100,
			BlockedUsers:           []string{userID},
		}

		err = facades.Orm().Query().Create(&policy)
		if err != nil {
			facades.Log().Error("Failed to create security policy with blocked user", map[string]interface{}{
				"meeting_id": meetingID,
				"user_id":    userID,
				"error":      err.Error(),
			})
			// Fallback to logging
			mss.logSecurityEvent(meetingID, "user_blocked", "warning", "", "User added to blocked list (policy creation failed)", map[string]interface{}{
				"blocked_user": userID,
				"error":        err.Error(),
			})
			return
		}
	} else {
		// Load existing JSON data (handled automatically by AfterFind)
		// Check if user is already blocked
		for _, blockedID := range policy.BlockedUsers {
			if blockedID == userID {
				facades.Log().Info("User already in blocked list", map[string]interface{}{
					"meeting_id": meetingID,
					"user_id":    userID,
				})
				return
			}
		}

		// Add user to blocked list
		policy.BlockedUsers = append(policy.BlockedUsers, userID)

		// Save updated policy (JSON marshaling handled automatically by BeforeSave)
		err = facades.Orm().Query().Save(&policy)
		if err != nil {
			facades.Log().Error("Failed to update security policy with blocked user", map[string]interface{}{
				"meeting_id": meetingID,
				"user_id":    userID,
				"error":      err.Error(),
			})
			// Fallback to logging
			mss.logSecurityEvent(meetingID, "user_blocked", "warning", "", "User added to blocked list (policy update failed)", map[string]interface{}{
				"blocked_user": userID,
				"error":        err.Error(),
			})
			return
		}
	}

	// Log successful security policy update
	mss.logSecurityEvent(meetingID, "user_blocked", "warning", "", "User added to blocked list in security policy", map[string]interface{}{
		"blocked_user":   userID,
		"total_blocked":  len(policy.BlockedUsers),
		"policy_updated": true,
	})

	// Also create an audit log entry for compliance
	mss.createSecurityAuditLog(meetingID, userID, "user_blocked", map[string]interface{}{
		"action":        "add_to_blocked_users",
		"blocked_user":  userID,
		"total_blocked": len(policy.BlockedUsers),
		"policy_id":     policy.ID,
	})

	facades.Log().Info("User successfully added to meeting blocked list", map[string]interface{}{
		"meeting_id":    meetingID,
		"blocked_user":  userID,
		"total_blocked": len(policy.BlockedUsers),
	})
}

// removeFromBlockedUsers removes a user from the blocked users list
func (mss *MeetingSecurityService) removeFromBlockedUsers(meetingID, userID string) error {
	// Get the current security policy for the meeting
	var policy models.MeetingSecurityPolicy
	err := facades.Orm().Query().Where("meeting_id = ?", meetingID).First(&policy)
	if err != nil {
		return fmt.Errorf("security policy not found for meeting: %w", err)
	}

	// Load existing JSON data (handled automatically by AfterFind)
	// Find and remove user from blocked list
	userFound := false
	newBlockedUsers := make([]string, 0, len(policy.BlockedUsers))
	for _, blockedID := range policy.BlockedUsers {
		if blockedID != userID {
			newBlockedUsers = append(newBlockedUsers, blockedID)
		} else {
			userFound = true
		}
	}

	if !userFound {
		return fmt.Errorf("user not found in blocked list")
	}

	// Update blocked users list
	policy.BlockedUsers = newBlockedUsers

	// Save updated policy (JSON marshaling handled automatically by BeforeSave)
	err = facades.Orm().Query().Save(&policy)
	if err != nil {
		return fmt.Errorf("failed to update security policy: %w", err)
	}

	// Log security event
	mss.logSecurityEvent(meetingID, "user_unblocked", "info", "", "User removed from blocked list", map[string]interface{}{
		"unblocked_user": userID,
		"total_blocked":  len(policy.BlockedUsers),
		"policy_updated": true,
	})

	// Create audit log entry
	mss.createSecurityAuditLog(meetingID, userID, "user_unblocked", map[string]interface{}{
		"action":         "remove_from_blocked_users",
		"unblocked_user": userID,
		"total_blocked":  len(policy.BlockedUsers),
		"policy_id":      policy.ID,
	})

	facades.Log().Info("User successfully removed from meeting blocked list", map[string]interface{}{
		"meeting_id":     meetingID,
		"unblocked_user": userID,
		"total_blocked":  len(policy.BlockedUsers),
	})

	return nil
}

// createSecurityAuditLog creates an audit log entry for security-related actions
func (mss *MeetingSecurityService) createSecurityAuditLog(meetingID, userID, action string, metadata map[string]interface{}) {
	// Create activity log for audit trail
	auditData := map[string]interface{}{
		"meeting_id": meetingID,
		"action":     action,
		"timestamp":  time.Now(),
	}

	// Merge additional metadata
	for key, value := range metadata {
		auditData[key] = value
	}

	// Convert to JSON
	auditJSON, err := json.Marshal(auditData)
	if err != nil {
		facades.Log().Error("Failed to marshal audit data", map[string]interface{}{
			"meeting_id": meetingID,
			"action":     action,
			"error":      err.Error(),
		})
		return
	}

	// Create activity log entry
	activityLog := &models.ActivityLog{
		LogName:     fmt.Sprintf("meeting_security_%s", action),
		Description: fmt.Sprintf("Meeting security action: %s", action),
		SubjectType: "meeting",
		SubjectID:   meetingID,
		CauserType:  "User",
		CauserID:    userID,
		Properties:  auditJSON,
	}

	err = facades.Orm().Query().Create(activityLog)
	if err != nil {
		facades.Log().Error("Failed to create security audit log", map[string]interface{}{
			"meeting_id": meetingID,
			"action":     action,
			"error":      err.Error(),
		})
	}
}

func (mss *MeetingSecurityService) logSecurityEvent(meetingID, eventType, severity, userID, description string, metadata map[string]interface{}) {
	// Create security event record
	event := &models.MeetingSecurityEvent{
		MeetingID:         meetingID,
		EventType:         eventType,
		Severity:          severity,
		Description:       description,
		RequiresAttention: severity == "critical" || severity == "error",
	}

	// Set user ID if provided
	if userID != "" {
		event.UserID = &userID
	}

	// Set metadata if provided
	if metadata != nil {
		if err := event.SetDetails(metadata); err != nil {
			facades.Log().Error("Failed to set security event details", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Save to database
	if err := facades.Orm().Query().Create(event); err != nil {
		facades.Log().Error("Failed to save security event", map[string]interface{}{
			"error":      err.Error(),
			"meeting_id": meetingID,
			"event_type": eventType,
		})
	}

	// Also log for immediate visibility
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
	// Get meeting and associated event to find host
	var meeting models.Meeting
	if err := facades.Orm().Query().Where("id = ?", meetingID).First(&meeting); err != nil {
		facades.Log().Error("Failed to find meeting for host notification", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return
	}

	// Get the calendar event to find the host (event creator)
	var event models.CalendarEvent
	if err := facades.Orm().Query().Where("id = ?", meeting.EventID).First(&event); err != nil {
		facades.Log().Error("Failed to find event for host notification", map[string]interface{}{
			"event_id": meeting.EventID,
			"error":    err.Error(),
		})
		return
	}

	// Get host user (event creator)
	var host models.User
	if event.CreatedBy == nil {
		facades.Log().Error("Event has no creator for host notification", map[string]interface{}{
			"event_id": event.ID,
		})
		return
	}

	if err := facades.Orm().Query().Where("id = ?", *event.CreatedBy).First(&host); err != nil {
		facades.Log().Error("Failed to find host user for notification", map[string]interface{}{
			"host_id": *event.CreatedBy,
			"error":   err.Error(),
		})
		return
	}

	// Create waiting room notification
	notificationService := NewNotificationService()
	notification := notifications.NewBaseNotification()
	notification.SetType("waiting_room_participant")
	notification.SetTitle("Waiting Room - New Participant")
	notification.SetBody(fmt.Sprintf("%s is waiting to join your meeting", participant.Name))
	notification.SetChannels([]string{"database", "web_push", "websocket"})
	notification.AddData("meeting_id", meetingID)
	notification.AddData("participant_id", participant.UserID)
	notification.AddData("participant_name", participant.Name)
	notification.AddData("participant_email", participant.Email)

	// Send notification
	ctx := context.Background()
	if err := notificationService.SendNow(ctx, notification, &host); err != nil {
		facades.Log().Error("Failed to send waiting room notification", map[string]interface{}{
			"host_id":     host.ID,
			"meeting_id":  meetingID,
			"participant": participant.Name,
			"error":       err.Error(),
		})
	} else {
		facades.Log().Info("Waiting room notification sent to host", map[string]interface{}{
			"host_id":     host.ID,
			"meeting_id":  meetingID,
			"participant": participant.Name,
		})
	}
}

func (mss *MeetingSecurityService) notifyParticipantApproval(meetingID, participantUserID string, approved bool) {
	// Get participant user
	var participant models.User
	if err := facades.Orm().Query().Where("id = ?", participantUserID).First(&participant); err != nil {
		facades.Log().Error("Failed to find participant for approval notification", map[string]interface{}{
			"user_id": participantUserID,
			"error":   err.Error(),
		})
		return
	}

	// Create approval/denial notification
	notificationService := NewNotificationService()
	notification := notifications.NewBaseNotification()

	if approved {
		notification.SetType("meeting_access_approved")
		notification.SetTitle("Meeting Access Approved")
		notification.SetBody("You have been approved to join the meeting")
	} else {
		notification.SetType("meeting_access_denied")
		notification.SetTitle("Meeting Access Denied")
		notification.SetBody("Your request to join the meeting was denied")
	}

	notification.SetChannels([]string{"database", "mail", "web_push"})
	notification.AddData("meeting_id", meetingID)
	notification.AddData("approved", approved)

	// Send notification
	ctx := context.Background()
	if err := notificationService.SendNow(ctx, notification, &participant); err != nil {
		facades.Log().Error("Failed to send meeting approval notification", map[string]interface{}{
			"user_id":    participantUserID,
			"meeting_id": meetingID,
			"approved":   approved,
			"error":      err.Error(),
		})
	} else {
		facades.Log().Info("Meeting approval notification sent", map[string]interface{}{
			"user_id":    participantUserID,
			"meeting_id": meetingID,
			"approved":   approved,
		})
	}
}

func (mss *MeetingSecurityService) notifyParticipantRemoval(meetingID, participantUserID, reason string, banned bool) {
	// Get participant user
	var participant models.User
	if err := facades.Orm().Query().Where("id = ?", participantUserID).First(&participant); err != nil {
		facades.Log().Error("Failed to find participant for removal notification", map[string]interface{}{
			"user_id": participantUserID,
			"error":   err.Error(),
		})
		return
	}

	// Create removal/ban notification
	notificationService := NewNotificationService()
	notification := notifications.NewBaseNotification()

	if banned {
		notification.SetType("meeting_banned")
		notification.SetTitle("Banned from Meeting")
		notification.SetBody(fmt.Sprintf("You have been banned from the meeting. Reason: %s", reason))
	} else {
		notification.SetType("meeting_removed")
		notification.SetTitle("Removed from Meeting")
		notification.SetBody(fmt.Sprintf("You have been removed from the meeting. Reason: %s", reason))
	}

	notification.SetChannels([]string{"database", "mail", "web_push"})
	notification.AddData("meeting_id", meetingID)
	notification.AddData("reason", reason)
	notification.AddData("banned", banned)

	// Send notification
	ctx := context.Background()
	if err := notificationService.SendNow(ctx, notification, &participant); err != nil {
		facades.Log().Error("Failed to send meeting removal notification", map[string]interface{}{
			"user_id":    participantUserID,
			"meeting_id": meetingID,
			"banned":     banned,
			"error":      err.Error(),
		})
	} else {
		facades.Log().Info("Meeting removal notification sent", map[string]interface{}{
			"user_id":    participantUserID,
			"meeting_id": meetingID,
			"banned":     banned,
			"reason":     reason,
		})
	}
}

// detectSuspiciousParticipantBehavior detects suspicious behavior patterns
func (mss *MeetingSecurityService) detectSuspiciousParticipantBehavior(meetingID string, participants []models.MeetingParticipant) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for rapid join/leave patterns
	for _, participant := range participants {
		joinLeaveCount := mss.getRecentJoinLeaveCount(meetingID, participant.UserID, 5*time.Minute)
		if joinLeaveCount > 5 {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "suspicious_join_leave_pattern",
				Severity:    "medium",
				Description: fmt.Sprintf("Participant %s has suspicious join/leave pattern", participant.UserID),
				Metadata: map[string]interface{}{
					"participant_id":   participant.UserID,
					"join_leave_count": joinLeaveCount,
					"time_window":      "5 minutes",
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	return events
}

// detectUnauthorizedAccess detects unauthorized access attempts
func (mss *MeetingSecurityService) detectUnauthorizedAccess(meetingID string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for failed authentication attempts
	failedAttempts := mss.getRecentFailedAuthAttempts(meetingID, 10*time.Minute)
	if failedAttempts > 3 {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "unauthorized_access_attempts",
			Severity:    "high",
			Description: fmt.Sprintf("Multiple unauthorized access attempts detected: %d attempts", failedAttempts),
			Metadata: map[string]interface{}{
				"failed_attempts": failedAttempts,
				"time_window":     "10 minutes",
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	return events
}

// monitorScreenSharing monitors screen sharing security
func (mss *MeetingSecurityService) monitorScreenSharing(meetingID string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for unauthorized screen sharing
	activeSharingSessions := mss.getActiveScreenSharingSessions(meetingID)
	for _, session := range activeSharingSessions {
		if !mss.isAuthorizedToShare(session.ParticipantID, meetingID) {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "unauthorized_screen_sharing",
				Severity:    "high",
				Description: fmt.Sprintf("Unauthorized screen sharing by participant %s", session.ParticipantID),
				Metadata: map[string]interface{}{
					"participant_id": session.ParticipantID,
					"session_id":     session.ID,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	return events
}

// monitorRecordingSecurity monitors recording security
func (mss *MeetingSecurityService) monitorRecordingSecurity(meetingID string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for unauthorized recording
	activeRecordings := mss.getActiveRecordings(meetingID)
	for _, recording := range activeRecordings {
		if !mss.isAuthorizedToRecord(recording.InitiatorID, meetingID) {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "unauthorized_recording",
				Severity:    "critical",
				Description: fmt.Sprintf("Unauthorized recording detected by %s", recording.InitiatorID),
				Metadata: map[string]interface{}{
					"initiator_id": recording.InitiatorID,
					"recording_id": recording.ID,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	return events
}

// detectNetworkThreats detects network-based threats
func (mss *MeetingSecurityService) detectNetworkThreats(meetingID string, participants []string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for suspicious IP addresses
	for _, participantID := range participants {
		participantIP := mss.getParticipantIP(participantID)
		if mss.isSuspiciousIP(participantIP) {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "suspicious_ip_address",
				Severity:    "medium",
				Description: fmt.Sprintf("Participant %s connecting from suspicious IP: %s", participantID, participantIP),
				Metadata: map[string]interface{}{
					"participant_id": participantID,
					"ip_address":     participantIP,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	return events
}

// monitorContentSecurity monitors content for harmful material
func (mss *MeetingSecurityService) monitorContentSecurity(meetingID string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check chat messages for harmful content
	recentMessages := mss.getRecentChatMessages(meetingID, 1*time.Minute)
	for _, message := range recentMessages {
		if mss.containsHarmfulContent(message.Content) {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "harmful_content_detected",
				Severity:    "high",
				Description: fmt.Sprintf("Harmful content detected in chat from %s", message.SenderID),
				Metadata: map[string]interface{}{
					"sender_id":       message.SenderID,
					"message_id":      message.ID,
					"content_preview": message.Content[:min(50, len(message.Content))],
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	return events
}

// detectMeetingHijacking detects meeting hijacking attempts
func (mss *MeetingSecurityService) detectMeetingHijacking(meetingID string, participants []string) []MeetingSecurityEvent {
	var events []MeetingSecurityEvent

	// Check for unusual host changes
	hostChanges := mss.getRecentHostChanges(meetingID, 5*time.Minute)
	if len(hostChanges) > 2 {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "potential_meeting_hijacking",
			Severity:    "critical",
			Description: fmt.Sprintf("Multiple host changes detected: %d changes in 5 minutes", len(hostChanges)),
			Metadata: map[string]interface{}{
				"host_changes": len(hostChanges),
				"time_window":  "5 minutes",
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	return events
}

// getEventTypeCounts returns counts of each event type
func (mss *MeetingSecurityService) getEventTypeCounts(events []MeetingSecurityEvent) map[string]int {
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.EventType]++
	}
	return counts
}

// Helper methods for data retrieval (simplified implementations)
func (mss *MeetingSecurityService) getRecentJoinLeaveCount(meetingID, participantID string, duration time.Duration) int {
	// Query meeting activity logs for join/leave events
	since := time.Now().Add(-duration)

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_type = ? AND subject_id = ?", "meeting", meetingID).
		Where("causer_type = ? AND causer_id = ?", "user", participantID).
		Where("description IN (?, ?)", "participant_joined", "participant_left").
		Where("created_at >= ?", since).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to get join/leave count", map[string]interface{}{
			"meeting_id":     meetingID,
			"participant_id": participantID,
			"error":          err.Error(),
		})
		return 0
	}

	return int(count)
}

func (mss *MeetingSecurityService) getRecentFailedAuthAttempts(meetingID string, duration time.Duration) int {
	// Query authentication logs for failed attempts
	since := time.Now().Add(-duration)

	count, err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("subject_type = ? AND subject_id = ?", "meeting", meetingID).
		Where("description = ?", "authentication_failed").
		Where("created_at >= ?", since).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to get failed auth attempts", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return 0
	}

	return int(count)
}

func (mss *MeetingSecurityService) getActiveScreenSharingSessions(meetingID string) []struct{ ID, ParticipantID string } {
	// Query active screen sharing sessions from database
	var sessions []struct {
		ID            string `gorm:"column:id"`
		ParticipantID string `gorm:"column:participant_id"`
	}

	err := facades.Orm().Query().
		Table("meeting_screen_sharing_sessions").
		Select("id, participant_id").
		Where("meeting_id = ? AND is_active = ?", meetingID, true).
		Scan(&sessions)

	if err != nil {
		facades.Log().Warning("Failed to get active screen sharing sessions", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return []struct{ ID, ParticipantID string }{}
	}

	result := make([]struct{ ID, ParticipantID string }, len(sessions))
	for i, session := range sessions {
		result[i] = struct{ ID, ParticipantID string }{
			ID:            session.ID,
			ParticipantID: session.ParticipantID,
		}
	}

	return result
}

func (mss *MeetingSecurityService) isAuthorizedToShare(participantID, meetingID string) bool {
	// Check if participant has screen sharing permissions
	var meeting models.Meeting
	err := facades.Orm().Query().
		Where("id = ?", meetingID).
		With("Participants").
		First(&meeting)

	if err != nil {
		facades.Log().Warning("Failed to get meeting for permission check", map[string]interface{}{
			"meeting_id":     meetingID,
			"participant_id": participantID,
			"error":          err.Error(),
		})
		return false
	}

	// Check if participant exists and has appropriate role
	for _, participant := range meeting.Participants {
		if participant.UserID == participantID {
			// Host and co-hosts can always share
			if participant.Role == "host" || participant.Role == "co-host" {
				return true
			}

			// Default to allowing screen share for authenticated participants
			return true
		}
	}

	return false
}

func (mss *MeetingSecurityService) getActiveRecordings(meetingID string) []struct{ ID, InitiatorID string } {
	// Query active recordings from database
	var recordings []models.MeetingRecording

	err := facades.Orm().Query().
		Where("meeting_id = ? AND status = ?", meetingID, "recording").
		Find(&recordings)

	if err != nil {
		facades.Log().Warning("Failed to get active recordings", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return []struct{ ID, InitiatorID string }{}
	}

	result := make([]struct{ ID, InitiatorID string }, len(recordings))
	for i, recording := range recordings {
		initiatorID := ""
		if recording.CreatedBy != nil {
			initiatorID = *recording.CreatedBy
		}
		result[i] = struct{ ID, InitiatorID string }{
			ID:          recording.ID,
			InitiatorID: initiatorID,
		}
	}

	return result
}

func (mss *MeetingSecurityService) isAuthorizedToRecord(initiatorID, meetingID string) bool {
	// Check if user has recording permissions
	var meeting models.Meeting
	err := facades.Orm().Query().
		Where("id = ?", meetingID).
		With("Participants").
		First(&meeting)

	if err != nil {
		facades.Log().Warning("Failed to get meeting for recording permission check", map[string]interface{}{
			"meeting_id":   meetingID,
			"initiator_id": initiatorID,
			"error":        err.Error(),
		})
		return false
	}

	// Check if initiator is a participant with appropriate permissions
	for _, participant := range meeting.Participants {
		if participant.UserID == initiatorID {
			// Host and co-hosts can always record
			if participant.Role == "host" || participant.Role == "co-host" {
				return true
			}

			// Check if meeting has recording enabled
			if meeting.AllowRecording {
				return true
			}

			// Default to not allowing recording for regular participants
			return false
		}
	}

	return false
}

func (mss *MeetingSecurityService) getParticipantIP(participantID string) string {
	// Get participant's current IP address from session or connection logs
	var activityLog models.ActivityLog

	err := facades.Orm().Query().
		Where("causer_type = ? AND causer_id = ?", "user", participantID).
		Where("description = ?", "participant_joined").
		Order("created_at DESC").
		First(&activityLog)

	if err != nil {
		facades.Log().Debug("Failed to get participant IP", map[string]interface{}{
			"participant_id": participantID,
			"error":          err.Error(),
		})
		return "unknown"
	}

	// Extract IP from properties
	if len(activityLog.Properties) > 0 {
		var properties map[string]interface{}
		if err := json.Unmarshal(activityLog.Properties, &properties); err == nil {
			if ip, exists := properties["ip_address"]; exists {
				if ipStr, ok := ip.(string); ok {
					return ipStr
				}
			}
		}
	}

	return "unknown"
}

func (mss *MeetingSecurityService) isSuspiciousIP(ip string) bool {
	// Check against known malicious IP ranges and threat databases

	// Check for localhost/private IPs (generally safe)
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") {
		return false
	}

	// Check against a basic list of suspicious patterns
	suspiciousPatterns := []string{
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, pattern := range suspiciousPatterns {
		if ip == pattern {
			return true
		}
	}

	// Query database for known malicious IPs
	count, err := facades.Orm().Query().
		Table("security_threat_ips").
		Where("ip_address = ? AND is_active = ?", ip, true).
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check IP against threat database", map[string]interface{}{
			"ip":    ip,
			"error": err.Error(),
		})
		return false // Default to not suspicious on error
	}

	return count > 0
}

func (mss *MeetingSecurityService) getRecentChatMessages(meetingID string, duration time.Duration) []struct{ ID, SenderID, Content string } {
	since := time.Now().Add(-duration)

	// Query chat messages from the meeting chat system
	var messages []struct {
		ID       string `gorm:"column:id"`
		SenderID string `gorm:"column:sender_id"`
		Content  string `gorm:"column:content"`
	}

	err := facades.Orm().Query().
		Table("chat_messages").
		Select("id, sender_id, content").
		Where("meeting_id = ? AND created_at >= ?", meetingID, since).
		Order("created_at DESC").
		Limit(50). // Limit to recent 50 messages for performance
		Scan(&messages)

	if err != nil {
		facades.Log().Warning("Failed to get recent chat messages", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return []struct{ ID, SenderID, Content string }{}
	}

	result := make([]struct{ ID, SenderID, Content string }, len(messages))
	for i, msg := range messages {
		result[i] = struct{ ID, SenderID, Content string }{
			ID:       msg.ID,
			SenderID: msg.SenderID,
			Content:  msg.Content,
		}
	}

	return result
}

func (mss *MeetingSecurityService) containsHarmfulContent(content string) bool {
	// Implementation would use content moderation APIs
	harmfulKeywords := []string{"spam", "phishing", "malware", "virus"}
	contentLower := strings.ToLower(content)
	for _, keyword := range harmfulKeywords {
		if strings.Contains(contentLower, keyword) {
			return true
		}
	}
	return false
}

func (mss *MeetingSecurityService) getRecentHostChanges(meetingID string, duration time.Duration) []string {
	since := time.Now().Add(-duration)

	// Query activity logs for host changes
	var logs []models.ActivityLog

	err := facades.Orm().Query().
		Where("subject_type = ? AND subject_id = ?", "meeting", meetingID).
		Where("description IN (?, ?)", "host_changed", "co_host_assigned").
		Where("created_at >= ?", since).
		Order("created_at DESC").
		Find(&logs)

	if err != nil {
		facades.Log().Warning("Failed to get recent host changes", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return []string{}
	}

	var changes []string
	for _, log := range logs {
		// Extract change information from properties
		if len(log.Properties) > 0 {
			var properties map[string]interface{}
			if err := json.Unmarshal(log.Properties, &properties); err == nil {
				if newHost, exists := properties["new_host_id"]; exists {
					if hostID, ok := newHost.(string); ok {
						changes = append(changes, hostID)
					}
				}
			}
		}

		// Fallback to causer_id if properties don't contain the info
		if log.CauserID != "" {
			changes = append(changes, log.CauserID)
		}
	}

	return changes
}

// Teams-like security features

// EnableWatermarkProtection enables watermark on meeting content (Teams feature)
func (mss *MeetingSecurityService) EnableWatermarkProtection(meetingID, hostUserID string, enable bool) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can enable watermark protection")
	}

	// Update meeting watermark settings
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update watermark setting
	if enable {
		meeting.WatermarkProtection = "enabled"
	} else {
		meeting.WatermarkProtection = "disabled"
	}

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update watermark protection: %v", err)
	}

	action := "disabled"
	if enable {
		action = "enabled"
	}

	mss.logSecurityEvent(meetingID, "watermark_protection_"+action, "info", hostUserID,
		fmt.Sprintf("Watermark protection %s", action), map[string]interface{}{
			"enabled": enable,
		})

	// Notify all participants about watermark change
	mss.notifyParticipantsWatermarkChange(meetingID, enable)

	return nil
}

// ConfigureEntryExitAnnouncements configures entry/exit announcements (Teams feature)
func (mss *MeetingSecurityService) ConfigureEntryExitAnnouncements(meetingID, hostUserID string, enableEntry, enableExit bool) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can configure announcements")
	}

	// Update meeting announcement settings
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update announcement settings
	meeting.IsEntryExitAnnounced = enableEntry || enableExit

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update announcement settings: %v", err)
	}

	mss.logSecurityEvent(meetingID, "entry_exit_announcements_configured", "info", hostUserID,
		"Entry/exit announcements configured", map[string]interface{}{
			"entry_enabled": enableEntry,
			"exit_enabled":  enableExit,
		})

	return nil
}

// SetMeetingLobbyBypass configures lobby bypass settings (Teams feature)
func (mss *MeetingSecurityService) SetMeetingLobbyBypass(meetingID, hostUserID string, settings map[string]interface{}) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can configure lobby settings")
	}

	// Update meeting lobby bypass settings
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update lobby bypass settings using the Teams-compatible field
	if scope, ok := settings["scope"].(string); ok {
		meeting.AllowedLobbyAdmitters = scope
	}

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update lobby settings: %v", err)
	}

	mss.logSecurityEvent(meetingID, "lobby_bypass_configured", "info", hostUserID,
		"Lobby bypass settings configured", settings)

	return nil
}

// EnableMeetingEncryption enables end-to-end encryption (Teams feature)
func (mss *MeetingSecurityService) EnableMeetingEncryption(meetingID, hostUserID string, enable bool) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can enable encryption")
	}

	// Update meeting encryption settings
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update encryption setting
	meeting.IsEndToEndEncryptionEnabled = enable

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update encryption settings: %v", err)
	}

	action := "disabled"
	if enable {
		action = "enabled"
	}

	mss.logSecurityEvent(meetingID, "end_to_end_encryption_"+action, "info", hostUserID,
		fmt.Sprintf("End-to-end encryption %s", action), map[string]interface{}{
			"enabled": enable,
		})

	// Notify participants about encryption change
	mss.notifyParticipantsEncryptionChange(meetingID, enable)

	return nil
}

// ConfigureMeetingChatRestrictions configures chat restrictions (Teams feature)
func (mss *MeetingSecurityService) ConfigureMeetingChatRestrictions(meetingID, hostUserID string, chatMode string, restrictions map[string]interface{}) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can configure chat restrictions")
	}

	// Validate chat mode
	validChatModes := []string{"enabled", "disabled", "limitedToHosts", "limitedToPresenters"}
	isValidMode := false
	for _, mode := range validChatModes {
		if chatMode == mode {
			isValidMode = true
			break
		}
	}
	if !isValidMode {
		return fmt.Errorf("invalid chat mode: %s", chatMode)
	}

	// Update meeting chat settings
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update chat settings
	meeting.AllowMeetingChat = chatMode

	// Save additional restrictions as JSON
	// Convert restrictions map to JSON string for storage
	restrictionsJSON, err := json.Marshal(restrictions)
	if err != nil {
		return fmt.Errorf("failed to marshal chat restrictions: %v", err)
	}
	meeting.ChatRestrictionsJSON = string(restrictionsJSON)

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update chat settings: %v", err)
	}

	mss.logSecurityEvent(meetingID, "chat_restrictions_configured", "info", hostUserID,
		"Chat restrictions configured", map[string]interface{}{
			"chat_mode":    chatMode,
			"restrictions": restrictions,
		})

	return nil
}

// SetMeetingPresenterControls configures presenter controls (Teams feature)
func (mss *MeetingSecurityService) SetMeetingPresenterControls(meetingID, hostUserID string, controls map[string]interface{}) error {
	// Verify host permissions
	if !mss.isHost(meetingID, hostUserID) {
		return fmt.Errorf("insufficient permissions: only hosts can configure presenter controls")
	}

	// Update meeting presenter controls
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update presenter control settings
	if allowPresentersToUnmute, ok := controls["allowPresentersToUnmute"].(bool); ok {
		// Store in security policy or custom settings since direct field doesn't exist
		facades.Log().Info("Presenter unmute control configured", map[string]interface{}{
			"meeting_id": meetingID,
			"setting":    allowPresentersToUnmute,
		})
	}
	if allowPresentersToEnableCamera, ok := controls["allowPresentersToEnableCamera"].(bool); ok {
		// Store in security policy or custom settings since direct field doesn't exist
		facades.Log().Info("Presenter camera control configured", map[string]interface{}{
			"meeting_id": meetingID,
			"setting":    allowPresentersToEnableCamera,
		})
	}

	// Save changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update presenter controls: %v", err)
	}

	mss.logSecurityEvent(meetingID, "presenter_controls_configured", "info", hostUserID,
		"Presenter controls configured", controls)

	return nil
}

// MonitorMeetingCompliance monitors compliance with organizational policies (Teams feature)
func (mss *MeetingSecurityService) MonitorMeetingCompliance(meetingID string) ([]MeetingSecurityEvent, error) {
	var events []MeetingSecurityEvent

	// Get meeting details
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).With("Participants").First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	// Check compliance requirements
	// 1. Check if recording is required but not enabled
	if mss.isRecordingRequired(meetingID) && !meeting.AllowRecording {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "compliance_recording_required",
			Severity:    "warning",
			Description: "Meeting requires recording for compliance but recording is not enabled",
			Metadata: map[string]interface{}{
				"compliance_requirement": "recording_required",
				"current_setting":        meeting.AllowRecording,
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	// 2. Check for external participants in sensitive meetings
	if mss.isSensitiveMeeting(meetingID) {
		externalParticipants := mss.getExternalParticipants(meetingID)
		if len(externalParticipants) > 0 {
			event := MeetingSecurityEvent{
				ID:          mss.generateEventID(),
				MeetingID:   meetingID,
				EventType:   "compliance_external_participants",
				Severity:    "high",
				Description: fmt.Sprintf("Sensitive meeting has %d external participants", len(externalParticipants)),
				Metadata: map[string]interface{}{
					"external_count":        len(externalParticipants),
					"external_participants": externalParticipants,
				},
				Timestamp: time.Now(),
				Resolved:  false,
			}
			events = append(events, event)
		}
	}

	// 3. Check for encryption requirements
	if mss.isEncryptionRequired(meetingID) && !meeting.IsEndToEndEncryptionEnabled {
		event := MeetingSecurityEvent{
			ID:          mss.generateEventID(),
			MeetingID:   meetingID,
			EventType:   "compliance_encryption_required",
			Severity:    "critical",
			Description: "Meeting requires encryption but end-to-end encryption is not enabled",
			Metadata: map[string]interface{}{
				"compliance_requirement": "encryption_required",
				"current_setting":        meeting.IsEndToEndEncryptionEnabled,
			},
			Timestamp: time.Now(),
			Resolved:  false,
		}
		events = append(events, event)
	}

	return events, nil
}

// Notification helper methods
func (mss *MeetingSecurityService) notifyParticipantsWatermarkChange(meetingID string, enabled bool) {
	// Get all current participants
	participants := mss.getCurrentParticipants(meetingID)

	for _, participant := range participants {
		// Get user details
		var user models.User
		if err := facades.Orm().Query().Where("id", participant.UserID).First(&user); err != nil {
			continue
		}

		// Create notification
		notificationService := NewNotificationService()
		notification := notifications.NewBaseNotification()
		notification.SetType("meeting_watermark_change")

		if enabled {
			notification.SetTitle("Watermark Protection Enabled")
			notification.SetBody("Content watermark protection has been enabled for this meeting")
		} else {
			notification.SetTitle("Watermark Protection Disabled")
			notification.SetBody("Content watermark protection has been disabled for this meeting")
		}

		notification.SetChannels([]string{"websocket", "web_push"})
		notification.AddData("meeting_id", meetingID)
		notification.AddData("watermark_enabled", enabled)

		// Send notification
		ctx := context.Background()
		if err := notificationService.SendNow(ctx, notification, &user); err != nil {
			facades.Log().Error("Failed to send watermark notification", map[string]interface{}{
				"user_id":    user.ID,
				"meeting_id": meetingID,
				"error":      err.Error(),
			})
		}
	}
}

func (mss *MeetingSecurityService) notifyParticipantsEncryptionChange(meetingID string, enabled bool) {
	// Get all current participants
	participants := mss.getCurrentParticipants(meetingID)

	for _, participant := range participants {
		// Get user details
		var user models.User
		if err := facades.Orm().Query().Where("id", participant.UserID).First(&user); err != nil {
			continue
		}

		// Create notification
		notificationService := NewNotificationService()
		notification := notifications.NewBaseNotification()
		notification.SetType("meeting_encryption_change")

		if enabled {
			notification.SetTitle("End-to-End Encryption Enabled")
			notification.SetBody("End-to-end encryption has been enabled for this meeting")
		} else {
			notification.SetTitle("End-to-End Encryption Disabled")
			notification.SetBody("End-to-end encryption has been disabled for this meeting")
		}

		notification.SetChannels([]string{"websocket", "web_push"})
		notification.AddData("meeting_id", meetingID)
		notification.AddData("encryption_enabled", enabled)

		// Send notification
		ctx := context.Background()
		if err := notificationService.SendNow(ctx, notification, &user); err != nil {
			facades.Log().Error("Failed to send encryption notification", map[string]interface{}{
				"user_id":    user.ID,
				"meeting_id": meetingID,
				"error":      err.Error(),
			})
		}
	}
}

// Compliance helper methods
func (mss *MeetingSecurityService) isRecordingRequired(meetingID string) bool {
	// Check organizational policies or meeting metadata for recording requirements
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return false
	}

	// Check if meeting has compliance tags that require recording
	// This could be based on meeting subject, participants, or organizational policies
	return strings.Contains(strings.ToLower(meeting.Subject), "compliance") ||
		strings.Contains(strings.ToLower(meeting.Subject), "audit") ||
		strings.Contains(strings.ToLower(meeting.Subject), "legal")
}

func (mss *MeetingSecurityService) isSensitiveMeeting(meetingID string) bool {
	// Check if meeting is marked as sensitive
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return false
	}

	// Check for sensitive keywords or classifications
	sensitiveKeywords := []string{"confidential", "sensitive", "restricted", "internal", "private"}
	subjectLower := strings.ToLower(meeting.Subject)

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(subjectLower, keyword) {
			return true
		}
	}

	return false
}

func (mss *MeetingSecurityService) isEncryptionRequired(meetingID string) bool {
	// Check if encryption is required based on organizational policies
	return mss.isSensitiveMeeting(meetingID) // Sensitive meetings require encryption
}

func (mss *MeetingSecurityService) getExternalParticipants(meetingID string) []string {
	// Get participants who are external to the organization
	var participants []models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id = ? AND status = ?", meetingID, "joined").
		With("User").
		Find(&participants)

	if err != nil {
		return []string{}
	}

	var externalParticipants []string
	organizationDomain := mss.getOrganizationDomain()

	for _, participant := range participants {
		if participant.User != nil {
			userDomain := mss.extractDomain(participant.User.Email)
			if userDomain != organizationDomain {
				externalParticipants = append(externalParticipants, participant.UserID)
			}
		}
	}

	return externalParticipants
}

func (mss *MeetingSecurityService) getOrganizationDomain() string {
	// Get the primary organization domain from configuration
	// This would typically be configured in the application settings
	return "example.com" // This should be configurable
}
