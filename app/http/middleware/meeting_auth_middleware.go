package middleware

import (
	"strings"
	"time"

	"goravel/app/http/responses"
	"goravel/app/models"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// MeetingAuthMiddleware handles authentication and authorization for meeting endpoints
type MeetingAuthMiddleware struct{}

// Handle validates user authentication and meeting access permissions
func (m *MeetingAuthMiddleware) Handle(ctx http.Context) http.Response {
	// Get user from context (assumes auth middleware has already run)
	user, exists := ctx.Value("user").(*models.User)
	if !exists || user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	// Get meeting ID from route
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting ID is required",
			Timestamp: time.Now(),
		})
	}

	// Validate meeting exists
	var meeting models.Meeting
	err := facades.Orm().Query().
		With("Event").
		Where("id", meetingID).
		First(&meeting)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting not found",
			Timestamp: time.Now(),
		})
	}

	// Check if user has access to the meeting
	hasAccess, role := m.checkMeetingAccess(user.ID, meetingID, &meeting)
	if !hasAccess {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Access denied to this meeting",
			Timestamp: time.Now(),
		})
	}

	// Add meeting and user role to context
	ctx.WithValue("meeting", &meeting)
	ctx.WithValue("user_role", role)
	ctx.WithValue("authenticated_user", user)

	ctx.Request().Next()
	return nil
}

// checkMeetingAccess verifies if a user has access to a meeting and returns their role
func (m *MeetingAuthMiddleware) checkMeetingAccess(userID, meetingID string, meeting *models.Meeting) (bool, string) {
	// Check if user is the event creator (host)
	if meeting.Event != nil && meeting.Event.CreatedBy != nil && *meeting.Event.CreatedBy == userID {
		return true, "host"
	}

	// Check if user is a meeting participant with explicit role
	var participant models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("user_id", userID).
		First(&participant)
	if err == nil {
		// Verify participant is still active and not banned
		if participant.Status == "active" {
			return true, participant.Role
		} else {
			facades.Log().Warning("Meeting access denied for inactive participant", map[string]interface{}{
				"user_id":    userID,
				"meeting_id": meetingID,
				"status":     participant.Status,
			})
			return false, ""
		}
	}

	// Check if user is an attendee of the associated calendar event
	if meeting.Event != nil {
		hasEventAccess, eventRole := m.checkEventAttendeeAccess(userID, meeting.Event.ID)
		if hasEventAccess {
			return true, eventRole
		}
	}

	// Check if user has access through calendar sharing
	if meeting.Event != nil {
		hasSharedAccess := m.checkCalendarSharingAccess(userID, meeting.Event.ID)
		if hasSharedAccess {
			return true, "attendee"
		}
	}

	// Check if meeting allows public access
	if m.checkPublicMeetingAccess(meeting, userID) {
		return true, "attendee"
	}

	// Check organization membership for internal meetings
	if meeting.Event != nil && meeting.Event.CreatedBy != nil {
		hasOrgAccess := m.checkOrganizationMembershipAccess(userID, *meeting.Event.CreatedBy)
		if hasOrgAccess {
			return true, "attendee"
		}
	}

	// Log access denial for security audit
	facades.Log().Warning("Meeting access denied", map[string]interface{}{
		"user_id":    userID,
		"meeting_id": meetingID,
	})

	return false, ""
}

// checkEventAttendeeAccess checks if user is an attendee of the calendar event
func (m *MeetingAuthMiddleware) checkEventAttendeeAccess(userID, eventID string) (bool, string) {
	// Check if user is explicitly invited to the event using EventParticipant model
	var participant models.EventParticipant
	err := facades.Orm().Query().
		Where("event_id", eventID).
		Where("user_id", userID).
		First(&participant)

	if err == nil {
		// Check if participant has accepted or is pending (allow both)
		if participant.ResponseStatus == "accepted" || participant.ResponseStatus == "pending" {
			// Map event roles to meeting roles
			switch participant.Role {
			case "organizer":
				return true, "host"
			case "presenter":
				return true, "co-host"
			default:
				return true, "attendee"
			}
		}
	}

	// Check if user is the event creator (fallback check)
	var event models.CalendarEvent
	err = facades.Orm().Query().Where("id", eventID).First(&event)
	if err != nil {
		return false, ""
	}

	if event.CreatedBy != nil && *event.CreatedBy == userID {
		return true, "host"
	}

	return false, ""
}

// checkCalendarSharingAccess checks if user has access through calendar sharing
func (m *MeetingAuthMiddleware) checkCalendarSharingAccess(userID, eventID string) bool {
	// Get the event to find its calendar
	var event models.CalendarEvent
	err := facades.Orm().Query().Where("id", eventID).First(&event)
	if err != nil {
		return false
	}

	// Check if user has access to the calendar through sharing
	var share models.CalendarShare
	err = facades.Orm().Query().
		Where("owner_id", event.CreatedBy).
		Where("shared_with_id", userID).
		Where("is_active", true).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		First(&share)

	if err == nil {
		// Check if the sharing permission allows meeting access
		return share.Permission == "edit" || share.Permission == "manage" || share.Permission == "view"
	}

	return false
}

// checkPublicMeetingRestrictions checks restrictions for public meetings
func (m *MeetingAuthMiddleware) checkPublicMeetingRestrictions(userID, meetingID string) bool {
	// Check meeting capacity limits (simplified implementation)
	participantCount, err := facades.Orm().Query().
		Table("meeting_participants").
		Where("meeting_id", meetingID).
		Where("status", "active").
		Count()

	if err != nil {
		facades.Log().Warning("Failed to check participant count", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		return true // Allow access if we can't check
	}

	// For now, allow up to 100 participants (in production this would be configurable)
	maxParticipants := 100
	if participantCount >= int64(maxParticipants) {
		facades.Log().Info("Meeting capacity reached", map[string]interface{}{
			"user_id":          userID,
			"meeting_id":       meetingID,
			"current_count":    participantCount,
			"max_participants": maxParticipants,
		})
		return false
	}

	return true
}

// checkPublicMeetingAccess checks if meeting allows public access and validates restrictions
func (m *MeetingAuthMiddleware) checkPublicMeetingAccess(meeting *models.Meeting, userID string) bool {
	// Get meeting security policy
	var securityPolicy models.MeetingSecurityPolicy
	err := facades.Orm().Query().
		Where("meeting_id", meeting.ID).
		First(&securityPolicy)

	if err != nil {
		// No security policy found, use default restrictive approach
		return false
	}

	// Check if anonymous join is allowed (equivalent to public access)
	if !securityPolicy.AllowAnonymousJoin {
		return false
	}

	// Check if user is blocked
	if securityPolicy.IsUserBlocked(userID) {
		facades.Log().Warning("Meeting access denied for blocked user", map[string]interface{}{
			"user_id":    userID,
			"meeting_id": meeting.ID,
		})
		return false
	}

	// Check if password is required and meeting has passcode
	if securityPolicy.RequirePassword && meeting.Passcode != "" {
		// In a real implementation, you'd validate the password from request
		// For now, we'll require explicit authentication for password-protected meetings
		return false
	}

	// Check domain restrictions if user email is available
	var user models.User
	err = facades.Orm().Query().Where("id", userID).First(&user)
	if err == nil && user.Email != "" {
		// Extract domain from email
		emailParts := strings.Split(user.Email, "@")
		if len(emailParts) == 2 {
			domain := emailParts[1]
			if !securityPolicy.IsDomainAllowed(domain) {
				facades.Log().Warning("Meeting access denied for domain restriction", map[string]interface{}{
					"user_id":    userID,
					"meeting_id": meeting.ID,
					"domain":     domain,
				})
				return false
			}
		}
	}

	// Check meeting capacity and other restrictions
	return m.checkPublicMeetingRestrictions(userID, meeting.ID)
}

// checkOrganizationMembershipAccess checks if user belongs to the same organization as meeting creator
func (m *MeetingAuthMiddleware) checkOrganizationMembershipAccess(userID, creatorID string) bool {
	// Get creator's organization memberships
	var creatorOrgs []models.UserOrganization
	err := facades.Orm().Query().
		Where("user_id", creatorID).
		Where("status", "active").
		Where("is_active", true).
		Find(&creatorOrgs)

	if err != nil || len(creatorOrgs) == 0 {
		return false
	}

	// Get user's organization memberships
	var userOrgs []models.UserOrganization
	err = facades.Orm().Query().
		Where("user_id", userID).
		Where("status", "active").
		Where("is_active", true).
		Find(&userOrgs)

	if err != nil || len(userOrgs) == 0 {
		return false
	}

	// Check if user and creator share any organization
	creatorOrgMap := make(map[string]bool)
	for _, org := range creatorOrgs {
		creatorOrgMap[org.OrganizationID] = true
	}

	for _, userOrg := range userOrgs {
		if creatorOrgMap[userOrg.OrganizationID] {
			// Additional check: ensure user has appropriate role/permissions
			if userOrg.Role == "member" || userOrg.Role == "admin" || userOrg.Role == "owner" {
				return true
			}
		}
	}

	return false
}

// checkOrganizationAccess checks if user belongs to the meeting's organization
func (m *MeetingAuthMiddleware) checkOrganizationAccess(userID, organizationID string) bool {
	if organizationID == "" {
		return false
	}

	// Check if user belongs to the organization with active membership
	var userOrg models.UserOrganization
	err := facades.Orm().Query().
		Where("user_id", userID).
		Where("organization_id", organizationID).
		Where("status", "active").
		Where("is_active", true).
		First(&userOrg)

	if err != nil {
		return false
	}

	// Check if membership is not expired
	if userOrg.ExpiresAt != nil && userOrg.ExpiresAt.Before(time.Now()) {
		return false
	}

	// Ensure user has appropriate role (exclude guests from meetings by default)
	return userOrg.Role == "member" || userOrg.Role == "admin" || userOrg.Role == "owner"
}

// RequireHostRole middleware that requires host or co-host permissions
func (m *MeetingAuthMiddleware) RequireHostRole(ctx http.Context) http.Response {
	userRole, exists := ctx.Value("user_role").(string)
	if !exists || (userRole != "host" && userRole != "co-host") {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Host or co-host permissions required",
			Timestamp: time.Now(),
		})
	}

	ctx.Request().Next()
	return nil
}

// RequireParticipantRole middleware that requires at least participant access
func (m *MeetingAuthMiddleware) RequireParticipantRole(ctx http.Context) http.Response {
	userRole, exists := ctx.Value("user_role").(string)
	if !exists || userRole == "" {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting participant access required",
			Timestamp: time.Now(),
		})
	}

	ctx.Request().Next()
	return nil
}
