package middleware

import (
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

	// Check if user is a meeting participant
	var participant models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("user_id", userID).
		First(&participant)
	if err == nil {
		return true, participant.Role
	}

	// For now, allow access to all authenticated users as default attendee
	// TODO: In production, you would check event attendees or implement proper access control
	return true, "attendee"
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
