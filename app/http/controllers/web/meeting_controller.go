package web

import (
	"fmt"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// MeetingController handles web requests for meetings
type MeetingController struct {
	liveKitService *services.LiveKitService
}

// Room displays the meeting room interface
func (mc *MeetingController) Room(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Redirect(302, "/dashboard")
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Redirect(302, "/auth/login")
	}

	// Get meeting details
	var meeting models.Meeting
	err := facades.Orm().Query().
		With("Event").
		Where("id", meetingID).
		First(&meeting)
	if err != nil {
		return ctx.Response().Redirect(302, "/dashboard")
	}

	// Get user details
	var user models.User
	err = facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return ctx.Response().Redirect(302, "/auth/login")
	}

	// Check if user is a participant
	var participant models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("user_id", userID).
		First(&participant)

	isHost := false
	canJoin := false

	if err == nil {
		// User is a participant
		isHost = participant.Role == "host" || participant.Role == "co-host"
		canJoin = true
	} else {
		// User is not a participant, check access control
		canJoin, err = mc.checkMeetingAccess(userID, meetingID)
		if err != nil {
			facades.Log().Error("Failed to check meeting access", map[string]interface{}{
				"error":      err.Error(),
				"meeting_id": meetingID,
				"user_id":    userID,
			})
			canJoin = false
		}
	}

	if !canJoin {
		return ctx.Response().Status(http.StatusForbidden).Json(http.Json{
			"success": false,
			"message": "Access denied: You are not authorized to join this meeting",
		})
	}

	// Generate LiveKit access token
	liveKitService := services.NewLiveKitService()
	token, err := liveKitService.GenerateAccessToken(meetingID, userID, user.Name, isHost)
	if err != nil {
		facades.Log().Error("Failed to generate LiveKit token", map[string]interface{}{
			"error":      err.Error(),
			"meeting_id": meetingID,
			"user_id":    userID,
		})
		// Fallback to temporary token
		token = "temp_token_" + userID + "_" + meetingID
	}

	// Get LiveKit server URL
	livekitURL := facades.Config().GetString("livekit.server.url", "ws://localhost:7880")

	return ctx.Response().View().Make("meetings/room.tmpl", map[string]interface{}{
		"meeting":    meeting,
		"user":       user,
		"isHost":     isHost,
		"token":      token,
		"livekitUrl": livekitURL,
		"title":      "Meeting Room - " + meeting.Event.Title,
	})
}

// Join handles joining a meeting via web interface
func (mc *MeetingController) Join(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "Meeting not found",
		})
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "Authentication required",
		})
	}

	// Check if meeting exists and is active
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "Meeting not found",
		})
	}

	// Redirect to meeting room
	return ctx.Response().Redirect(302, "/meetings/"+meetingID+"/room?user_id="+userID)
}

// PreJoin displays the pre-join screen
func (mc *MeetingController) PreJoin(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Redirect(302, "/dashboard")
	}

	// Get meeting details
	var meeting models.Meeting
	err := facades.Orm().Query().
		With("Event").
		Where("id", meetingID).
		First(&meeting)
	if err != nil {
		return ctx.Response().Redirect(302, "/dashboard")
	}

	return ctx.Response().View().Make("meetings/pre-join.tmpl", map[string]interface{}{
		"meeting": meeting,
		"title":   "Join Meeting - " + meeting.Event.Title,
	})
}

// checkMeetingAccess checks if a user has access to join a meeting
func (mc *MeetingController) checkMeetingAccess(userID, meetingID string) (bool, error) {
	// Get meeting details
	var meeting models.Meeting
	err := facades.Orm().Query().
		Where("id = ?", meetingID).
		First(&meeting)
	if err != nil {
		return false, fmt.Errorf("meeting not found: %w", err)
	}

	// Check if user is the event creator (host)
	if meeting.Event != nil && meeting.Event.CreatedBy != nil && *meeting.Event.CreatedBy == userID {
		return true, nil
	}

	// Check if user is invited to the calendar event
	var eventParticipant models.EventParticipant
	err = facades.Orm().Query().
		Where("event_id = ? AND user_id = ?", meeting.EventID, userID).
		First(&eventParticipant)
	if err == nil {
		// User is invited to the event
		return true, nil
	}

	// Check if user is in the same organization as the event creator
	if meeting.Event != nil && meeting.Event.CreatedBy != nil {
		var creatorOrg, userOrg models.UserOrganization

		// Get creator's organization
		err1 := facades.Orm().Query().
			Where("user_id = ?", *meeting.Event.CreatedBy).
			First(&creatorOrg)

		// Get user's organization
		err2 := facades.Orm().Query().
			Where("user_id = ?", userID).
			First(&userOrg)

		if err1 == nil && err2 == nil && creatorOrg.OrganizationID == userOrg.OrganizationID {
			// Same organization - allow access for internal users
			return true, nil
		}
	}

	// Check if user has a valid meeting link/token
	meetingToken := facades.Cache().Get(fmt.Sprintf("meeting_access_%s_%s", meetingID, userID))
	if meetingToken != nil {
		return true, nil
	}

	// No access granted
	facades.Log().Info("Meeting access denied", map[string]interface{}{
		"user_id":    userID,
		"meeting_id": meetingID,
		"reason":     "no valid access method found",
	})

	return false, nil
}
