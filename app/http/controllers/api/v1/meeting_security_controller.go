package v1

import (
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
	"strconv"

	"github.com/goravel/framework/contracts/http"
)

// MeetingSecurityController handles meeting security operations
type MeetingSecurityController struct {
	securityService *services.MeetingSecurityService
}

// NewMeetingSecurityController creates a new meeting security controller
func NewMeetingSecurityController() *MeetingSecurityController {
	return &MeetingSecurityController{
		securityService: services.NewMeetingSecurityService(),
	}
}

// ApplySecurityPolicy applies security policies to a meeting
// @Summary Apply security policy
// @Description Apply security policies to a meeting (host only)
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param policy body services.MeetingSecurityPolicy true "Security policy"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/policy [post]
func (msc *MeetingSecurityController) ApplySecurityPolicy(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	var policy models.MeetingSecurityPolicy
	if err := ctx.Request().Bind(&policy); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid security policy", err.Error(), 400)
	}

	err := msc.securityService.ApplySecurityPolicy(meetingID, &policy)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to apply security policy", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Security policy applied successfully", nil)
}

// ValidateAccess validates if a user can access a meeting
// @Summary Validate meeting access
// @Description Validate if a user can access a meeting based on security policies
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID"
// @Param device_info body object false "Device information"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/validate-access [post]
func (msc *MeetingSecurityController) ValidateAccess(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	var deviceInfo map[string]interface{}
	deviceInfoStr := ctx.Request().Input("device_info", "{}")
	if deviceInfoStr != "{}" {
		// Parse device info if provided
		deviceInfo = make(map[string]interface{})
	}

	result, err := msc.securityService.ValidateAccess(meetingID, userID, deviceInfo)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to validate access", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Access validation completed", result)
}

// GetWaitingRoomParticipants returns participants in the waiting room
// @Summary Get waiting room participants
// @Description Get list of participants waiting for approval (host only)
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/waiting-room [get]
func (msc *MeetingSecurityController) GetWaitingRoomParticipants(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	participants, err := msc.securityService.GetWaitingRoomParticipants(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get waiting room participants", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Waiting room participants retrieved successfully", participants)
}

// ApproveWaitingRoomParticipant approves a participant from waiting room
// @Summary Approve waiting room participant
// @Description Approve a participant from the waiting room (host only)
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID to approve"
// @Param host_user_id body string true "Host User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/waiting-room/approve [post]
func (msc *MeetingSecurityController) ApproveWaitingRoomParticipant(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	participantUserID := ctx.Request().Input("user_id", "")
	if participantUserID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	err := msc.securityService.ApproveWaitingRoomParticipant(meetingID, hostUserID, participantUserID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to approve participant", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Participant approved successfully", nil)
}

// DenyWaitingRoomParticipant denies a participant from waiting room
// @Summary Deny waiting room participant
// @Description Deny a participant from the waiting room (host only)
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID to deny"
// @Param host_user_id body string true "Host User ID"
// @Param reason body string false "Reason for denial"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/waiting-room/deny [post]
func (msc *MeetingSecurityController) DenyWaitingRoomParticipant(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	participantUserID := ctx.Request().Input("user_id", "")
	if participantUserID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	reason := ctx.Request().Input("reason", "")

	err := msc.securityService.DenyWaitingRoomParticipant(meetingID, hostUserID, participantUserID, reason)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to deny participant", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Participant denied successfully", nil)
}

// RemoveParticipant removes a participant from the meeting
// @Summary Remove participant
// @Description Remove a participant from the meeting (kick/ban)
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID to remove"
// @Param host_user_id body string true "Host User ID"
// @Param reason body string false "Reason for removal"
// @Param ban body bool false "Whether to ban the user"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/remove-participant [post]
func (msc *MeetingSecurityController) RemoveParticipant(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	participantUserID := ctx.Request().Input("user_id", "")
	if participantUserID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	reason := ctx.Request().Input("reason", "")
	banStr := ctx.Request().Input("ban", "false")
	ban, _ := strconv.ParseBool(banStr)

	err := msc.securityService.RemoveParticipant(meetingID, hostUserID, participantUserID, reason, ban)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to remove participant", err.Error(), 500)
	}

	action := "removed"
	if ban {
		action = "banned"
	}

	return responses.SuccessResponse(ctx, "Participant "+action+" successfully", nil)
}

// MuteParticipant mutes/unmutes a participant
// @Summary Mute participant
// @Description Mute or unmute a participant
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID to mute/unmute"
// @Param host_user_id body string true "Host User ID"
// @Param mute body bool true "Whether to mute (true) or unmute (false)"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/mute-participant [post]
func (msc *MeetingSecurityController) MuteParticipant(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	participantUserID := ctx.Request().Input("user_id", "")
	if participantUserID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	muteStr := ctx.Request().Input("mute", "true")
	mute, _ := strconv.ParseBool(muteStr)

	err := msc.securityService.MuteParticipant(meetingID, hostUserID, participantUserID, mute)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to mute/unmute participant", err.Error(), 500)
	}

	action := "unmuted"
	if mute {
		action = "muted"
	}

	return responses.SuccessResponse(ctx, "Participant "+action+" successfully", nil)
}

// DisableParticipantCamera disables/enables a participant's camera
// @Summary Disable participant camera
// @Description Disable or enable a participant's camera
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param user_id body string true "User ID"
// @Param host_user_id body string true "Host User ID"
// @Param disable body bool true "Whether to disable (true) or enable (false)"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/disable-camera [post]
func (msc *MeetingSecurityController) DisableParticipantCamera(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	participantUserID := ctx.Request().Input("user_id", "")
	if participantUserID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	disableStr := ctx.Request().Input("disable", "true")
	disable, _ := strconv.ParseBool(disableStr)

	err := msc.securityService.DisableParticipantCamera(meetingID, hostUserID, participantUserID, disable)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to control participant camera", err.Error(), 500)
	}

	action := "enabled"
	if disable {
		action = "disabled"
	}

	return responses.SuccessResponse(ctx, "Participant camera "+action+" successfully", nil)
}

// LockMeeting locks/unlocks a meeting
// @Summary Lock meeting
// @Description Lock or unlock a meeting to prevent new participants from joining
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param host_user_id body string true "Host User ID"
// @Param lock body bool true "Whether to lock (true) or unlock (false)"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/lock [post]
func (msc *MeetingSecurityController) LockMeeting(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host User ID is required", "Missing host_user_id parameter", 400)
	}

	lockStr := ctx.Request().Input("lock", "true")
	lock, _ := strconv.ParseBool(lockStr)

	err := msc.securityService.LockMeeting(meetingID, hostUserID, lock)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to lock/unlock meeting", err.Error(), 500)
	}

	action := "unlocked"
	if lock {
		action = "locked"
	}

	return responses.SuccessResponse(ctx, "Meeting "+action+" successfully", nil)
}

// GetSecurityEvents returns security events for a meeting
// @Summary Get security events
// @Description Get security events and alerts for a meeting
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param limit query int false "Number of events to return" default(50)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/events [get]
func (msc *MeetingSecurityController) GetSecurityEvents(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	limit := ctx.Request().InputInt("limit", 50)

	events, err := msc.securityService.GetSecurityEvents(meetingID, limit)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get security events", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Security events retrieved successfully", events)
}

// MonitorMeetingSecurity monitors ongoing security threats
// @Summary Monitor meeting security
// @Description Monitor ongoing security threats and suspicious activities
// @Tags meeting-security
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/security/monitor [get]
func (msc *MeetingSecurityController) MonitorMeetingSecurity(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	threats, err := msc.securityService.MonitorMeetingSecurity(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to monitor meeting security", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Security monitoring completed", map[string]interface{}{
		"meeting_id": meetingID,
		"threats":    threats,
		"status":     "monitored",
	})
}
