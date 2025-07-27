package v1

import (
	"strconv"
	"time"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// MeetingController handles meeting-related HTTP requests
type MeetingController struct {
	meetingService     *services.MeetingService
	recordingService   *services.MeetingRecordingService
	securityService    *services.MeetingSecurityService
	performanceService *services.MeetingPerformanceService
	monitoringService  *services.MeetingMonitoringService
	clusterService     *services.MeetingClusterService
	liveKitService     *services.LiveKitService
}

// NewMeetingController creates a new meeting controller
func NewMeetingController() *MeetingController {
	return &MeetingController{
		meetingService:     services.NewMeetingService(),
		recordingService:   services.NewMeetingRecordingService(),
		securityService:    services.NewMeetingSecurityService(),
		performanceService: services.NewMeetingPerformanceService(),
		monitoringService:  services.NewMeetingMonitoringService(),
		clusterService:     services.NewMeetingClusterService("api-node"),
		liveKitService:     services.NewLiveKitService(),
	}
}

// StartMeeting starts a meeting session
func (mc *MeetingController) StartMeeting(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	err := mc.meetingService.StartMeeting(meetingID, user.ID)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start meeting",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Meeting started successfully",
		Data:      map[string]interface{}{"meeting_id": meetingID},
		Timestamp: time.Now(),
	})
}

// JoinMeeting allows a user to join a meeting
func (mc *MeetingController) JoinMeeting(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	var request requests.JoinMeetingRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Create device info map
	deviceInfo := map[string]string{
		"device_type":  request.DeviceInfo["device_type"],
		"browser_info": ctx.Request().Header("User-Agent", ""),
		"ip_address":   ctx.Request().Ip(),
	}

	participant, err := mc.meetingService.JoinMeeting(meetingID, user.ID, request.ConnectionID, deviceInfo)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to join meeting",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Joined meeting successfully",
		Data:      participant,
		Timestamp: time.Now(),
	})
}

// GetMeetingStatus retrieves current meeting status and metrics
func (mc *MeetingController) GetMeetingStatus(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")

	// Get meeting details
	meeting, err := mc.performanceService.GetMeetingCached(meetingID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting not found",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Get basic metrics from monitoring service
	metrics, err := mc.monitoringService.GetMeetingMetrics(meetingID)
	if err != nil {
		metrics = &services.MeetingMetricsData{
			TotalConnections:  0,
			ActiveConnections: 0,
			LastUpdated:       time.Now(),
		}
	}

	// Get participant count
	participantCount, _ := facades.Orm().Query().Model(&models.MeetingParticipant{}).
		Where("meeting_id = ? AND status = ?", meetingID, "joined").
		Count()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Meeting status retrieved successfully",
		Data: map[string]interface{}{
			"meeting":           meeting,
			"participant_count": participantCount,
			"metrics":           metrics,
			"health_status":     "healthy",
		},
		Timestamp: time.Now(),
	})
}

// StartRecording starts recording a meeting
func (mc *MeetingController) StartRecording(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	var request requests.StartRecordingRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Create recording configuration from request (as value, not pointer)
	config := services.RecordingConfiguration{
		Quality:           request.Quality,
		Format:            request.Format,
		IncludeVideo:      request.IncludeVideo,
		IncludeAudio:      request.IncludeAudio,
		AutoTranscribe:    request.AutoTranscribe,
		GenerateSummary:   request.GenerateSummary,
		LanguageCode:      request.LanguageCode,
		RetentionDays:     request.RetentionDays,
		WatermarkEnabled:  request.WatermarkEnabled,
		EncryptionEnabled: request.EncryptionEnabled,
	}

	recording, err := mc.recordingService.StartRecording(meetingID, user.ID, config)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start recording",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Recording started successfully",
		Data:      recording,
		Timestamp: time.Now(),
	})
}

// EndMeeting ends a meeting session
func (mc *MeetingController) EndMeeting(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	err := mc.meetingService.EndMeeting(meetingID, user.ID)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to end meeting",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Meeting ended successfully",
		Data:      map[string]interface{}{"meeting_id": meetingID},
		Timestamp: time.Now(),
	})
}

// UpdateParticipantStatus updates participant real-time status
func (mc *MeetingController) UpdateParticipantStatus(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	var request requests.UpdateParticipantStatusRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Convert to map[string]interface{} as expected by the service
	updates := make(map[string]interface{})
	if request.IsMuted != nil {
		updates["is_muted"] = *request.IsMuted
	}
	if request.IsVideoEnabled != nil {
		updates["is_video_enabled"] = *request.IsVideoEnabled
	}
	if request.IsScreenSharing != nil {
		updates["is_screen_sharing"] = *request.IsScreenSharing
	}
	if request.IsHandRaised != nil {
		updates["is_hand_raised"] = *request.IsHandRaised
	}

	err := mc.meetingService.UpdateParticipantStatus(meetingID, user.ID, updates)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update participant status",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Participant status updated successfully",
		Timestamp: time.Now(),
	})
}

// SendChatMessage sends a chat message in a meeting
func (mc *MeetingController) SendChatMessage(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	var request requests.SendChatMessageRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Handle recipient ID
	var recipientID *string
	if request.RecipientID != "" {
		recipientID = &request.RecipientID
	}

	// Call service method with correct signature
	message, err := mc.meetingService.SendChatMessage(meetingID, user.ID, request.Content, request.MessageType, recipientID)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to send chat message",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat message sent successfully",
		Data:      message,
		Timestamp: time.Now(),
	})
}

// CreateBreakoutRooms creates breakout rooms for a meeting
func (mc *MeetingController) CreateBreakoutRooms(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	var request requests.CreateBreakoutRoomsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	// Convert request.Rooms to []map[string]interface{} as expected by the service
	rooms := make([]map[string]interface{}, len(request.Rooms))
	for i, room := range request.Rooms {
		rooms[i] = map[string]interface{}{
			"name":                         room.Name,
			"description":                  room.Description,
			"capacity":                     room.Capacity,
			"time_limit_minutes":           room.TimeLimitMinutes,
			"auto_assign":                  room.AutoAssign,
			"allow_participants_to_choose": room.AllowParticipantsToChoose,
			"allow_participants_to_return": room.AllowParticipantsToReturn,
		}
	}

	createdRooms, err := mc.meetingService.CreateBreakoutRooms(meetingID, user.ID, rooms)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create breakout rooms",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Breakout rooms created successfully",
		Data:      createdRooms,
		Timestamp: time.Now(),
	})
}

// LeaveMeeting allows a user to leave a meeting
func (mc *MeetingController) LeaveMeeting(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	err := mc.meetingService.LeaveMeeting(meetingID, user.ID)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to leave meeting",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Left meeting successfully",
		Data:      map[string]interface{}{"meeting_id": meetingID},
		Timestamp: time.Now(),
	})
}

// GetParticipants returns current meeting participants
func (mc *MeetingController) GetParticipants(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")

	participants, err := mc.meetingService.GetActiveMeetingParticipants(meetingID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve participants",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Participants retrieved successfully",
		Data:      participants,
		Timestamp: time.Now(),
	})
}

// GetChatHistory returns chat history for a meeting
func (mc *MeetingController) GetChatHistory(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "50"))
	offset, _ := strconv.Atoi(ctx.Request().Query("offset", "0"))

	messages, err := mc.meetingService.GetMeetingChatHistory(meetingID, user.ID, limit, offset)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve chat history",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat history retrieved successfully",
		Data:      messages,
		Timestamp: time.Now(),
	})
}

// AssignToBreakoutRoom assigns a participant to a breakout room
func (mc *MeetingController) AssignToBreakoutRoom(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	participantUserID := ctx.Request().Input("participant_user_id", "")
	breakoutRoomID := ctx.Request().Input("breakout_room_id", "")

	if participantUserID == "" || breakoutRoomID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Participant ID and breakout room ID are required",
			Timestamp: time.Now(),
		})
	}

	err := mc.meetingService.AssignToBreakoutRoom(meetingID, participantUserID, breakoutRoomID, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to assign participant to breakout room",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Participant assigned to breakout room successfully",
		Data: map[string]interface{}{
			"participant_user_id": participantUserID,
			"breakout_room_id":    breakoutRoomID,
		},
		Timestamp: time.Now(),
	})
}

// GenerateLiveKitToken generates a LiveKit access token for a participant
func (mc *MeetingController) GenerateLiveKitToken(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	// Check if user is a participant in the meeting
	var participant models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("user_id", user.ID).
		First(&participant)

	isHost := false
	if err == nil {
		isHost = participant.Role == "host" || participant.Role == "co-host"
	}

	// Generate LiveKit access token
	token, err := mc.liveKitService.GenerateAccessToken(meetingID, user.ID, user.Name, isHost)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate access token",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Access token generated successfully",
		Data: map[string]interface{}{
			"token":      token,
			"meeting_id": meetingID,
			"user_id":    user.ID,
			"is_host":    isHost,
		},
		Timestamp: time.Now(),
	})
}
