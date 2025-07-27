package v1

import (
	"time"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
)

// MeetingRecordingController handles recording operations in meetings
type MeetingRecordingController struct {
	recordingService *services.MeetingRecordingService
}

// NewMeetingRecordingController creates a new recording controller
func NewMeetingRecordingController() *MeetingRecordingController {
	return &MeetingRecordingController{
		recordingService: services.NewMeetingRecordingService(),
	}
}

// StartRecording starts recording a meeting
func (rc *MeetingRecordingController) StartRecording(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting ID is required",
			Timestamp: time.Now(),
		})
	}

	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	// Create recording configuration with defaults
	config := services.RecordingConfiguration{
		Quality:            ctx.Request().Input("quality", "medium"),
		Format:             ctx.Request().Input("format", "mp4"),
		IncludeVideo:       ctx.Request().InputBool("include_video", true),
		IncludeAudio:       ctx.Request().InputBool("include_audio", true),
		IncludeScreenShare: ctx.Request().InputBool("include_screen_share", true),
		AutoTranscribe:     ctx.Request().InputBool("auto_transcribe", false),
		GenerateSummary:    ctx.Request().InputBool("generate_summary", false),
		LanguageCode:       ctx.Request().Input("language_code", "en"),
		RetentionDays:      ctx.Request().InputInt("retention_days", 30),
		IsPublic:           ctx.Request().InputBool("is_public", false),
		WatermarkEnabled:   ctx.Request().InputBool("watermark_enabled", false),
		EncryptionEnabled:  ctx.Request().InputBool("encryption_enabled", false),
	}

	recording, err := rc.recordingService.StartRecording(meetingID, user.ID, config)
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

// StopRecording stops recording a meeting
func (rc *MeetingRecordingController) StopRecording(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting ID is required",
			Timestamp: time.Now(),
		})
	}

	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	recording, err := rc.recordingService.StopRecording(meetingID, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to stop recording",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Recording stopped successfully",
		Data:      recording,
		Timestamp: time.Now(),
	})
}

// GetRecordings retrieves all recordings for a meeting
func (rc *MeetingRecordingController) GetRecordings(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting ID is required",
			Timestamp: time.Now(),
		})
	}

	recordings, err := rc.recordingService.ListRecordings(meetingID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve recordings",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Recordings retrieved successfully",
		Data:      recordings,
		Timestamp: time.Now(),
	})
}

// GetRecording retrieves a specific recording
func (rc *MeetingRecordingController) GetRecording(ctx http.Context) http.Response {
	recordingID := ctx.Request().Route("recordingId")
	if recordingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Recording ID is required",
			Timestamp: time.Now(),
		})
	}

	recording, err := rc.recordingService.GetRecording(recordingID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Recording not found",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Recording retrieved successfully",
		Data:      recording,
		Timestamp: time.Now(),
	})
}

// DeleteRecording deletes a recording
func (rc *MeetingRecordingController) DeleteRecording(ctx http.Context) http.Response {
	recordingID := ctx.Request().Route("recordingId")
	if recordingID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Recording ID is required",
			Timestamp: time.Now(),
		})
	}

	user, exists := ctx.Value("authenticated_user").(*models.User)
	if !exists {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Authentication required",
			Timestamp: time.Now(),
		})
	}

	err := rc.recordingService.DeleteRecording(recordingID, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete recording",
			Details:   map[string]interface{}{"error": err.Error()},
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Recording deleted successfully",
		Timestamp: time.Now(),
	})
}
