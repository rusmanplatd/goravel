package v1

import (
	"encoding/json"

	"goravel/app/http/responses"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
)

// MeetingWhiteboardController handles whiteboard operations in meetings
type MeetingWhiteboardController struct {
	whiteboardService *services.MeetingWhiteboardService
}

// NewMeetingWhiteboardController creates a new whiteboard controller
func NewMeetingWhiteboardController() *MeetingWhiteboardController {
	return &MeetingWhiteboardController{
		whiteboardService: services.NewMeetingWhiteboardService(),
	}
}

// CreateWhiteboard creates a new whiteboard in a meeting
// @Summary Create a new whiteboard
// @Description Create a new whiteboard in a meeting (host/co-host only)
// @Tags Meeting Whiteboard
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param whiteboard body object true "Whiteboard data"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/whiteboard [post]
func (wc *MeetingWhiteboardController) CreateWhiteboard(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	// Parse whiteboard data
	whiteboardData := map[string]interface{}{
		"title":            ctx.Request().Input("title", "Meeting Whiteboard"),
		"description":      ctx.Request().Input("description", ""),
		"is_shared":        ctx.Request().InputBool("is_shared"),
		"width":            ctx.Request().InputInt("width", 1920),
		"height":           ctx.Request().InputInt("height", 1080),
		"background_color": ctx.Request().Input("background_color", "#ffffff"),
	}

	whiteboard, err := wc.whiteboardService.CreateWhiteboard(meetingID, userID, whiteboardData)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create whiteboard", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Whiteboard created successfully", whiteboard)
}

// UpdateWhiteboard updates whiteboard canvas data
// @Summary Update whiteboard
// @Description Update whiteboard with drawing actions
// @Tags Meeting Whiteboard
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param whiteboardId path string true "Whiteboard ID"
// @Param action body object true "Drawing action"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/whiteboard/{whiteboardId}/update [post]
func (wc *MeetingWhiteboardController) UpdateWhiteboard(ctx http.Context) http.Response {
	whiteboardID := ctx.Request().Route("whiteboardId")
	if whiteboardID == "" {
		return responses.CreateErrorResponse(ctx, "Whiteboard ID is required", "Missing whiteboard ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	// Parse drawing action
	actionType := ctx.Request().Input("action_type", "draw")
	tool := ctx.Request().Input("tool", "pen")
	color := ctx.Request().Input("color", "#000000")
	size := ctx.Request().InputInt("size", 2)

	// Parse points from JSON string
	var points []map[string]float64
	if pointsStr := ctx.Request().Input("points", ""); pointsStr != "" {
		json.Unmarshal([]byte(pointsStr), &points)
	}

	// Parse properties from JSON string
	var properties map[string]interface{}
	if propertiesStr := ctx.Request().Input("properties", ""); propertiesStr != "" {
		json.Unmarshal([]byte(propertiesStr), &properties)
	}

	action := services.DrawingAction{
		ActionType: actionType,
		Tool:       tool,
		Color:      color,
		Size:       size,
		Points:     points,
		Properties: properties,
	}

	err := wc.whiteboardService.UpdateWhiteboard(whiteboardID, userID, action)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to update whiteboard", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Whiteboard updated successfully", nil)
}

// GetWhiteboard gets whiteboard data
// @Summary Get whiteboard
// @Description Get whiteboard data and canvas content
// @Tags Meeting Whiteboard
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param whiteboardId path string true "Whiteboard ID"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/whiteboard/{whiteboardId} [get]
func (wc *MeetingWhiteboardController) GetWhiteboard(ctx http.Context) http.Response {
	whiteboardID := ctx.Request().Route("whiteboardId")
	if whiteboardID == "" {
		return responses.CreateErrorResponse(ctx, "Whiteboard ID is required", "Missing whiteboard ID parameter", 400)
	}

	whiteboard, err := wc.whiteboardService.GetWhiteboard(whiteboardID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get whiteboard", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Whiteboard retrieved successfully", whiteboard)
}

// ClearWhiteboard clears the whiteboard canvas
// @Summary Clear whiteboard
// @Description Clear all content from the whiteboard
// @Tags Meeting Whiteboard
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param whiteboardId path string true "Whiteboard ID"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/whiteboard/{whiteboardId}/clear [post]
func (wc *MeetingWhiteboardController) ClearWhiteboard(ctx http.Context) http.Response {
	whiteboardID := ctx.Request().Route("whiteboardId")
	if whiteboardID == "" {
		return responses.CreateErrorResponse(ctx, "Whiteboard ID is required", "Missing whiteboard ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	err := wc.whiteboardService.ClearWhiteboard(whiteboardID, userID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to clear whiteboard", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Whiteboard cleared successfully", nil)
}

// AddCollaborator adds a collaborator to the whiteboard
// @Summary Add collaborator
// @Description Add a collaborator to the whiteboard
// @Tags Meeting Whiteboard
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param whiteboardId path string true "Whiteboard ID"
// @Param collaborator body object true "Collaborator data"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/whiteboard/{whiteboardId}/collaborators [post]
func (wc *MeetingWhiteboardController) AddCollaborator(ctx http.Context) http.Response {
	whiteboardID := ctx.Request().Route("whiteboardId")
	if whiteboardID == "" {
		return responses.CreateErrorResponse(ctx, "Whiteboard ID is required", "Missing whiteboard ID parameter", 400)
	}

	hostUserID := ctx.Request().Input("host_user_id", "")
	if hostUserID == "" {
		return responses.CreateErrorResponse(ctx, "Host user ID is required", "Missing host_user_id parameter", 400)
	}

	collaboratorUserID := ctx.Request().Input("collaborator_user_id", "")
	if collaboratorUserID == "" {
		return responses.CreateErrorResponse(ctx, "Collaborator user ID is required", "Missing collaborator_user_id parameter", 400)
	}

	err := wc.whiteboardService.AddCollaborator(whiteboardID, hostUserID, collaboratorUserID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to add collaborator", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Collaborator added successfully", nil)
}
