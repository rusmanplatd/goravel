package v1

import (
	"goravel/app/http/responses"
	"goravel/app/services"
	"strconv"

	"github.com/goravel/framework/contracts/http"
)

// MeetingPollController handles poll operations in meetings
type MeetingPollController struct {
	pollService *services.MeetingPollService
}

// NewMeetingPollController creates a new poll controller
func NewMeetingPollController() *MeetingPollController {
	return &MeetingPollController{
		pollService: services.NewMeetingPollService(),
	}
}

// CreatePoll creates a new poll in a meeting
// @Summary Create a new poll
// @Description Create a new poll in a meeting (host/co-host only)
// @Tags Meeting Polls
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param poll body object true "Poll data"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/polls [post]
func (pc *MeetingPollController) CreatePoll(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	// Parse poll data
	pollData := map[string]interface{}{
		"title":                ctx.Request().Input("title", ""),
		"description":          ctx.Request().Input("description", ""),
		"poll_type":            ctx.Request().Input("poll_type", "single_choice"),
		"is_anonymous":         ctx.Request().InputBool("is_anonymous"),
		"allow_multiple_votes": ctx.Request().InputBool("allow_multiple_votes"),
		"starts_at":            ctx.Request().Input("starts_at", ""),
		"ends_at":              ctx.Request().Input("ends_at", ""),
	}

	// Parse options if provided
	if optionsStr := ctx.Request().Input("options", ""); optionsStr != "" {
		// In a real implementation, you'd parse JSON options
		// For now, we'll create a simple structure
		pollData["options"] = []interface{}{
			map[string]interface{}{"text": "Option 1"},
			map[string]interface{}{"text": "Option 2"},
		}
	}

	poll, err := pc.pollService.CreatePoll(meetingID, userID, pollData)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create poll", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Poll created successfully", poll)
}

// SubmitVote submits a vote for a poll
// @Summary Submit a vote
// @Description Submit a vote for a poll
// @Tags Meeting Polls
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param pollId path string true "Poll ID"
// @Param vote body object true "Vote data"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/polls/{pollId}/vote [post]
func (pc *MeetingPollController) SubmitVote(ctx http.Context) http.Response {
	pollID := ctx.Request().Route("pollId")
	if pollID == "" {
		return responses.CreateErrorResponse(ctx, "Poll ID is required", "Missing poll ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	// Parse vote data
	ratingStr := ctx.Request().Input("rating", "0.0")
	rating := 0.0
	if ratingStr != "" {
		if parsedRating, err := strconv.ParseFloat(ratingStr, 64); err == nil {
			rating = parsedRating
		}
	}

	voteData := map[string]interface{}{
		"option_id": ctx.Request().Input("option_id", ""),
		"text":      ctx.Request().Input("text", ""),
		"rating":    rating,
	}

	vote, err := pc.pollService.SubmitVote(pollID, userID, voteData)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to submit vote", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Vote submitted successfully", vote)
}

// GetPollResults gets poll results
// @Summary Get poll results
// @Description Get results for a poll
// @Tags Meeting Polls
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param pollId path string true "Poll ID"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/polls/{pollId}/results [get]
func (pc *MeetingPollController) GetPollResults(ctx http.Context) http.Response {
	pollID := ctx.Request().Route("pollId")
	if pollID == "" {
		return responses.CreateErrorResponse(ctx, "Poll ID is required", "Missing poll ID parameter", 400)
	}

	results, err := pc.pollService.GetPollResults(pollID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get poll results", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Poll results retrieved successfully", results)
}

// ClosePoll closes an active poll
// @Summary Close a poll
// @Description Close an active poll (host/co-host only)
// @Tags Meeting Polls
// @Accept json
// @Produce json
// @Param id path string true "Meeting ID"
// @Param pollId path string true "Poll ID"
// @Success 200 {object} responses.SuccessResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 401 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{id}/polls/{pollId}/close [post]
func (pc *MeetingPollController) ClosePoll(ctx http.Context) http.Response {
	pollID := ctx.Request().Route("pollId")
	if pollID == "" {
		return responses.CreateErrorResponse(ctx, "Poll ID is required", "Missing poll ID parameter", 400)
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return responses.CreateErrorResponse(ctx, "User ID is required", "Missing user_id parameter", 400)
	}

	err := pc.pollService.ClosePoll(pollID, userID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to close poll", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Poll closed successfully", nil)
}

// Helper function to parse float from string
func parseFloat(s string) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return 0.0
}
