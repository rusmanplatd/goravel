package v1

import (
	"encoding/json"
	"fmt"
	"strings"

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
		var options []interface{}

		// Try to parse as JSON array first
		if err := json.Unmarshal([]byte(optionsStr), &options); err != nil {
			// If JSON parsing fails, try to parse as comma-separated string
			optionTexts := strings.Split(optionsStr, ",")
			options = make([]interface{}, len(optionTexts))

			for i, text := range optionTexts {
				options[i] = map[string]interface{}{
					"text":  strings.TrimSpace(text),
					"value": strings.TrimSpace(text),
					"id":    fmt.Sprintf("option_%d", i+1),
				}
			}
		} else {
			// Validate and normalize the parsed JSON options
			normalizedOptions := make([]interface{}, 0, len(options))

			for i, option := range options {
				if optionMap, ok := option.(map[string]interface{}); ok {
					// Ensure required fields exist
					if text, exists := optionMap["text"]; exists {
						normalizedOption := map[string]interface{}{
							"text":  text,
							"value": optionMap["value"],
							"id":    optionMap["id"],
						}

						// Set default values if not provided
						if normalizedOption["value"] == nil {
							normalizedOption["value"] = text
						}
						if normalizedOption["id"] == nil {
							normalizedOption["id"] = fmt.Sprintf("option_%d", i+1)
						}

						normalizedOptions = append(normalizedOptions, normalizedOption)
					}
				} else if optionStr, ok := option.(string); ok {
					// Handle string options
					normalizedOptions = append(normalizedOptions, map[string]interface{}{
						"text":  optionStr,
						"value": optionStr,
						"id":    fmt.Sprintf("option_%d", i+1),
					})
				}
			}

			options = normalizedOptions
		}

		// Validate minimum options
		if len(options) < 2 {
			return responses.CreateErrorResponse(ctx, "Invalid poll options", "Poll must have at least 2 options", 400)
		}

		// Validate maximum options (reasonable limit)
		if len(options) > 20 {
			return responses.CreateErrorResponse(ctx, "Too many poll options", "Poll cannot have more than 20 options", 400)
		}

		pollData["options"] = options
	} else {
		// No options provided, return error
		return responses.CreateErrorResponse(ctx, "Missing poll options", "Poll options are required", 400)
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
