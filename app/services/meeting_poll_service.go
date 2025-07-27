package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// MeetingPollService handles poll operations in meetings
type MeetingPollService struct {
	meetingService *MeetingService
	hub            *WebSocketHub
}

// PollEvent represents a poll-related event
type PollEvent struct {
	Type      string      `json:"type"`
	MeetingID string      `json:"meeting_id"`
	PollID    string      `json:"poll_id"`
	UserID    string      `json:"user_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// PollSettings represents poll configuration
type PollSettings struct {
	ShowResults       bool `json:"show_results"`
	AllowComments     bool `json:"allow_comments"`
	RandomizeOptions  bool `json:"randomize_options"`
	RequireAllOptions bool `json:"require_all_options"`
}

// NewMeetingPollService creates a new poll service
func NewMeetingPollService() *MeetingPollService {
	return &MeetingPollService{
		meetingService: NewMeetingService(),
		hub:            GetWebSocketHub(),
	}
}

// CreatePoll creates a new poll in a meeting
func (s *MeetingPollService) CreatePoll(meetingID, creatorID string, pollData map[string]interface{}) (*models.MeetingPoll, error) {
	// Validate meeting exists and user has permission
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	// Check if user is host or co-host
	var participant models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("user_id", creatorID).
		Where("role", "IN", []string{"host", "co-host"}).
		First(&participant)
	if err != nil {
		return nil, fmt.Errorf("insufficient permissions to create poll")
	}

	// Parse poll settings
	settings := PollSettings{
		ShowResults:       true,
		AllowComments:     false,
		RandomizeOptions:  false,
		RequireAllOptions: false,
	}
	if settingsData, ok := pollData["settings"].(map[string]interface{}); ok {
		settingsJSON, _ := json.Marshal(settingsData)
		json.Unmarshal(settingsJSON, &settings)
	}
	settingsJSON, _ := json.Marshal(settings)

	// Create poll
	poll := &models.MeetingPoll{
		MeetingID:          meetingID,
		CreatorID:          creatorID,
		Title:              pollData["title"].(string),
		Description:        getStringValue(pollData, "description"),
		PollType:           getStringValue(pollData, "poll_type", "single_choice"),
		IsAnonymous:        getBoolValue(pollData, "is_anonymous"),
		AllowMultipleVotes: getBoolValue(pollData, "allow_multiple_votes"),
		IsActive:           true,
		Settings:           string(settingsJSON),
	}

	// Set start and end times if provided
	if startsAt, ok := pollData["starts_at"].(string); ok && startsAt != "" {
		if parsedTime, err := time.Parse(time.RFC3339, startsAt); err == nil {
			poll.StartsAt = &parsedTime
		}
	}
	if endsAt, ok := pollData["ends_at"].(string); ok && endsAt != "" {
		if parsedTime, err := time.Parse(time.RFC3339, endsAt); err == nil {
			poll.EndsAt = &parsedTime
		}
	}

	if err := facades.Orm().Query().Create(poll); err != nil {
		return nil, fmt.Errorf("failed to create poll: %v", err)
	}

	// Create poll options
	if options, ok := pollData["options"].([]interface{}); ok {
		for i, optionData := range options {
			if optionMap, ok := optionData.(map[string]interface{}); ok {
				option := &models.MeetingPollOption{
					PollID:     poll.ID,
					OptionText: optionMap["text"].(string),
					OrderIndex: i,
				}
				facades.Orm().Query().Create(option)
			}
		}
	}

	// Broadcast poll created event
	s.broadcastPollEvent(meetingID, PollEvent{
		Type:      "poll_created",
		MeetingID: meetingID,
		PollID:    poll.ID,
		UserID:    creatorID,
		Data: map[string]interface{}{
			"poll": poll,
		},
		Timestamp: time.Now(),
	})

	facades.Log().Info("Poll created", map[string]interface{}{
		"meeting_id": meetingID,
		"poll_id":    poll.ID,
		"creator_id": creatorID,
		"title":      poll.Title,
	})

	return poll, nil
}

// SubmitVote submits a vote for a poll
func (s *MeetingPollService) SubmitVote(pollID, voterID string, voteData map[string]interface{}) (*models.MeetingPollVote, error) {
	// Get poll
	var poll models.MeetingPoll
	err := facades.Orm().Query().
		With("Options").
		Where("id", pollID).
		First(&poll)
	if err != nil {
		return nil, fmt.Errorf("poll not found: %v", err)
	}

	// Check if poll is active
	if !poll.IsActive {
		return nil, fmt.Errorf("poll is not active")
	}

	// Check if poll has ended
	if poll.EndsAt != nil && time.Now().After(*poll.EndsAt) {
		return nil, fmt.Errorf("poll has ended")
	}

	// Check if user already voted (unless multiple votes allowed)
	if !poll.AllowMultipleVotes {
		var existingVote models.MeetingPollVote
		err = facades.Orm().Query().
			Where("poll_id", pollID).
			Where("voter_id", voterID).
			First(&existingVote)
		if err == nil {
			return nil, fmt.Errorf("user has already voted")
		}
	}

	// Create vote
	vote := &models.MeetingPollVote{
		PollID:  pollID,
		VoterID: voterID,
		VotedAt: time.Now(),
	}

	// Handle different vote types
	switch poll.PollType {
	case "single_choice", "multiple_choice":
		if optionID, ok := voteData["option_id"].(string); ok {
			vote.OptionID = &optionID
		}
	case "rating":
		if rating, ok := voteData["rating"].(float64); ok {
			ratingInt := int(rating)
			vote.RatingValue = &ratingInt
		}
	case "text":
		if text, ok := voteData["text"].(string); ok {
			vote.TextResponse = text
		}
	}

	if err := facades.Orm().Query().Create(vote); err != nil {
		return nil, fmt.Errorf("failed to submit vote: %v", err)
	}

	// Update vote counts
	if vote.OptionID != nil {
		facades.Orm().Query().Model(&models.MeetingPollOption{}).
			Where("id", *vote.OptionID).
			Update("vote_count", facades.Orm().Query().Raw("vote_count + 1"))
	}

	// Update total votes
	facades.Orm().Query().Model(&models.MeetingPoll{}).
		Where("id", pollID).
		Update("total_votes", facades.Orm().Query().Raw("total_votes + 1"))

	// Broadcast vote submitted event
	s.broadcastPollEvent(poll.MeetingID, PollEvent{
		Type:      "vote_submitted",
		MeetingID: poll.MeetingID,
		PollID:    pollID,
		UserID:    voterID,
		Data: map[string]interface{}{
			"vote": vote,
		},
		Timestamp: time.Now(),
	})

	facades.Log().Info("Vote submitted", map[string]interface{}{
		"poll_id":  pollID,
		"voter_id": voterID,
	})

	return vote, nil
}

// GetPollResults gets poll results
func (s *MeetingPollService) GetPollResults(pollID string) (map[string]interface{}, error) {
	var poll models.MeetingPoll
	err := facades.Orm().Query().
		With("Options").
		With("Votes").
		Where("id", pollID).
		First(&poll)
	if err != nil {
		return nil, fmt.Errorf("poll not found: %v", err)
	}

	results := map[string]interface{}{
		"poll_id":     poll.ID,
		"title":       poll.Title,
		"poll_type":   poll.PollType,
		"total_votes": poll.TotalVotes,
		"is_active":   poll.IsActive,
		"options":     []map[string]interface{}{},
		"votes":       []map[string]interface{}{},
	}

	// Add option results
	for _, option := range poll.Options {
		optionResult := map[string]interface{}{
			"option_id":   option.ID,
			"option_text": option.OptionText,
			"vote_count":  option.VoteCount,
			"percentage":  0.0,
		}
		if poll.TotalVotes > 0 {
			optionResult["percentage"] = float64(option.VoteCount) / float64(poll.TotalVotes) * 100
		}
		results["options"] = append(results["options"].([]map[string]interface{}), optionResult)
	}

	// Add individual votes (if not anonymous)
	if !poll.IsAnonymous {
		for _, vote := range poll.Votes {
			voteResult := map[string]interface{}{
				"vote_id":       vote.ID,
				"voter_id":      vote.VoterID,
				"option_id":     vote.OptionID,
				"text_response": vote.TextResponse,
				"rating_value":  vote.RatingValue,
				"voted_at":      vote.VotedAt,
			}
			results["votes"] = append(results["votes"].([]map[string]interface{}), voteResult)
		}
	}

	return results, nil
}

// ClosePoll closes an active poll
func (s *MeetingPollService) ClosePoll(pollID, userID string) error {
	var poll models.MeetingPoll
	err := facades.Orm().Query().Where("id", pollID).First(&poll)
	if err != nil {
		return fmt.Errorf("poll not found: %v", err)
	}

	// Check permissions
	var participant models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", poll.MeetingID).
		Where("user_id", userID).
		Where("role", "IN", []string{"host", "co-host"}).
		First(&participant)
	if err != nil && poll.CreatorID != userID {
		return fmt.Errorf("insufficient permissions to close poll")
	}

	// Close poll
	now := time.Now()
	poll.IsActive = false
	poll.EndsAt = &now

	if err := facades.Orm().Query().Save(&poll); err != nil {
		return fmt.Errorf("failed to close poll: %v", err)
	}

	// Broadcast poll closed event
	s.broadcastPollEvent(poll.MeetingID, PollEvent{
		Type:      "poll_closed",
		MeetingID: poll.MeetingID,
		PollID:    pollID,
		UserID:    userID,
		Data: map[string]interface{}{
			"poll": poll,
		},
		Timestamp: time.Now(),
	})

	return nil
}

// broadcastPollEvent broadcasts poll events to meeting participants
func (s *MeetingPollService) broadcastPollEvent(meetingID string, event PollEvent) {
	if s.hub != nil {
		broadcastMsg := &BroadcastMessage{
			Type:    "poll_event",
			Target:  "room:" + meetingID,
			Message: event,
		}
		s.hub.broadcast <- broadcastMsg
	}
}

// Helper functions
func getStringValue(data map[string]interface{}, key string, defaultValue ...string) string {
	if value, ok := data[key].(string); ok {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func getBoolValue(data map[string]interface{}, key string) bool {
	if value, ok := data[key].(bool); ok {
		return value
	}
	return false
}
