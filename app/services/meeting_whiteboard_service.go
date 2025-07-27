package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// MeetingWhiteboardService handles whiteboard operations in meetings
type MeetingWhiteboardService struct {
	meetingService *MeetingService
	hub            *WebSocketHub
}

// WhiteboardEvent represents a whiteboard-related event
type WhiteboardEvent struct {
	Type      string      `json:"type"`
	MeetingID string      `json:"meeting_id"`
	BoardID   string      `json:"board_id"`
	UserID    string      `json:"user_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// DrawingAction represents a drawing action on the whiteboard
type DrawingAction struct {
	ActionType string                 `json:"action_type"` // draw, erase, clear, undo, redo
	Tool       string                 `json:"tool"`        // pen, brush, line, rectangle, circle, text
	Color      string                 `json:"color"`
	Size       int                    `json:"size"`
	Points     []map[string]float64   `json:"points"`
	Properties map[string]interface{} `json:"properties"`
}

// NewMeetingWhiteboardService creates a new whiteboard service
func NewMeetingWhiteboardService() *MeetingWhiteboardService {
	return &MeetingWhiteboardService{
		meetingService: NewMeetingService(),
		hub:            GetWebSocketHub(),
	}
}

// CreateWhiteboard creates a new whiteboard in a meeting
func (s *MeetingWhiteboardService) CreateWhiteboard(meetingID, creatorID string, whiteboardData map[string]interface{}) (*models.MeetingWhiteboard, error) {
	// Validate meeting exists
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
		return nil, fmt.Errorf("insufficient permissions to create whiteboard")
	}

	// Create whiteboard
	whiteboard := &models.MeetingWhiteboard{
		MeetingID:       meetingID,
		Title:           getStringValue(whiteboardData, "title", "Meeting Whiteboard"),
		Description:     getStringValue(whiteboardData, "description"),
		IsActive:        true,
		IsShared:        getBoolValueWithDefault(whiteboardData, "is_shared", true),
		Width:           getIntValue(whiteboardData, "width", 1920),
		Height:          getIntValue(whiteboardData, "height", 1080),
		BackgroundColor: getStringValue(whiteboardData, "background_color", "#ffffff"),
		CanvasData:      "{}",
		CanvasVersion:   "1.0",
		Collaborators:   "[]",
	}

	if err := facades.Orm().Query().Create(whiteboard); err != nil {
		return nil, fmt.Errorf("failed to create whiteboard: %v", err)
	}

	// Broadcast whiteboard created event
	s.broadcastWhiteboardEvent(meetingID, WhiteboardEvent{
		Type:      "whiteboard_created",
		MeetingID: meetingID,
		BoardID:   whiteboard.ID,
		UserID:    creatorID,
		Data: map[string]interface{}{
			"whiteboard": whiteboard,
		},
		Timestamp: time.Now(),
	})

	facades.Log().Info("Whiteboard created", map[string]interface{}{
		"meeting_id":    meetingID,
		"whiteboard_id": whiteboard.ID,
		"creator_id":    creatorID,
		"title":         whiteboard.Title,
	})

	return whiteboard, nil
}

// UpdateWhiteboard updates whiteboard canvas data
func (s *MeetingWhiteboardService) UpdateWhiteboard(whiteboardID, userID string, action DrawingAction) error {
	// Get whiteboard
	var whiteboard models.MeetingWhiteboard
	err := facades.Orm().Query().Where("id", whiteboardID).First(&whiteboard)
	if err != nil {
		return fmt.Errorf("whiteboard not found: %v", err)
	}

	// Check if user has permission to edit
	if !whiteboard.IsShared {
		// Check if user is in collaborators list
		var collaborators []string
		if err := json.Unmarshal([]byte(whiteboard.Collaborators), &collaborators); err == nil {
			hasPermission := false
			for _, collaboratorID := range collaborators {
				if collaboratorID == userID {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				return fmt.Errorf("insufficient permissions to edit whiteboard")
			}
		}
	}

	// Parse current canvas data
	var canvasData map[string]interface{}
	if err := json.Unmarshal([]byte(whiteboard.CanvasData), &canvasData); err != nil {
		canvasData = make(map[string]interface{})
	}

	// Apply drawing action
	if canvasData["actions"] == nil {
		canvasData["actions"] = []interface{}{}
	}

	actions := canvasData["actions"].([]interface{})

	// Add timestamp and user info to action
	actionWithMeta := map[string]interface{}{
		"action":    action,
		"user_id":   userID,
		"timestamp": time.Now().Unix(),
	}

	actions = append(actions, actionWithMeta)
	canvasData["actions"] = actions
	canvasData["last_updated"] = time.Now().Unix()

	// Update canvas data
	canvasDataJSON, _ := json.Marshal(canvasData)
	whiteboard.CanvasData = string(canvasDataJSON)

	if err := facades.Orm().Query().Save(&whiteboard); err != nil {
		return fmt.Errorf("failed to update whiteboard: %v", err)
	}

	// Broadcast drawing action to other participants
	s.broadcastWhiteboardEvent(whiteboard.MeetingID, WhiteboardEvent{
		Type:      "drawing_action",
		MeetingID: whiteboard.MeetingID,
		BoardID:   whiteboardID,
		UserID:    userID,
		Data: map[string]interface{}{
			"action": actionWithMeta,
		},
		Timestamp: time.Now(),
	})

	return nil
}

// GetWhiteboard gets whiteboard data
func (s *MeetingWhiteboardService) GetWhiteboard(whiteboardID string) (*models.MeetingWhiteboard, error) {
	var whiteboard models.MeetingWhiteboard
	err := facades.Orm().Query().Where("id", whiteboardID).First(&whiteboard)
	if err != nil {
		return nil, fmt.Errorf("whiteboard not found: %v", err)
	}

	return &whiteboard, nil
}

// AddCollaborator adds a collaborator to the whiteboard
func (s *MeetingWhiteboardService) AddCollaborator(whiteboardID, hostUserID, collaboratorUserID string) error {
	// Get whiteboard
	var whiteboard models.MeetingWhiteboard
	err := facades.Orm().Query().Where("id", whiteboardID).First(&whiteboard)
	if err != nil {
		return fmt.Errorf("whiteboard not found: %v", err)
	}

	// Check if host has permission
	var participant models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", whiteboard.MeetingID).
		Where("user_id", hostUserID).
		Where("role", "IN", []string{"host", "co-host"}).
		First(&participant)
	if err != nil {
		return fmt.Errorf("insufficient permissions to add collaborator")
	}

	// Parse collaborators
	var collaborators []string
	if err := json.Unmarshal([]byte(whiteboard.Collaborators), &collaborators); err != nil {
		collaborators = []string{}
	}

	// Check if already a collaborator
	for _, id := range collaborators {
		if id == collaboratorUserID {
			return fmt.Errorf("user is already a collaborator")
		}
	}

	// Add collaborator
	collaborators = append(collaborators, collaboratorUserID)
	collaboratorsJSON, _ := json.Marshal(collaborators)
	whiteboard.Collaborators = string(collaboratorsJSON)

	if err := facades.Orm().Query().Save(&whiteboard); err != nil {
		return fmt.Errorf("failed to add collaborator: %v", err)
	}

	// Broadcast collaborator added event
	s.broadcastWhiteboardEvent(whiteboard.MeetingID, WhiteboardEvent{
		Type:      "collaborator_added",
		MeetingID: whiteboard.MeetingID,
		BoardID:   whiteboardID,
		UserID:    hostUserID,
		Data: map[string]interface{}{
			"collaborator_id": collaboratorUserID,
		},
		Timestamp: time.Now(),
	})

	return nil
}

// ClearWhiteboard clears the whiteboard canvas
func (s *MeetingWhiteboardService) ClearWhiteboard(whiteboardID, userID string) error {
	// Get whiteboard
	var whiteboard models.MeetingWhiteboard
	err := facades.Orm().Query().Where("id", whiteboardID).First(&whiteboard)
	if err != nil {
		return fmt.Errorf("whiteboard not found: %v", err)
	}

	// Check permissions (host, co-host, or collaborator)
	hasPermission := false

	// Check if host or co-host
	var participant models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", whiteboard.MeetingID).
		Where("user_id", userID).
		Where("role", "IN", []string{"host", "co-host"}).
		First(&participant)
	if err == nil {
		hasPermission = true
	}

	// Check if collaborator
	if !hasPermission {
		var collaborators []string
		if err := json.Unmarshal([]byte(whiteboard.Collaborators), &collaborators); err == nil {
			for _, collaboratorID := range collaborators {
				if collaboratorID == userID {
					hasPermission = true
					break
				}
			}
		}
	}

	if !hasPermission {
		return fmt.Errorf("insufficient permissions to clear whiteboard")
	}

	// Clear canvas data
	canvasData := map[string]interface{}{
		"actions":      []interface{}{},
		"last_updated": time.Now().Unix(),
		"cleared_by":   userID,
		"cleared_at":   time.Now().Unix(),
	}

	canvasDataJSON, _ := json.Marshal(canvasData)
	whiteboard.CanvasData = string(canvasDataJSON)

	if err := facades.Orm().Query().Save(&whiteboard); err != nil {
		return fmt.Errorf("failed to clear whiteboard: %v", err)
	}

	// Broadcast whiteboard cleared event
	s.broadcastWhiteboardEvent(whiteboard.MeetingID, WhiteboardEvent{
		Type:      "whiteboard_cleared",
		MeetingID: whiteboard.MeetingID,
		BoardID:   whiteboardID,
		UserID:    userID,
		Data: map[string]interface{}{
			"cleared_by": userID,
			"cleared_at": time.Now(),
		},
		Timestamp: time.Now(),
	})

	return nil
}

// broadcastWhiteboardEvent broadcasts whiteboard events to meeting participants
func (s *MeetingWhiteboardService) broadcastWhiteboardEvent(meetingID string, event WhiteboardEvent) {
	if s.hub != nil {
		broadcastMsg := &BroadcastMessage{
			Type:    "whiteboard_event",
			Target:  "room:" + meetingID,
			Message: event,
		}
		s.hub.broadcast <- broadcastMsg
	}
}

// Helper functions
func getIntValue(data map[string]interface{}, key string, defaultValue ...int) int {
	if value, ok := data[key].(float64); ok {
		return int(value)
	}
	if value, ok := data[key].(int); ok {
		return value
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return 0
}

func getBoolValueWithDefault(data map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := data[key].(bool); ok {
		return value
	}
	return defaultValue
}
