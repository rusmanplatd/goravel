package services

import (
	"fmt"
	"sync"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// MeetingService handles meeting operations and real-time features
type MeetingService struct {
	hub                 *WebSocketHub
	notificationService *NotificationService
	liveKitService      *LiveKitService
	mu                  sync.RWMutex
	activeMeetings      map[string]*ActiveMeeting
}

// ActiveMeeting represents an active meeting session
type ActiveMeeting struct {
	MeetingID     string
	Participants  map[string]*models.MeetingParticipant
	BreakoutRooms map[string]*models.MeetingBreakoutRoom
	IsRecording   bool
	StartedAt     time.Time
	LastActivity  time.Time
	mu            sync.RWMutex
}

// MeetingEvent represents a real-time meeting event
type MeetingEvent struct {
	Type      string      `json:"type"`
	MeetingID string      `json:"meeting_id"`
	UserID    string      `json:"user_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ParticipantUpdate represents a participant status update
type ParticipantUpdate struct {
	ParticipantID   string `json:"participant_id"`
	UserID          string `json:"user_id"`
	Status          string `json:"status"`
	IsMuted         bool   `json:"is_muted"`
	IsVideoEnabled  bool   `json:"is_video_enabled"`
	IsScreenSharing bool   `json:"is_screen_sharing"`
	IsHandRaised    bool   `json:"is_hand_raised"`
}

// ChatMessage represents a meeting chat message
type ChatMessage struct {
	MessageID   string    `json:"message_id"`
	SenderID    string    `json:"sender_id"`
	SenderName  string    `json:"sender_name"`
	RecipientID *string   `json:"recipient_id,omitempty"`
	Content     string    `json:"content"`
	MessageType string    `json:"message_type"`
	IsPrivate   bool      `json:"is_private"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewMeetingService creates a new meeting service
func NewMeetingService() *MeetingService {
	return &MeetingService{
		hub:                 GetWebSocketHub(),
		notificationService: NewNotificationService(),
		liveKitService:      NewLiveKitService(),
		activeMeetings:      make(map[string]*ActiveMeeting),
	}
}

// StartMeeting starts a meeting session
func (s *MeetingService) StartMeeting(meetingID, hostUserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if meeting is already active
	if _, exists := s.activeMeetings[meetingID]; exists {
		return ErrMeetingAlreadyActiveError(meetingID)
	}

	// Get meeting from database
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return ErrMeetingNotFoundError(meetingID)
	}

	// Update meeting status
	meeting.Status = "in_progress"
	now := time.Now()
	meeting.StartedAt = &now
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update meeting status: %v", err)
	}

	// Create active meeting session
	activeMeeting := &ActiveMeeting{
		MeetingID:     meetingID,
		Participants:  make(map[string]*models.MeetingParticipant),
		BreakoutRooms: make(map[string]*models.MeetingBreakoutRoom),
		IsRecording:   meeting.RecordMeeting,
		StartedAt:     now,
		LastActivity:  now,
	}

	s.activeMeetings[meetingID] = activeMeeting

	// Broadcast meeting started event
	event := MeetingEvent{
		Type:      "meeting_started",
		MeetingID: meetingID,
		UserID:    hostUserID,
		Data: map[string]interface{}{
			"meeting_id":   meetingID,
			"started_at":   now,
			"is_recording": meeting.RecordMeeting,
		},
		Timestamp: now,
	}

	s.broadcastMeetingEvent(meetingID, event)

	facades.Log().Info("Meeting started", map[string]interface{}{
		"meeting_id": meetingID,
		"host_id":    hostUserID,
		"started_at": now,
	})

	return nil
}

// JoinMeeting adds a participant to a meeting
func (s *MeetingService) JoinMeeting(meetingID, userID, connectionID string, deviceInfo map[string]string) (*models.MeetingParticipant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create active meeting
	activeMeeting, exists := s.activeMeetings[meetingID]
	if !exists {
		return nil, fmt.Errorf("meeting is not active")
	}

	// Check if user is already a participant
	var participant models.MeetingParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).Where("user_id", userID).First(&participant)

	if err != nil {
		// Create new participant
		participant = models.MeetingParticipant{
			MeetingID:               meetingID,
			UserID:                  userID,
			Role:                    "attendee",
			Status:                  "joined",
			IsMuted:                 true, // Join muted by default
			IsVideoEnabled:          false,
			IsScreenSharing:         false,
			IsHandRaised:            false,
			IsInWaitingRoom:         false,
			IsRecordingConsentGiven: false,
			ConnectionID:            connectionID,
			DeviceType:              deviceInfo["device_type"],
			BrowserInfo:             deviceInfo["browser_info"],
			IPAddress:               deviceInfo["ip_address"],
		}

		now := time.Now()
		participant.JoinedAt = &now

		if err := facades.Orm().Query().Create(&participant); err != nil {
			return nil, fmt.Errorf("failed to create participant: %v", err)
		}
	} else {
		// Update existing participant
		participant.Status = "joined"
		participant.ConnectionID = connectionID
		participant.DeviceType = deviceInfo["device_type"]
		participant.BrowserInfo = deviceInfo["browser_info"]
		participant.IPAddress = deviceInfo["ip_address"]
		now := time.Now()
		participant.JoinedAt = &now

		if err := facades.Orm().Query().Save(&participant); err != nil {
			return nil, fmt.Errorf("failed to update participant: %v", err)
		}
	}

	// Add to active meeting
	activeMeeting.mu.Lock()
	activeMeeting.Participants[userID] = &participant
	activeMeeting.LastActivity = time.Now()
	activeMeeting.mu.Unlock()

	// Broadcast participant joined event
	event := MeetingEvent{
		Type:      "participant_joined",
		MeetingID: meetingID,
		UserID:    userID,
		Data: ParticipantUpdate{
			ParticipantID:   participant.ID,
			UserID:          userID,
			Status:          participant.Status,
			IsMuted:         participant.IsMuted,
			IsVideoEnabled:  participant.IsVideoEnabled,
			IsScreenSharing: participant.IsScreenSharing,
			IsHandRaised:    participant.IsHandRaised,
		},
		Timestamp: time.Now(),
	}

	s.broadcastMeetingEvent(meetingID, event)

	facades.Log().Info("Participant joined meeting", map[string]interface{}{
		"meeting_id":     meetingID,
		"user_id":        userID,
		"participant_id": participant.ID,
	})

	return &participant, nil
}

// LeaveMeeting removes a participant from a meeting
func (s *MeetingService) LeaveMeeting(meetingID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	activeMeeting, exists := s.activeMeetings[meetingID]
	if !exists {
		return fmt.Errorf("meeting is not active")
	}

	// Update participant in database
	var participant models.MeetingParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).Where("user_id", userID).First(&participant)
	if err != nil {
		return fmt.Errorf("participant not found: %v", err)
	}

	participant.Status = "left"
	now := time.Now()
	participant.LeftAt = &now

	// Calculate duration
	if participant.JoinedAt != nil {
		duration := now.Sub(*participant.JoinedAt)
		participant.DurationSeconds = int(duration.Seconds())
	}

	if err := facades.Orm().Query().Save(&participant); err != nil {
		return fmt.Errorf("failed to update participant: %v", err)
	}

	// Remove from active meeting
	activeMeeting.mu.Lock()
	delete(activeMeeting.Participants, userID)
	activeMeeting.LastActivity = time.Now()
	activeMeeting.mu.Unlock()

	// Broadcast participant left event
	event := MeetingEvent{
		Type:      "participant_left",
		MeetingID: meetingID,
		UserID:    userID,
		Data: map[string]interface{}{
			"participant_id": participant.ID,
			"user_id":        userID,
			"duration":       participant.DurationSeconds,
		},
		Timestamp: now,
	}

	s.broadcastMeetingEvent(meetingID, event)

	facades.Log().Info("Participant left meeting", map[string]interface{}{
		"meeting_id":     meetingID,
		"user_id":        userID,
		"participant_id": participant.ID,
		"duration":       participant.DurationSeconds,
	})

	return nil
}

// UpdateParticipantStatus updates participant's real-time status
func (s *MeetingService) UpdateParticipantStatus(meetingID, userID string, updates map[string]interface{}) error {
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("meeting is not active")
	}

	// Get participant from database
	var participant models.MeetingParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).Where("user_id", userID).First(&participant)
	if err != nil {
		return fmt.Errorf("participant not found: %v", err)
	}

	// Update participant fields
	if muted, ok := updates["is_muted"].(bool); ok {
		participant.IsMuted = muted
	}
	if video, ok := updates["is_video_enabled"].(bool); ok {
		participant.IsVideoEnabled = video
	}
	if sharing, ok := updates["is_screen_sharing"].(bool); ok {
		participant.IsScreenSharing = sharing
	}
	if handRaised, ok := updates["is_hand_raised"].(bool); ok {
		participant.IsHandRaised = handRaised
	}
	if waitingRoom, ok := updates["is_in_waiting_room"].(bool); ok {
		participant.IsInWaitingRoom = waitingRoom
	}

	if err := facades.Orm().Query().Save(&participant); err != nil {
		return fmt.Errorf("failed to update participant: %v", err)
	}

	// Update active meeting
	activeMeeting.mu.Lock()
	activeMeeting.Participants[userID] = &participant
	activeMeeting.LastActivity = time.Now()
	activeMeeting.mu.Unlock()

	// Broadcast participant update event
	event := MeetingEvent{
		Type:      "participant_updated",
		MeetingID: meetingID,
		UserID:    userID,
		Data: ParticipantUpdate{
			ParticipantID:   participant.ID,
			UserID:          userID,
			Status:          participant.Status,
			IsMuted:         participant.IsMuted,
			IsVideoEnabled:  participant.IsVideoEnabled,
			IsScreenSharing: participant.IsScreenSharing,
			IsHandRaised:    participant.IsHandRaised,
		},
		Timestamp: time.Now(),
	}

	s.broadcastMeetingEvent(meetingID, event)

	return nil
}

// SendChatMessage sends a chat message in a meeting
func (s *MeetingService) SendChatMessage(meetingID, senderID string, content, messageType string, recipientID *string) (*models.MeetingChat, error) {
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("meeting is not active")
	}

	// Verify sender is a participant
	activeMeeting.mu.RLock()
	_, isParticipant := activeMeeting.Participants[senderID]
	activeMeeting.mu.RUnlock()

	if !isParticipant {
		return nil, fmt.Errorf("sender is not a meeting participant")
	}

	// Create chat message
	chatMessage := models.MeetingChat{
		MeetingID:   meetingID,
		SenderID:    senderID,
		RecipientID: recipientID,
		MessageType: messageType,
		Content:     content,
		IsPrivate:   recipientID != nil,
		IsSystem:    false,
		Status:      "sent",
	}

	if err := facades.Orm().Query().Create(&chatMessage); err != nil {
		return nil, fmt.Errorf("failed to create chat message: %v", err)
	}

	// Get sender info
	var sender models.User
	facades.Orm().Query().Where("id", senderID).First(&sender)

	// Create chat event
	chatEvent := ChatMessage{
		MessageID:   chatMessage.ID,
		SenderID:    senderID,
		SenderName:  sender.Name,
		RecipientID: recipientID,
		Content:     content,
		MessageType: messageType,
		IsPrivate:   recipientID != nil,
		Timestamp:   chatMessage.CreatedAt,
	}

	// Broadcast chat message event
	event := MeetingEvent{
		Type:      "chat_message",
		MeetingID: meetingID,
		UserID:    senderID,
		Data:      chatEvent,
		Timestamp: time.Now(),
	}

	if recipientID != nil {
		// Send private message to specific participant
		s.broadcastToParticipant(meetingID, *recipientID, event)
		s.broadcastToParticipant(meetingID, senderID, event) // Also send to sender
	} else {
		// Broadcast to all participants
		s.broadcastMeetingEvent(meetingID, event)
	}

	activeMeeting.mu.Lock()
	activeMeeting.LastActivity = time.Now()
	activeMeeting.mu.Unlock()

	return &chatMessage, nil
}

// CreateBreakoutRooms creates breakout rooms for a meeting
func (s *MeetingService) CreateBreakoutRooms(meetingID, hostUserID string, rooms []map[string]interface{}) ([]models.MeetingBreakoutRoom, error) {
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("meeting is not active")
	}

	var createdRooms []models.MeetingBreakoutRoom

	for i, roomData := range rooms {
		room := models.MeetingBreakoutRoom{
			MeetingID:                 meetingID,
			Name:                      fmt.Sprintf("Breakout Room %d", i+1),
			Description:               "",
			Capacity:                  10, // Default capacity
			Status:                    "active",
			AutoAssign:                false,
			AllowParticipantsToChoose: true,
			AllowParticipantsToReturn: true,
			TimeLimitMinutes:          0, // Unlimited by default
		}

		// Override defaults with provided data
		if name, ok := roomData["name"].(string); ok {
			room.Name = name
		}
		if desc, ok := roomData["description"].(string); ok {
			room.Description = desc
		}
		if capacity, ok := roomData["capacity"].(int); ok {
			room.Capacity = capacity
		}
		if timeLimit, ok := roomData["time_limit_minutes"].(int); ok {
			room.TimeLimitMinutes = timeLimit
		}

		if err := facades.Orm().Query().Create(&room); err != nil {
			return nil, fmt.Errorf("failed to create breakout room: %v", err)
		}

		createdRooms = append(createdRooms, room)

		// Add to active meeting
		activeMeeting.mu.Lock()
		activeMeeting.BreakoutRooms[room.ID] = &room
		activeMeeting.LastActivity = time.Now()
		activeMeeting.mu.Unlock()
	}

	// Broadcast breakout rooms created event
	event := MeetingEvent{
		Type:      "breakout_rooms_created",
		MeetingID: meetingID,
		UserID:    hostUserID,
		Data: map[string]interface{}{
			"rooms": createdRooms,
		},
		Timestamp: time.Now(),
	}

	s.broadcastMeetingEvent(meetingID, event)

	return createdRooms, nil
}

// AssignToBreakoutRoom assigns a participant to a breakout room
func (s *MeetingService) AssignToBreakoutRoom(meetingID, participantUserID, breakoutRoomID, assignedByUserID string) error {
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("meeting is not active")
	}

	// Get meeting participant
	var participant models.MeetingParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).Where("user_id", participantUserID).First(&participant)
	if err != nil {
		return fmt.Errorf("participant not found: %v", err)
	}

	// Create breakout room participant assignment
	assignment := models.BreakoutRoomParticipant{
		BreakoutRoomID:       breakoutRoomID,
		MeetingParticipantID: participant.ID,
		AssignmentType:       "manual",
		Status:               "assigned",
	}

	if err := facades.Orm().Query().Create(&assignment); err != nil {
		return fmt.Errorf("failed to create breakout room assignment: %v", err)
	}

	// Broadcast assignment event
	event := MeetingEvent{
		Type:      "breakout_room_assigned",
		MeetingID: meetingID,
		UserID:    assignedByUserID,
		Data: map[string]interface{}{
			"participant_id":   participantUserID,
			"breakout_room_id": breakoutRoomID,
			"assignment_id":    assignment.ID,
		},
		Timestamp: time.Now(),
	}

	s.broadcastToParticipant(meetingID, participantUserID, event)

	activeMeeting.mu.Lock()
	activeMeeting.LastActivity = time.Now()
	activeMeeting.mu.Unlock()

	return nil
}

// EndMeeting ends a meeting session
func (s *MeetingService) EndMeeting(meetingID, hostUserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	activeMeeting, exists := s.activeMeetings[meetingID]
	if !exists {
		return fmt.Errorf("meeting is not active")
	}

	// Update meeting in database
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	meeting.Status = "completed"
	now := time.Now()
	meeting.EndedAt = &now

	// Calculate attendance count
	activeMeeting.mu.RLock()
	meeting.AttendanceCount = len(activeMeeting.Participants)
	activeMeeting.mu.RUnlock()

	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to update meeting: %v", err)
	}

	// Update all active participants
	activeMeeting.mu.RLock()
	for _, participant := range activeMeeting.Participants {
		if participant.Status == "joined" {
			participant.Status = "left"
			participant.LeftAt = &now
			if participant.JoinedAt != nil {
				duration := now.Sub(*participant.JoinedAt)
				participant.DurationSeconds = int(duration.Seconds())
			}
			facades.Orm().Query().Save(participant)
		}
	}
	activeMeeting.mu.RUnlock()

	// Broadcast meeting ended event
	event := MeetingEvent{
		Type:      "meeting_ended",
		MeetingID: meetingID,
		UserID:    hostUserID,
		Data: map[string]interface{}{
			"meeting_id":       meetingID,
			"ended_at":         now,
			"attendance_count": meeting.AttendanceCount,
		},
		Timestamp: now,
	}

	s.broadcastMeetingEvent(meetingID, event)

	// Remove from active meetings
	delete(s.activeMeetings, meetingID)

	facades.Log().Info("Meeting ended", map[string]interface{}{
		"meeting_id":       meetingID,
		"host_id":          hostUserID,
		"ended_at":         now,
		"attendance_count": meeting.AttendanceCount,
	})

	return nil
}

// GetActiveMeetingParticipants returns current participants in a meeting
func (s *MeetingService) GetActiveMeetingParticipants(meetingID string) ([]models.MeetingParticipant, error) {
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("meeting is not active")
	}

	activeMeeting.mu.RLock()
	defer activeMeeting.mu.RUnlock()

	var participants []models.MeetingParticipant
	for _, participant := range activeMeeting.Participants {
		participants = append(participants, *participant)
	}

	return participants, nil
}

// broadcastMeetingEvent broadcasts an event to all meeting participants
func (s *MeetingService) broadcastMeetingEvent(meetingID string, event MeetingEvent) {
	if s.hub == nil {
		return
	}

	// Get all participants in the meeting
	s.mu.RLock()
	activeMeeting, exists := s.activeMeetings[meetingID]
	s.mu.RUnlock()

	if !exists {
		return
	}

	activeMeeting.mu.RLock()
	defer activeMeeting.mu.RUnlock()

	// Broadcast to all participants
	for userID := range activeMeeting.Participants {
		s.hub.SendToUser(userID, event)
	}
}

// broadcastToParticipant broadcasts an event to a specific participant
func (s *MeetingService) broadcastToParticipant(meetingID, userID string, event MeetingEvent) {
	if s.hub == nil {
		return
	}

	s.hub.SendToUser(userID, event)
}

// GetMeetingChatHistory returns chat history for a meeting
func (s *MeetingService) GetMeetingChatHistory(meetingID, userID string, limit, offset int) ([]models.MeetingChat, error) {
	// Verify user is a participant
	var participant models.MeetingParticipant
	err := facades.Orm().Query().Where("meeting_id", meetingID).Where("user_id", userID).First(&participant)
	if err != nil {
		return nil, fmt.Errorf("access denied: not a meeting participant")
	}

	var messages []models.MeetingChat
	query := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("(is_private = ? OR (is_private = ? AND (sender_id = ? OR recipient_id = ?)))", false, true, userID, userID).
		Order("created_at ASC").
		Limit(limit).
		Offset(offset)

	err = query.Find(&messages)
	if err != nil {
		return nil, fmt.Errorf("failed to get chat history: %v", err)
	}

	return messages, nil
}

// IsActiveMeeting checks if a meeting is currently active
func (s *MeetingService) IsActiveMeeting(meetingID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.activeMeetings[meetingID]
	return exists
}

// GetActiveMeetings returns all currently active meetings
func (s *MeetingService) GetActiveMeetings() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var meetingIDs []string
	for meetingID := range s.activeMeetings {
		meetingIDs = append(meetingIDs, meetingID)
	}

	return meetingIDs
}
