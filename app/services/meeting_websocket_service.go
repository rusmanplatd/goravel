package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"github.com/gorilla/websocket"
)

// MeetingWebSocketService handles real-time WebSocket connections for meetings
type MeetingWebSocketService struct {
	connections     map[string]*MeetingConnection            // connectionID -> connection
	meetingRooms    map[string]map[string]*MeetingConnection // meetingID -> connectionID -> connection
	mu              sync.RWMutex
	heartbeatTicker *time.Ticker
	ctx             context.Context
	cancel          context.CancelFunc
}

// MeetingConnection represents a WebSocket connection for a meeting participant
type MeetingConnection struct {
	ID         string
	UserID     string
	MeetingID  string
	UserRole   string
	Conn       *websocket.Conn
	Send       chan []byte
	LastPing   time.Time
	IsActive   bool
	DeviceInfo map[string]interface{}
	JoinedAt   time.Time
	mu         sync.RWMutex
}

// MeetingWebSocketMessage represents a WebSocket message for meetings
type MeetingWebSocketMessage struct {
	Type      string                 `json:"type"`
	MeetingID string                 `json:"meeting_id"`
	UserID    string                 `json:"user_id"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// Message types
const (
	MessageTypeJoin              = "join"
	MessageTypeLeave             = "leave"
	MessageTypeParticipantUpdate = "participant_update"
	MessageTypeChat              = "chat"
	MessageTypeScreenShare       = "screen_share"
	MessageTypeRecording         = "recording"
	MessageTypeBreakoutRoom      = "breakout_room"
	MessageTypePoll              = "poll"
	MessageTypeWhiteboard        = "whiteboard"
	MessageTypeReaction          = "reaction"
	MessageTypeHandRaise         = "hand_raise"
	MessageTypeError             = "error"
	MessageTypePing              = "ping"
	MessageTypePong              = "pong"
	MessageTypeConnectionStatus  = "connection_status"
	MessageTypeParticipantList   = "participant_list"
	MessageTypeMeetingStatus     = "meeting_status"
)

// NewMeetingWebSocketService creates a new meeting WebSocket service
func NewMeetingWebSocketService() *MeetingWebSocketService {
	ctx, cancel := context.WithCancel(context.Background())

	service := &MeetingWebSocketService{
		connections:  make(map[string]*MeetingConnection),
		meetingRooms: make(map[string]map[string]*MeetingConnection),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start heartbeat monitoring
	service.startHeartbeat()

	return service
}

// AddConnection adds a new WebSocket connection for a meeting participant
func (mws *MeetingWebSocketService) AddConnection(connectionID, userID, meetingID, userRole string, conn *websocket.Conn, deviceInfo map[string]interface{}) error {
	mws.mu.Lock()
	defer mws.mu.Unlock()

	// Create new connection
	meetingConn := &MeetingConnection{
		ID:         connectionID,
		UserID:     userID,
		MeetingID:  meetingID,
		UserRole:   userRole,
		Conn:       conn,
		Send:       make(chan []byte, 256),
		LastPing:   time.Now(),
		IsActive:   true,
		DeviceInfo: deviceInfo,
		JoinedAt:   time.Now(),
	}

	// Add to connections map
	mws.connections[connectionID] = meetingConn

	// Add to meeting room
	if mws.meetingRooms[meetingID] == nil {
		mws.meetingRooms[meetingID] = make(map[string]*MeetingConnection)
	}
	mws.meetingRooms[meetingID][connectionID] = meetingConn

	// Start connection handlers
	go mws.handleConnection(meetingConn)
	go mws.handleConnectionWriter(meetingConn)

	// Notify other participants about new join
	mws.broadcastToMeeting(meetingID, MeetingWebSocketMessage{
		Type:      MessageTypeJoin,
		MeetingID: meetingID,
		UserID:    userID,
		Data: map[string]interface{}{
			"user_id":     userID,
			"user_role":   userRole,
			"device_info": deviceInfo,
			"joined_at":   time.Now(),
		},
		Timestamp: time.Now(),
	}, connectionID) // Exclude the joining user

	facades.Log().Info("WebSocket connection added", map[string]interface{}{
		"connection_id": connectionID,
		"user_id":       userID,
		"meeting_id":    meetingID,
		"user_role":     userRole,
	})

	return nil
}

// RemoveConnection removes a WebSocket connection
func (mws *MeetingWebSocketService) RemoveConnection(connectionID string) {
	mws.mu.Lock()
	defer mws.mu.Unlock()

	conn, exists := mws.connections[connectionID]
	if !exists {
		return
	}

	// Close connection
	conn.IsActive = false
	close(conn.Send)
	conn.Conn.Close()

	// Remove from meeting room
	if room, exists := mws.meetingRooms[conn.MeetingID]; exists {
		delete(room, connectionID)

		// Clean up empty room
		if len(room) == 0 {
			delete(mws.meetingRooms, conn.MeetingID)
		} else {
			// Notify other participants about leave
			mws.broadcastToMeeting(conn.MeetingID, MeetingWebSocketMessage{
				Type:      MessageTypeLeave,
				MeetingID: conn.MeetingID,
				UserID:    conn.UserID,
				Data: map[string]interface{}{
					"user_id":  conn.UserID,
					"left_at":  time.Now(),
					"duration": time.Since(conn.JoinedAt).Seconds(),
				},
				Timestamp: time.Now(),
			}, connectionID)
		}
	}

	// Remove from connections map
	delete(mws.connections, connectionID)

	facades.Log().Info("WebSocket connection removed", map[string]interface{}{
		"connection_id": connectionID,
		"user_id":       conn.UserID,
		"meeting_id":    conn.MeetingID,
		"duration":      time.Since(conn.JoinedAt).Seconds(),
	})
}

// BroadcastToMeeting broadcasts a message to all participants in a meeting
func (mws *MeetingWebSocketService) BroadcastToMeeting(meetingID string, message MeetingWebSocketMessage, excludeConnectionID ...string) {
	mws.broadcastToMeeting(meetingID, message, excludeConnectionID...)
}

// broadcastToMeeting internal method to broadcast messages
func (mws *MeetingWebSocketService) broadcastToMeeting(meetingID string, message MeetingWebSocketMessage, excludeConnectionID ...string) {
	mws.mu.RLock()
	room, exists := mws.meetingRooms[meetingID]
	if !exists {
		mws.mu.RUnlock()
		return
	}

	// Create exclude map for efficient lookup
	excludeMap := make(map[string]bool)
	for _, id := range excludeConnectionID {
		excludeMap[id] = true
	}

	// Prepare message
	messageBytes, err := json.Marshal(message)
	if err != nil {
		mws.mu.RUnlock()
		facades.Log().Error("Failed to marshal WebSocket message", map[string]interface{}{
			"error":      err.Error(),
			"message":    message,
			"meeting_id": meetingID,
		})
		return
	}

	// Send to all connections in the room
	for connID, conn := range room {
		if excludeMap[connID] || !conn.IsActive {
			continue
		}

		select {
		case conn.Send <- messageBytes:
		default:
			// Connection send buffer is full, close it
			mws.mu.RUnlock()
			mws.RemoveConnection(connID)
			mws.mu.RLock()
		}
	}
	mws.mu.RUnlock()
}

// SendToConnection sends a message to a specific connection
func (mws *MeetingWebSocketService) SendToConnection(connectionID string, message MeetingWebSocketMessage) error {
	mws.mu.RLock()
	conn, exists := mws.connections[connectionID]
	mws.mu.RUnlock()

	if !exists || !conn.IsActive {
		return fmt.Errorf("connection not found or inactive: %s", connectionID)
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	select {
	case conn.Send <- messageBytes:
		return nil
	default:
		// Connection send buffer is full
		mws.RemoveConnection(connectionID)
		return fmt.Errorf("connection send buffer full, connection closed")
	}
}

// GetMeetingParticipants returns active participants in a meeting
func (mws *MeetingWebSocketService) GetMeetingParticipants(meetingID string) []map[string]interface{} {
	mws.mu.RLock()
	defer mws.mu.RUnlock()

	room, exists := mws.meetingRooms[meetingID]
	if !exists {
		return []map[string]interface{}{}
	}

	participants := make([]map[string]interface{}, 0, len(room))
	for _, conn := range room {
		if conn.IsActive {
			participants = append(participants, map[string]interface{}{
				"connection_id": conn.ID,
				"user_id":       conn.UserID,
				"user_role":     conn.UserRole,
				"device_info":   conn.DeviceInfo,
				"joined_at":     conn.JoinedAt,
				"last_ping":     conn.LastPing,
			})
		}
	}

	return participants
}

// handleConnection handles incoming WebSocket messages
func (mws *MeetingWebSocketService) handleConnection(conn *MeetingConnection) {
	defer mws.RemoveConnection(conn.ID)

	// Set read deadline and pong handler
	conn.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.Conn.SetPongHandler(func(string) error {
		conn.mu.Lock()
		conn.LastPing = time.Now()
		conn.mu.Unlock()
		conn.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		var message MeetingWebSocketMessage
		err := conn.Conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("WebSocket unexpected close", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": conn.ID,
					"user_id":       conn.UserID,
					"meeting_id":    conn.MeetingID,
				})
			}
			break
		}

		// Update last activity
		conn.mu.Lock()
		conn.LastPing = time.Now()
		conn.mu.Unlock()

		// Handle different message types
		mws.handleMessage(conn, message)
	}
}

// handleConnectionWriter handles outgoing WebSocket messages
func (mws *MeetingWebSocketService) handleConnectionWriter(conn *MeetingConnection) {
	ticker := time.NewTicker(54 * time.Second) // Ping every 54 seconds
	defer func() {
		ticker.Stop()
		conn.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-conn.Send:
			conn.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				conn.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := conn.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			conn.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming WebSocket messages
func (mws *MeetingWebSocketService) handleMessage(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Validate message
	if message.MeetingID != conn.MeetingID {
		mws.sendError(conn, "Message meeting ID doesn't match connection meeting ID")
		return
	}

	switch message.Type {
	case MessageTypePing:
		mws.handlePing(conn, message)
	case MessageTypeParticipantUpdate:
		mws.handleParticipantUpdate(conn, message)
	case MessageTypeChat:
		mws.handleChat(conn, message)
	case MessageTypeScreenShare:
		mws.handleScreenShare(conn, message)
	case MessageTypeReaction:
		mws.handleReaction(conn, message)
	case MessageTypeHandRaise:
		mws.handleHandRaise(conn, message)
	default:
		facades.Log().Warning("Unknown WebSocket message type", map[string]interface{}{
			"type":          message.Type,
			"connection_id": conn.ID,
			"user_id":       conn.UserID,
			"meeting_id":    conn.MeetingID,
		})
	}
}

// handlePing responds to ping messages
func (mws *MeetingWebSocketService) handlePing(conn *MeetingConnection, message MeetingWebSocketMessage) {
	response := MeetingWebSocketMessage{
		Type:      MessageTypePong,
		MeetingID: conn.MeetingID,
		UserID:    conn.UserID,
		Data: map[string]interface{}{
			"timestamp": time.Now(),
		},
		Timestamp: time.Now(),
	}
	mws.SendToConnection(conn.ID, response)
}

// handleParticipantUpdate handles participant status updates
func (mws *MeetingWebSocketService) handleParticipantUpdate(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Broadcast update to all other participants
	mws.broadcastToMeeting(conn.MeetingID, message, conn.ID)

	// Update participant in database
	var participant models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", conn.MeetingID).
		Where("user_id", conn.UserID).
		First(&participant)

	if err == nil {
		// Update participant status based on message data
		if isMuted, ok := message.Data["is_muted"].(bool); ok {
			participant.IsMuted = isMuted
		}
		if isVideoEnabled, ok := message.Data["is_video_enabled"].(bool); ok {
			participant.IsVideoEnabled = isVideoEnabled
		}
		if isScreenSharing, ok := message.Data["is_screen_sharing"].(bool); ok {
			participant.IsScreenSharing = isScreenSharing
		}
		if isHandRaised, ok := message.Data["is_hand_raised"].(bool); ok {
			participant.IsHandRaised = isHandRaised
		}

		facades.Orm().Query().Save(&participant)
	}
}

// handleChat handles chat messages
func (mws *MeetingWebSocketService) handleChat(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Add sender information
	message.Data["sender_id"] = conn.UserID
	message.Data["sender_role"] = conn.UserRole

	// Broadcast to all participants
	mws.broadcastToMeeting(conn.MeetingID, message)
}

// handleScreenShare handles screen sharing events
func (mws *MeetingWebSocketService) handleScreenShare(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Add sender information
	message.Data["user_id"] = conn.UserID
	message.Data["user_role"] = conn.UserRole

	// Broadcast to all participants
	mws.broadcastToMeeting(conn.MeetingID, message)
}

// handleReaction handles meeting reactions
func (mws *MeetingWebSocketService) handleReaction(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Add sender information
	message.Data["user_id"] = conn.UserID
	message.Data["user_role"] = conn.UserRole

	// Broadcast to all participants
	mws.broadcastToMeeting(conn.MeetingID, message)
}

// handleHandRaise handles hand raise/lower events
func (mws *MeetingWebSocketService) handleHandRaise(conn *MeetingConnection, message MeetingWebSocketMessage) {
	// Add sender information
	message.Data["user_id"] = conn.UserID
	message.Data["user_role"] = conn.UserRole

	// Broadcast to all participants
	mws.broadcastToMeeting(conn.MeetingID, message)
}

// sendError sends an error message to a connection
func (mws *MeetingWebSocketService) sendError(conn *MeetingConnection, errorMsg string) {
	errorMessage := MeetingWebSocketMessage{
		Type:      MessageTypeError,
		MeetingID: conn.MeetingID,
		UserID:    conn.UserID,
		Data: map[string]interface{}{
			"error": errorMsg,
		},
		Timestamp: time.Now(),
	}
	mws.SendToConnection(conn.ID, errorMessage)
}

// startHeartbeat starts the heartbeat monitoring
func (mws *MeetingWebSocketService) startHeartbeat() {
	mws.heartbeatTicker = time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-mws.heartbeatTicker.C:
				mws.checkConnections()
			case <-mws.ctx.Done():
				return
			}
		}
	}()
}

// checkConnections checks for stale connections and removes them
func (mws *MeetingWebSocketService) checkConnections() {
	mws.mu.RLock()
	staleConnections := make([]string, 0)

	for connID, conn := range mws.connections {
		conn.mu.RLock()
		if time.Since(conn.LastPing) > 90*time.Second {
			staleConnections = append(staleConnections, connID)
		}
		conn.mu.RUnlock()
	}
	mws.mu.RUnlock()

	// Remove stale connections
	for _, connID := range staleConnections {
		facades.Log().Info("Removing stale WebSocket connection", map[string]interface{}{
			"connection_id": connID,
		})
		mws.RemoveConnection(connID)
	}
}

// Shutdown gracefully shuts down the WebSocket service
func (mws *MeetingWebSocketService) Shutdown() {
	mws.cancel()

	if mws.heartbeatTicker != nil {
		mws.heartbeatTicker.Stop()
	}

	// Close all connections
	mws.mu.Lock()
	for connID := range mws.connections {
		mws.RemoveConnection(connID)
	}
	mws.mu.Unlock()
}
