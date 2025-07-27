package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goravel/app/services"

	goravelhttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/gorilla/websocket"
)

// checkWebSocketOrigin validates the origin of WebSocket connections
func checkMeetingWebSocketOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Allow connections without Origin header for non-browser clients
		// but log for security monitoring
		facades.Log().Warning("WebSocket connection without Origin header", map[string]interface{}{
			"remote_addr": r.RemoteAddr,
			"user_agent":  r.Header.Get("User-Agent"),
		})
		return facades.Config().GetBool("websocket.allow_no_origin", false)
	}

	// Parse the origin URL
	originURL, err := url.Parse(origin)
	if err != nil {
		facades.Log().Warning("Invalid Origin header in WebSocket request", map[string]interface{}{
			"origin":      origin,
			"remote_addr": r.RemoteAddr,
			"error":       err.Error(),
		})
		return false
	}

	// Get allowed origins from configuration
	allowedOrigins := facades.Config().Get("websocket.allowed_origins", []string{}).([]string)

	// Check if origin is in allowed list
	for _, allowedOrigin := range allowedOrigins {
		if matchOrigin(originURL, allowedOrigin) {
			facades.Log().Info("WebSocket connection allowed", map[string]interface{}{
				"origin":      origin,
				"remote_addr": r.RemoteAddr,
			})
			return true
		}
	}

	// Check if it's a same-origin request (for development)
	if facades.Config().GetBool("websocket.allow_same_origin", true) {
		host := r.Header.Get("Host")
		if host != "" && (originURL.Host == host || originURL.Host == "localhost:"+strings.Split(host, ":")[1]) {
			facades.Log().Info("WebSocket same-origin connection allowed", map[string]interface{}{
				"origin":      origin,
				"host":        host,
				"remote_addr": r.RemoteAddr,
			})
			return true
		}
	}

	// Log rejected connection for security monitoring
	facades.Log().Warning("WebSocket connection rejected - origin not allowed", map[string]interface{}{
		"origin":          origin,
		"remote_addr":     r.RemoteAddr,
		"user_agent":      r.Header.Get("User-Agent"),
		"allowed_origins": allowedOrigins,
	})

	return false
}

// matchOrigin checks if an origin URL matches an allowed origin pattern
func matchMeetingOrigin(originURL *url.URL, allowedPattern string) bool {
	// Handle wildcard patterns
	if allowedPattern == "*" {
		return true
	}

	// Handle subdomain wildcards (e.g., "*.example.com")
	if strings.HasPrefix(allowedPattern, "*.") {
		domain := strings.TrimPrefix(allowedPattern, "*.")
		return strings.HasSuffix(originURL.Host, "."+domain) || originURL.Host == domain
	}

	// Handle protocol wildcards (e.g., "*://example.com")
	if strings.HasPrefix(allowedPattern, "*://") {
		expectedHost := strings.TrimPrefix(allowedPattern, "*://")
		return originURL.Host == expectedHost
	}

	// Parse allowed origin for exact matching
	allowedURL, err := url.Parse(allowedPattern)
	if err != nil {
		// If parsing fails, try simple string matching
		return originURL.String() == allowedPattern
	}

	// Check scheme and host match
	return originURL.Scheme == allowedURL.Scheme && originURL.Host == allowedURL.Host
}

// MeetingWebSocketController handles WebSocket connections for meetings
type MeetingWebSocketController struct {
	hub            *services.WebSocketHub
	meetingService *services.MeetingService
	upgrader       *websocket.Upgrader
}

// WebRTCSignalMessage represents WebRTC signaling message
type WebRTCSignalMessage struct {
	Type              string                 `json:"type"`
	MeetingID         string                 `json:"meeting_id"`
	FromParticipantID string                 `json:"from_participant_id"`
	ToParticipantID   string                 `json:"to_participant_id"`
	SDP               string                 `json:"sdp,omitempty"`
	Candidate         map[string]interface{} `json:"candidate,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
}

// MeetingReactionMessage represents a meeting reaction
type MeetingReactionMessage struct {
	Type          string    `json:"type"`
	MeetingID     string    `json:"meeting_id"`
	ParticipantID string    `json:"participant_id"`
	ReactionType  string    `json:"reaction_type"`
	Duration      int       `json:"duration"`
	Timestamp     time.Time `json:"timestamp"`
}

// ScreenShareMessage represents screen sharing events
type ScreenShareMessage struct {
	Type          string    `json:"type"`
	MeetingID     string    `json:"meeting_id"`
	ParticipantID string    `json:"participant_id"`
	Action        string    `json:"action"` // start, stop
	StreamID      string    `json:"stream_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// NewMeetingWebSocketController creates a new meeting WebSocket controller
func NewMeetingWebSocketController() *MeetingWebSocketController {
	return &MeetingWebSocketController{
		hub:            services.GetWebSocketHub(),
		meetingService: services.NewMeetingService(),
		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return checkWebSocketOrigin(r)
			},
			EnableCompression: true,
		},
	}
}

// ConnectToMeeting establishes WebSocket connection for meeting
// @Summary Connect to meeting WebSocket
// @Description Establish WebSocket connection for real-time meeting features
// @Tags meetings
// @Param id path string true "Meeting ID"
// @Success 101 "Switching Protocols"
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/meetings/{id}/ws [get]
func (mwc *MeetingWebSocketController) ConnectToMeeting(ctx goravelhttp.Context) goravelhttp.Response {
	meetingID := ctx.Request().Route("id")
	if meetingID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Meeting ID is required",
		})
	}

	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "User authentication required",
		})
	}

	// Check if meeting is active
	if !mwc.meetingService.IsActiveMeeting(meetingID) {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Meeting is not active",
		})
	}

	// Upgrade to WebSocket
	responseWriter := ctx.Response().Writer()
	request := ctx.Request().Origin()

	conn, err := mwc.upgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		facades.Log().Error("Failed to upgrade to WebSocket for meeting", map[string]interface{}{
			"error":      err.Error(),
			"meeting_id": meetingID,
			"user_id":    userID,
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to establish WebSocket connection",
		})
	}

	// Create WebSocket connection
	wsConn := services.NewWebSocketConnection(
		fmt.Sprintf("meeting_%s_%s_%d", meetingID, userID, time.Now().UnixNano()),
		userID,
		conn,
		mwc.hub,
	)

	// Set meeting context
	wsConn.SetMetadata("meeting_id", meetingID)
	wsConn.SetMetadata("connected_at", time.Now())

	// Register connection
	mwc.hub.RegisterConnection(wsConn)

	// Join meeting room
	mwc.hub.JoinRoom(fmt.Sprintf("meeting_%s", meetingID), wsConn.ID)

	// Start message handlers
	go mwc.handleMeetingMessages(wsConn, conn, meetingID, userID)
	go mwc.handleMeetingWrites(wsConn, conn)

	facades.Log().Info("Meeting WebSocket connection established", map[string]interface{}{
		"connection_id": wsConn.ID,
		"meeting_id":    meetingID,
		"user_id":       userID,
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":       "Meeting WebSocket connection established",
		"connection_id": wsConn.ID,
		"meeting_id":    meetingID,
	})
}

// handleMeetingMessages handles incoming WebSocket messages for meetings
func (mwc *MeetingWebSocketController) handleMeetingMessages(wsConn *services.WebSocketConnection, conn *websocket.Conn, meetingID, userID string) {
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("Meeting WebSocket message handler panic", map[string]interface{}{
				"error":         fmt.Sprintf("%v", r),
				"connection_id": wsConn.ID,
				"meeting_id":    meetingID,
				"user_id":       userID,
			})
		}
		conn.Close()
	}()

	// Set read deadline and limits
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetReadLimit(512)

	// Set pong handler
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("Meeting WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"meeting_id":    meetingID,
					"user_id":       userID,
				})
			}
			break
		}

		if messageType == websocket.TextMessage {
			mwc.processMessage(wsConn, meetingID, userID, message)
		}

		// Reset read deadline
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

// processMessage processes incoming WebSocket messages
func (mwc *MeetingWebSocketController) processMessage(wsConn *services.WebSocketConnection, meetingID, userID string, message []byte) {
	var baseMessage map[string]interface{}
	if err := json.Unmarshal(message, &baseMessage); err != nil {
		facades.Log().Error("Failed to parse WebSocket message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	messageType, ok := baseMessage["type"].(string)
	if !ok {
		facades.Log().Warning("Missing message type in WebSocket message", map[string]interface{}{
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	switch messageType {
	case "webrtc_signal":
		mwc.handleWebRTCSignal(wsConn, meetingID, userID, message)
	case "meeting_reaction":
		mwc.handleMeetingReaction(wsConn, meetingID, userID, message)
	case "screen_share":
		mwc.handleScreenShare(wsConn, meetingID, userID, message)
	case "ping":
		mwc.handlePing(wsConn)
	default:
		facades.Log().Warning("Unknown message type in meeting WebSocket", map[string]interface{}{
			"message_type":  messageType,
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
	}
}

// handleWebRTCSignal handles WebRTC signaling messages
func (mwc *MeetingWebSocketController) handleWebRTCSignal(wsConn *services.WebSocketConnection, meetingID, userID string, message []byte) {
	var signalMsg WebRTCSignalMessage
	if err := json.Unmarshal(message, &signalMsg); err != nil {
		facades.Log().Error("Failed to parse WebRTC signal message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	// Validate signal message
	if signalMsg.ToParticipantID == "" {
		facades.Log().Warning("Missing target participant in WebRTC signal", map[string]interface{}{
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	// Set sender information
	signalMsg.FromParticipantID = userID
	signalMsg.MeetingID = meetingID
	signalMsg.Timestamp = time.Now()

	// Forward signal to target participant
	targetMessage := map[string]interface{}{
		"type":                "webrtc_signal",
		"from_participant_id": signalMsg.FromParticipantID,
		"to_participant_id":   signalMsg.ToParticipantID,
		"signal_type":         signalMsg.Type,
		"sdp":                 signalMsg.SDP,
		"candidate":           signalMsg.Candidate,
		"timestamp":           signalMsg.Timestamp,
	}

	if err := mwc.hub.SendToUser(signalMsg.ToParticipantID, targetMessage); err != nil {
		facades.Log().Error("Failed to forward WebRTC signal", map[string]interface{}{
			"error":            err.Error(),
			"from_participant": signalMsg.FromParticipantID,
			"to_participant":   signalMsg.ToParticipantID,
			"meeting_id":       meetingID,
		})
	}

	facades.Log().Debug("WebRTC signal forwarded", map[string]interface{}{
		"signal_type":      signalMsg.Type,
		"from_participant": signalMsg.FromParticipantID,
		"to_participant":   signalMsg.ToParticipantID,
		"meeting_id":       meetingID,
	})
}

// handleMeetingReaction handles meeting reaction messages
func (mwc *MeetingWebSocketController) handleMeetingReaction(wsConn *services.WebSocketConnection, meetingID, userID string, message []byte) {
	var reactionMsg MeetingReactionMessage
	if err := json.Unmarshal(message, &reactionMsg); err != nil {
		facades.Log().Error("Failed to parse meeting reaction message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	// Set reaction information
	reactionMsg.MeetingID = meetingID
	reactionMsg.ParticipantID = userID
	reactionMsg.Timestamp = time.Now()

	// Broadcast reaction to all meeting participants
	broadcastMessage := map[string]interface{}{
		"type":           "meeting_reaction",
		"meeting_id":     meetingID,
		"participant_id": userID,
		"reaction_type":  reactionMsg.ReactionType,
		"duration":       reactionMsg.Duration,
		"timestamp":      reactionMsg.Timestamp,
	}

	roomID := fmt.Sprintf("meeting_%s", meetingID)
	if err := mwc.hub.SendToRoom(roomID, broadcastMessage); err != nil {
		facades.Log().Error("Failed to broadcast meeting reaction", map[string]interface{}{
			"error":          err.Error(),
			"meeting_id":     meetingID,
			"participant_id": userID,
			"reaction_type":  reactionMsg.ReactionType,
		})
	}

	facades.Log().Info("Meeting reaction broadcast", map[string]interface{}{
		"meeting_id":     meetingID,
		"participant_id": userID,
		"reaction_type":  reactionMsg.ReactionType,
		"duration":       reactionMsg.Duration,
	})
}

// handleScreenShare handles screen sharing events
func (mwc *MeetingWebSocketController) handleScreenShare(wsConn *services.WebSocketConnection, meetingID, userID string, message []byte) {
	var shareMsg ScreenShareMessage
	if err := json.Unmarshal(message, &shareMsg); err != nil {
		facades.Log().Error("Failed to parse screen share message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"meeting_id":    meetingID,
			"user_id":       userID,
		})
		return
	}

	// Set screen share information
	shareMsg.MeetingID = meetingID
	shareMsg.ParticipantID = userID
	shareMsg.Timestamp = time.Now()

	// Update participant screen sharing status
	updates := map[string]interface{}{
		"is_screen_sharing": shareMsg.Action == "start",
	}

	if err := mwc.meetingService.UpdateParticipantStatus(meetingID, userID, updates); err != nil {
		facades.Log().Error("Failed to update screen sharing status", map[string]interface{}{
			"error":          err.Error(),
			"meeting_id":     meetingID,
			"participant_id": userID,
			"action":         shareMsg.Action,
		})
		return
	}

	// Broadcast screen share event to all meeting participants
	broadcastMessage := map[string]interface{}{
		"type":           "screen_share",
		"meeting_id":     meetingID,
		"participant_id": userID,
		"action":         shareMsg.Action,
		"stream_id":      shareMsg.StreamID,
		"timestamp":      shareMsg.Timestamp,
	}

	roomID := fmt.Sprintf("meeting_%s", meetingID)
	if err := mwc.hub.SendToRoom(roomID, broadcastMessage); err != nil {
		facades.Log().Error("Failed to broadcast screen share event", map[string]interface{}{
			"error":          err.Error(),
			"meeting_id":     meetingID,
			"participant_id": userID,
			"action":         shareMsg.Action,
		})
	}

	facades.Log().Info("Screen share event broadcast", map[string]interface{}{
		"meeting_id":     meetingID,
		"participant_id": userID,
		"action":         shareMsg.Action,
		"stream_id":      shareMsg.StreamID,
	})
}

// handlePing handles ping messages
func (mwc *MeetingWebSocketController) handlePing(wsConn *services.WebSocketConnection) {
	pongMessage := map[string]interface{}{
		"type":      "pong",
		"timestamp": time.Now(),
	}

	if messageBytes, err := json.Marshal(pongMessage); err == nil {
		select {
		case wsConn.Send <- messageBytes:
		default:
			facades.Log().Warning("Failed to send pong message: channel full", map[string]interface{}{
				"connection_id": wsConn.ID,
			})
		}
	}
}

// handleMeetingWrites handles outgoing WebSocket messages
func (mwc *MeetingWebSocketController) handleMeetingWrites(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		conn.Close()
	}()

	for {
		select {
		case message, ok := <-wsConn.Send:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := conn.NextWriter(websocket.TextMessage)
			if err != nil {
				facades.Log().Error("Failed to get WebSocket writer", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
				})
				return
			}

			if _, err := w.Write(message); err != nil {
				facades.Log().Error("Failed to write WebSocket message", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
				})
				w.Close()
				return
			}

			if err := w.Close(); err != nil {
				facades.Log().Error("Failed to close WebSocket writer", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
				})
				return
			}

		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				facades.Log().Warning("Failed to send ping message", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
				})
				return
			}
		}
	}
}
