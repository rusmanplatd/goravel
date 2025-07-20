package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"goravel/app/services"

	goravelhttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/gorilla/websocket"
)

type WebSocketController struct {
	hub *services.WebSocketHub
}

func NewWebSocketController() *WebSocketController {
	return &WebSocketController{
		hub: services.GetWebSocketHub(),
	}
}

// Connect establishes a WebSocket connection for notifications
func (c *WebSocketController) Connect(ctx goravelhttp.Context) goravelhttp.Response {
	// Get user ID from authentication (you'll need to implement this based on your auth system)
	userID := c.getUserIDFromContext(ctx)
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	// Upgrade the HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// In production, implement proper origin checking
			return true
		},
	}

	// Get the underlying HTTP response writer and request
	responseWriter := ctx.Response().Writer()
	request := ctx.Request().Origin()

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		facades.Log().Error("Failed to upgrade connection to WebSocket", map[string]interface{}{
			"error": err.Error(),
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to establish WebSocket connection",
		})
	}

	// Create WebSocket connection
	wsConn := &services.WebSocketConnection{
		ID:     fmt.Sprintf("conn_%s_%d", userID, time.Now().UnixNano()),
		UserID: userID,
		Send:   make(chan []byte, 256),
		Hub:    c.hub,
	}

	// Register the connection
	c.hub.RegisterConnection(wsConn)

	// Start goroutines to handle reading and writing
	go c.handleRead(wsConn, conn)
	go c.handleWrite(wsConn, conn)

	// Return success (the WebSocket connection is now established)
	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "WebSocket connection established",
		"user_id": userID,
	})
}

// handleRead handles incoming messages from the WebSocket client
func (c *WebSocketController) handleRead(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	defer func() {
		c.hub.UnregisterConnection(wsConn)
		conn.Close()
	}()

	conn.SetReadLimit(512) // Limit message size
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
			}
			break
		}

		// Handle the message
		c.handleMessage(wsConn, message)
	}
}

// handleWrite handles outgoing messages to the WebSocket client
func (c *WebSocketController) handleWrite(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
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
				// The hub closed the channel
				conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message
			n := len(wsConn.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-wsConn.Send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming WebSocket messages
func (c *WebSocketController) handleMessage(wsConn *services.WebSocketConnection, message []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		facades.Log().Error("Failed to unmarshal WebSocket message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
		})
		return
	}

	// Handle different message types
	msgType, ok := msg["type"].(string)
	if !ok {
		facades.Log().Error("Invalid message type", map[string]interface{}{
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
		})
		return
	}

	switch msgType {
	case "ping":
		// Send pong response
		response := map[string]interface{}{
			"type":      "pong",
			"timestamp": time.Now().Unix(),
		}
		responseBytes, _ := json.Marshal(response)
		wsConn.Send <- responseBytes

	case "subscribe":
		// Handle subscription to specific notification types
		c.handleSubscribe(wsConn, msg)

	case "unsubscribe":
		// Handle unsubscription from specific notification types
		c.handleUnsubscribe(wsConn, msg)

	default:
		facades.Log().Warning("Unknown message type", map[string]interface{}{
			"type":          msgType,
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
		})
	}
}

// handleSubscribe handles subscription to notification types
func (c *WebSocketController) handleSubscribe(wsConn *services.WebSocketConnection, msg map[string]interface{}) {
	// This is a simplified implementation
	// In a real application, you'd store subscription preferences
	facades.Log().Info("User subscribed to notifications", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       wsConn.UserID,
		"message":       msg,
	})

	// Send confirmation
	response := map[string]interface{}{
		"type":      "subscribed",
		"timestamp": time.Now().Unix(),
	}
	responseBytes, _ := json.Marshal(response)
	wsConn.Send <- responseBytes
}

// handleUnsubscribe handles unsubscription from notification types
func (c *WebSocketController) handleUnsubscribe(wsConn *services.WebSocketConnection, msg map[string]interface{}) {
	// This is a simplified implementation
	// In a real application, you'd store subscription preferences
	facades.Log().Info("User unsubscribed from notifications", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       wsConn.UserID,
		"message":       msg,
	})

	// Send confirmation
	response := map[string]interface{}{
		"type":      "unsubscribed",
		"timestamp": time.Now().Unix(),
	}
	responseBytes, _ := json.Marshal(response)
	wsConn.Send <- responseBytes
}

// getUserIDFromContext extracts the user ID from the context
// This is a placeholder - implement based on your authentication system
func (c *WebSocketController) getUserIDFromContext(ctx goravelhttp.Context) string {
	// In a real application, you'd get this from your authentication middleware
	// For now, we'll use a query parameter or header
	userID := ctx.Request().Query("user_id")
	if userID == "" {
		userID = ctx.Request().Header("X-User-ID")
	}
	return userID
}

// GetConnectionStats returns statistics about WebSocket connections
func (c *WebSocketController) GetConnectionStats(ctx goravelhttp.Context) goravelhttp.Response {
	stats := map[string]interface{}{
		"total_connections": c.hub.GetTotalConnections(),
		"connected_users":   c.hub.GetConnectedUsers(),
	}

	return ctx.Response().Success().Json(stats)
}

// SendTestNotification sends a test notification to a specific user
func (c *WebSocketController) SendTestNotification(ctx goravelhttp.Context) goravelhttp.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "User ID is required",
		})
	}

	// Create a test notification message
	testMessage := map[string]interface{}{
		"type": "notification",
		"data": map[string]interface{}{
			"id":        "test_notification",
			"title":     "Test Notification",
			"body":      "This is a test notification sent via WebSocket",
			"message":   "Test message content",
			"timestamp": time.Now().Unix(),
		},
	}

	// Send the test notification
	if err := c.hub.SendToUser(userID, testMessage); err != nil {
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": err.Error(),
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "Test notification sent successfully",
		"user_id": userID,
	})
}
