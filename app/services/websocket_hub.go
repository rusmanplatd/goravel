package services

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/goravel/framework/facades"
)

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	ID     string
	UserID string
	Send   chan []byte
	Hub    *WebSocketHub
	mu     sync.Mutex
}

// WebSocketHub manages all WebSocket connections
type WebSocketHub struct {
	connections map[string]*WebSocketConnection // connection ID -> connection
	users       map[string][]string             // user ID -> connection IDs
	register    chan *WebSocketConnection
	unregister  chan *WebSocketConnection
	mu          sync.RWMutex
}

var (
	hubInstance *WebSocketHub
	hubOnce     sync.Once
)

// GetWebSocketHub returns the singleton WebSocket hub instance
func GetWebSocketHub() *WebSocketHub {
	hubOnce.Do(func() {
		hubInstance = &WebSocketHub{
			connections: make(map[string]*WebSocketConnection),
			users:       make(map[string][]string),
			register:    make(chan *WebSocketConnection),
			unregister:  make(chan *WebSocketConnection),
		}
		go hubInstance.run()
	})
	return hubInstance
}

// run starts the hub's event loop
func (h *WebSocketHub) run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.connections[conn.ID] = conn
			h.users[conn.UserID] = append(h.users[conn.UserID], conn.ID)
			h.mu.Unlock()

			facades.Log().Info("WebSocket connection registered", map[string]interface{}{
				"connection_id": conn.ID,
				"user_id":       conn.UserID,
			})

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.connections[conn.ID]; ok {
				delete(h.connections, conn.ID)

				// Remove from user's connections
				if userConns, ok := h.users[conn.UserID]; ok {
					for i, connID := range userConns {
						if connID == conn.ID {
							h.users[conn.UserID] = append(userConns[:i], userConns[i+1:]...)
							break
						}
					}

					// Remove user if no more connections
					if len(h.users[conn.UserID]) == 0 {
						delete(h.users, conn.UserID)
					}
				}

				close(conn.Send)
			}
			h.mu.Unlock()

			facades.Log().Info("WebSocket connection unregistered", map[string]interface{}{
				"connection_id": conn.ID,
				"user_id":       conn.UserID,
			})
		}
	}
}

// RegisterConnection registers a new WebSocket connection
func (h *WebSocketHub) RegisterConnection(conn *WebSocketConnection) {
	h.register <- conn
}

// UnregisterConnection unregisters a WebSocket connection
func (h *WebSocketHub) UnregisterConnection(conn *WebSocketConnection) {
	h.unregister <- conn
}

// SendToUser sends a message to all connections of a specific user
func (h *WebSocketHub) SendToUser(userID string, message interface{}) error {
	h.mu.RLock()
	userConns, exists := h.users[userID]
	h.mu.RUnlock()

	if !exists {
		return fmt.Errorf("user %s has no active connections", userID)
	}

	// Marshal the message
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Send to all user's connections
	var errors []error
	for _, connID := range userConns {
		h.mu.RLock()
		conn, exists := h.connections[connID]
		h.mu.RUnlock()

		if exists {
			select {
			case conn.Send <- messageBytes:
				// Message sent successfully
			default:
				// Connection buffer is full, consider it disconnected
				errors = append(errors, fmt.Errorf("connection %s buffer full", connID))
				h.UnregisterConnection(conn)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("some connections failed: %v", errors)
	}

	return nil
}

// SendToAll sends a message to all connected users
func (h *WebSocketHub) SendToAll(message interface{}) error {
	// Marshal the message
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	h.mu.RLock()
	connections := make([]*WebSocketConnection, 0, len(h.connections))
	for _, conn := range h.connections {
		connections = append(connections, conn)
	}
	h.mu.RUnlock()

	// Send to all connections
	var errors []error
	for _, conn := range connections {
		select {
		case conn.Send <- messageBytes:
			// Message sent successfully
		default:
			// Connection buffer is full, consider it disconnected
			errors = append(errors, fmt.Errorf("connection %s buffer full", conn.ID))
			h.UnregisterConnection(conn)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("some connections failed: %v", errors)
	}

	return nil
}

// GetUserConnections returns the number of connections for a user
func (h *WebSocketHub) GetUserConnections(userID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if userConns, exists := h.users[userID]; exists {
		return len(userConns)
	}
	return 0
}

// GetTotalConnections returns the total number of connections
func (h *WebSocketHub) GetTotalConnections() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.connections)
}

// GetConnectedUsers returns the number of unique users with connections
func (h *WebSocketHub) GetConnectedUsers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.users)
}

// IsUserConnected checks if a user has any active connections
func (h *WebSocketHub) IsUserConnected(userID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if userConns, exists := h.users[userID]; exists {
		return len(userConns) > 0
	}
	return false
}

// CloseConnection closes a specific connection
func (h *WebSocketHub) CloseConnection(connID string) {
	h.mu.RLock()
	conn, exists := h.connections[connID]
	h.mu.RUnlock()

	if exists {
		h.UnregisterConnection(conn)
	}
}

// CloseUserConnections closes all connections for a specific user
func (h *WebSocketHub) CloseUserConnections(userID string) {
	h.mu.RLock()
	userConns, exists := h.users[userID]
	connections := make([]*WebSocketConnection, 0, len(userConns))
	if exists {
		for _, connID := range userConns {
			if conn, ok := h.connections[connID]; ok {
				connections = append(connections, conn)
			}
		}
	}
	h.mu.RUnlock()

	// Close all user's connections
	for _, conn := range connections {
		h.UnregisterConnection(conn)
	}
}
