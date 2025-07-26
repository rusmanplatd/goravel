package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
	"github.com/gorilla/websocket"
)

// WebSocketConnection represents a WebSocket connection with enhanced features
type WebSocketConnection struct {
	ID               string
	UserID           string
	Send             chan []byte
	Hub              *WebSocketHub
	mu               sync.RWMutex
	conn             *websocket.Conn
	ctx              context.Context
	cancel           context.CancelFunc
	lastPing         time.Time
	lastPong         time.Time
	isAlive          bool
	metadata         map[string]interface{}
	createdAt        time.Time
	lastActive       time.Time
	messagesSent     int64
	messagesReceived int64
	subscriptions    map[string]bool
	rateLimiter      *connectionRateLimiter
}

// connectionRateLimiter provides per-connection rate limiting
type connectionRateLimiter struct {
	tokens     int
	lastRefill time.Time
	limit      int
	burst      int
	mu         sync.Mutex
}

// WebSocketHub manages all WebSocket connections with enhanced features
type WebSocketHub struct {
	connections    map[string]*WebSocketConnection // connection ID -> connection
	users          map[string][]string             // user ID -> connection IDs
	rooms          map[string][]string             // room ID -> connection IDs
	register       chan *WebSocketConnection
	unregister     chan *WebSocketConnection
	broadcast      chan *BroadcastMessage
	shutdown       chan struct{}
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	isShuttingDown bool
	stats          *HubStats
	config         *HubConfig
}

// BroadcastMessage represents a message to be broadcasted
type BroadcastMessage struct {
	Type      string
	Target    string // "all", "user:userID", "room:roomID"
	Message   interface{}
	ExcludeID string // connection ID to exclude
}

// HubStats tracks WebSocket hub statistics
type HubStats struct {
	TotalConnections     int64
	ActiveConnections    int64
	TotalMessages        int64
	MessagesPerSecond    float64
	ConnectionsCreated   int64
	ConnectionsDestroyed int64
	ErrorCount           int64
	LastStatsUpdate      time.Time
	mu                   sync.RWMutex
}

// HubConfig contains configuration for the WebSocket hub
type HubConfig struct {
	MaxConnections        int
	MaxConnectionsPerUser int
	MaxConnectionsPerIP   int
	HeartbeatInterval     time.Duration
	ConnectionTimeout     time.Duration
	MessageBufferSize     int
	EnableMetrics         bool
	CleanupInterval       time.Duration
	GracefulShutdownTime  time.Duration
}

var (
	hubInstance *WebSocketHub
	hubOnce     sync.Once
)

// GetWebSocketHub returns the singleton WebSocket hub instance
func GetWebSocketHub() *WebSocketHub {
	hubOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		hubInstance = &WebSocketHub{
			connections: make(map[string]*WebSocketConnection),
			users:       make(map[string][]string),
			rooms:       make(map[string][]string),
			register:    make(chan *WebSocketConnection, 100),
			unregister:  make(chan *WebSocketConnection, 100),
			broadcast:   make(chan *BroadcastMessage, 1000),
			shutdown:    make(chan struct{}),
			ctx:         ctx,
			cancel:      cancel,
			stats:       &HubStats{LastStatsUpdate: time.Now()},
			config:      loadHubConfig(),
		}

		go hubInstance.run()
		go hubInstance.heartbeatMonitor()
		go hubInstance.statsCollector()
		go hubInstance.cleanup()
	})
	return hubInstance
}

// loadHubConfig loads configuration from facades.Config
func loadHubConfig() *HubConfig {
	return &HubConfig{
		MaxConnections:        facades.Config().GetInt("websocket.connection.max_total", 10000),
		MaxConnectionsPerUser: facades.Config().GetInt("websocket.connection.max_connections_per_user", 5),
		MaxConnectionsPerIP:   facades.Config().GetInt("websocket.security.max_connections_per_ip", 10),
		HeartbeatInterval:     time.Duration(facades.Config().GetInt("websocket.connection.ping_interval", 54)) * time.Second,
		ConnectionTimeout:     time.Duration(facades.Config().GetInt("websocket.connection.read_timeout", 60)) * time.Second,
		MessageBufferSize:     facades.Config().GetInt("websocket.connection.send_buffer_size", 256),
		EnableMetrics:         facades.Config().GetBool("websocket.monitoring.metrics", true),
		CleanupInterval:       time.Duration(facades.Config().GetInt("websocket.cleanup.interval", 300)) * time.Second,
		GracefulShutdownTime:  30 * time.Second,
	}
}

// run starts the hub's main event loop
func (h *WebSocketHub) run() {
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("WebSocket hub panic recovered", map[string]interface{}{
				"panic": r,
			})
			// Restart the hub after a brief delay
			time.Sleep(time.Second)
			go h.run()
		}
	}()

	for {
		select {
		case conn := <-h.register:
			h.handleRegister(conn)

		case conn := <-h.unregister:
			h.handleUnregister(conn)

		case message := <-h.broadcast:
			h.handleBroadcast(message)

		case <-h.shutdown:
			facades.Log().Info("WebSocket hub shutting down gracefully")
			h.gracefulShutdown()
			return

		case <-h.ctx.Done():
			facades.Log().Info("WebSocket hub context cancelled")
			return
		}
	}
}

// handleRegister handles new connection registration
func (h *WebSocketHub) handleRegister(conn *WebSocketConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check global connection limit
	if len(h.connections) >= h.config.MaxConnections {
		facades.Log().Warning("Maximum connections reached, rejecting new connection", map[string]interface{}{
			"max_connections": h.config.MaxConnections,
			"current_count":   len(h.connections),
			"user_id":         conn.UserID,
		})
		conn.Close()
		return
	}

	// Check user connection limit
	if userConns, exists := h.users[conn.UserID]; exists {
		if len(userConns) >= h.config.MaxConnectionsPerUser {
			facades.Log().Warning("User connection limit reached", map[string]interface{}{
				"user_id":            conn.UserID,
				"max_per_user":       h.config.MaxConnectionsPerUser,
				"current_user_count": len(userConns),
			})
			conn.Close()
			return
		}
	}

	// Register the connection
	h.connections[conn.ID] = conn
	h.users[conn.UserID] = append(h.users[conn.UserID], conn.ID)

	// Update statistics
	h.stats.mu.Lock()
	h.stats.ActiveConnections++
	h.stats.ConnectionsCreated++
	h.stats.mu.Unlock()

	facades.Log().Info("WebSocket connection registered", map[string]interface{}{
		"connection_id":     conn.ID,
		"user_id":           conn.UserID,
		"total_connections": len(h.connections),
	})
}

// handleUnregister handles connection unregistration
func (h *WebSocketHub) handleUnregister(conn *WebSocketConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.connections[conn.ID]; exists {
		// Remove from connections
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

		// Remove from all rooms
		for roomID, roomConns := range h.rooms {
			for i, connID := range roomConns {
				if connID == conn.ID {
					h.rooms[roomID] = append(roomConns[:i], roomConns[i+1:]...)
					if len(h.rooms[roomID]) == 0 {
						delete(h.rooms, roomID)
					}
					break
				}
			}
		}

		// Close the connection and cleanup
		conn.Close()

		// Update statistics
		h.stats.mu.Lock()
		h.stats.ActiveConnections--
		h.stats.ConnectionsDestroyed++
		h.stats.mu.Unlock()

		facades.Log().Info("WebSocket connection unregistered", map[string]interface{}{
			"connection_id":         conn.ID,
			"user_id":               conn.UserID,
			"remaining_connections": len(h.connections),
			"connection_duration":   time.Since(conn.createdAt).String(),
			"messages_sent":         conn.messagesSent,
			"messages_received":     conn.messagesReceived,
		})
	}
}

// handleBroadcast handles message broadcasting
func (h *WebSocketHub) handleBroadcast(message *BroadcastMessage) {
	messageBytes, err := json.Marshal(message.Message)
	if err != nil {
		facades.Log().Error("Failed to marshal broadcast message", map[string]interface{}{
			"error": err.Error(),
			"type":  message.Type,
		})
		h.stats.mu.Lock()
		h.stats.ErrorCount++
		h.stats.mu.Unlock()
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	var targetConnections []*WebSocketConnection

	switch {
	case message.Target == "all":
		for _, conn := range h.connections {
			if conn.ID != message.ExcludeID {
				targetConnections = append(targetConnections, conn)
			}
		}

	case len(message.Target) > 5 && message.Target[:5] == "user:":
		userID := message.Target[5:]
		if userConns, exists := h.users[userID]; exists {
			for _, connID := range userConns {
				if conn, ok := h.connections[connID]; ok && conn.ID != message.ExcludeID {
					targetConnections = append(targetConnections, conn)
				}
			}
		}

	case len(message.Target) > 5 && message.Target[:5] == "room:":
		roomID := message.Target[5:]
		if roomConns, exists := h.rooms[roomID]; exists {
			for _, connID := range roomConns {
				if conn, ok := h.connections[connID]; ok && conn.ID != message.ExcludeID {
					targetConnections = append(targetConnections, conn)
				}
			}
		}
	}

	// Send to target connections
	successCount := 0
	for _, conn := range targetConnections {
		if conn.SendMessage(messageBytes) {
			successCount++
		}
	}

	// Update statistics
	h.stats.mu.Lock()
	h.stats.TotalMessages += int64(successCount)
	h.stats.mu.Unlock()

	facades.Log().Debug("Broadcast message sent", map[string]interface{}{
		"type":          message.Type,
		"target":        message.Target,
		"success_count": successCount,
		"total_targets": len(targetConnections),
	})
}

// heartbeatMonitor monitors connection health
func (h *WebSocketHub) heartbeatMonitor() {
	ticker := time.NewTicker(h.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.checkConnectionHealth()
		case <-h.ctx.Done():
			return
		}
	}
}

// checkConnectionHealth checks and maintains connection health
func (h *WebSocketHub) checkConnectionHealth() {
	h.mu.RLock()
	connections := make([]*WebSocketConnection, 0, len(h.connections))
	for _, conn := range h.connections {
		connections = append(connections, conn)
	}
	h.mu.RUnlock()

	now := time.Now()
	staleConnections := 0

	for _, conn := range connections {
		conn.mu.RLock()
		lastPong := conn.lastPong
		isAlive := conn.isAlive
		conn.mu.RUnlock()

		// Check if connection is stale
		if now.Sub(lastPong) > h.config.ConnectionTimeout {
			facades.Log().Warning("Stale WebSocket connection detected", map[string]interface{}{
				"connection_id": conn.ID,
				"user_id":       conn.UserID,
				"last_pong":     lastPong,
				"timeout":       h.config.ConnectionTimeout,
			})
			h.UnregisterConnection(conn)
			staleConnections++
			continue
		}

		// Send ping if connection is alive
		if isAlive {
			conn.SendPing()
		}
	}

	if staleConnections > 0 {
		facades.Log().Info("Cleaned up stale connections", map[string]interface{}{
			"stale_count":        staleConnections,
			"active_connections": len(h.connections),
		})
	}
}

// statsCollector collects and reports statistics
func (h *WebSocketHub) statsCollector() {
	if !h.config.EnableMetrics {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.collectStats()
		case <-h.ctx.Done():
			return
		}
	}
}

// collectStats collects current statistics
func (h *WebSocketHub) collectStats() {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(h.stats.LastStatsUpdate).Seconds()

	if elapsed > 0 {
		h.stats.MessagesPerSecond = float64(h.stats.TotalMessages) / elapsed
	}

	h.stats.LastStatsUpdate = now

	facades.Log().Info("WebSocket hub statistics", map[string]interface{}{
		"active_connections":    h.stats.ActiveConnections,
		"total_connections":     h.stats.TotalConnections,
		"messages_per_second":   h.stats.MessagesPerSecond,
		"connections_created":   h.stats.ConnectionsCreated,
		"connections_destroyed": h.stats.ConnectionsDestroyed,
		"error_count":           h.stats.ErrorCount,
	})
}

// cleanup performs periodic cleanup tasks
func (h *WebSocketHub) cleanup() {
	ticker := time.NewTicker(h.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.performCleanup()
		case <-h.ctx.Done():
			return
		}
	}
}

// performCleanup performs cleanup tasks
func (h *WebSocketHub) performCleanup() {
	facades.Log().Debug("Performing WebSocket hub cleanup")

	// Cleanup empty rooms
	h.mu.Lock()
	emptyRooms := 0
	for roomID, connections := range h.rooms {
		if len(connections) == 0 {
			delete(h.rooms, roomID)
			emptyRooms++
		}
	}
	h.mu.Unlock()

	if emptyRooms > 0 {
		facades.Log().Debug("Cleaned up empty rooms", map[string]interface{}{
			"empty_rooms": emptyRooms,
		})
	}
}

// gracefulShutdown performs graceful shutdown
func (h *WebSocketHub) gracefulShutdown() {
	h.mu.Lock()
	h.isShuttingDown = true
	connections := make([]*WebSocketConnection, 0, len(h.connections))
	for _, conn := range h.connections {
		connections = append(connections, conn)
	}
	h.mu.Unlock()

	facades.Log().Info("Starting graceful shutdown of WebSocket connections", map[string]interface{}{
		"connection_count": len(connections),
	})

	// Send close message to all connections
	closeMessage := map[string]interface{}{
		"type":      "server_shutdown",
		"message":   "Server is shutting down",
		"timestamp": time.Now().Unix(),
	}

	for _, conn := range connections {
		conn.SendCloseMessage(closeMessage)
	}

	// Wait for connections to close gracefully
	timeout := time.NewTimer(h.config.GracefulShutdownTime)
	defer timeout.Stop()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout.C:
			facades.Log().Warning("Graceful shutdown timeout, forcing connection closures")
			h.forceCloseAllConnections()
			return
		case <-ticker.C:
			h.mu.RLock()
			remaining := len(h.connections)
			h.mu.RUnlock()

			if remaining == 0 {
				facades.Log().Info("All WebSocket connections closed gracefully")
				return
			}

			facades.Log().Info("Waiting for connections to close", map[string]interface{}{
				"remaining": remaining,
			})
		}
	}
}

// forceCloseAllConnections forcefully closes all connections
func (h *WebSocketHub) forceCloseAllConnections() {
	h.mu.RLock()
	connections := make([]*WebSocketConnection, 0, len(h.connections))
	for _, conn := range h.connections {
		connections = append(connections, conn)
	}
	h.mu.RUnlock()

	for _, conn := range connections {
		conn.ForceClose()
	}
}

// Shutdown initiates graceful shutdown of the hub
func (h *WebSocketHub) Shutdown() {
	select {
	case h.shutdown <- struct{}{}:
	default:
		// Channel is full or hub is already shutting down
	}
}

// RegisterConnection registers a new WebSocket connection
func (h *WebSocketHub) RegisterConnection(conn *WebSocketConnection) {
	if h.isShuttingDown {
		facades.Log().Warning("Rejecting new connection during shutdown", map[string]interface{}{
			"connection_id": conn.ID,
			"user_id":       conn.UserID,
		})
		conn.Close()
		return
	}

	select {
	case h.register <- conn:
	case <-time.After(5 * time.Second):
		facades.Log().Error("Failed to register connection: timeout", map[string]interface{}{
			"connection_id": conn.ID,
			"user_id":       conn.UserID,
		})
		conn.Close()
	}
}

// UnregisterConnection unregisters a WebSocket connection
func (h *WebSocketHub) UnregisterConnection(conn *WebSocketConnection) {
	select {
	case h.unregister <- conn:
	case <-time.After(5 * time.Second):
		facades.Log().Error("Failed to unregister connection: timeout", map[string]interface{}{
			"connection_id": conn.ID,
			"user_id":       conn.UserID,
		})
	}
}

// SendToUser sends a message to all connections of a specific user
func (h *WebSocketHub) SendToUser(userID string, message interface{}) error {
	if h.isShuttingDown {
		return errors.New("hub is shutting down")
	}

	broadcastMsg := &BroadcastMessage{
		Type:    "user_message",
		Target:  fmt.Sprintf("user:%s", userID),
		Message: message,
	}

	select {
	case h.broadcast <- broadcastMsg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("broadcast timeout")
	}
}

// SendToAll sends a message to all connected users
func (h *WebSocketHub) SendToAll(message interface{}) error {
	if h.isShuttingDown {
		return errors.New("hub is shutting down")
	}

	broadcastMsg := &BroadcastMessage{
		Type:    "broadcast",
		Target:  "all",
		Message: message,
	}

	select {
	case h.broadcast <- broadcastMsg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("broadcast timeout")
	}
}

// SendToRoom sends a message to all connections in a specific room
func (h *WebSocketHub) SendToRoom(roomID string, message interface{}) error {
	if h.isShuttingDown {
		return errors.New("hub is shutting down")
	}

	broadcastMsg := &BroadcastMessage{
		Type:    "room_message",
		Target:  fmt.Sprintf("room:%s", roomID),
		Message: message,
	}

	select {
	case h.broadcast <- broadcastMsg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("broadcast timeout")
	}
}

// SendToRoomExcept sends a message to all connections in a room except the specified user
func (h *WebSocketHub) SendToRoomExcept(roomID, excludeUserID string, message interface{}) error {
	if h.isShuttingDown {
		return errors.New("hub is shutting down")
	}

	// Find connection ID to exclude
	var excludeConnID string
	h.mu.RLock()
	if userConns, exists := h.users[excludeUserID]; exists {
		for _, connID := range userConns {
			if conn, ok := h.connections[connID]; ok {
				// Check if this connection is in the room
				if roomConns, roomExists := h.rooms[roomID]; roomExists {
					for _, roomConnID := range roomConns {
						if roomConnID == conn.ID {
							excludeConnID = conn.ID
							break
						}
					}
				}
				if excludeConnID != "" {
					break
				}
			}
		}
	}
	h.mu.RUnlock()

	broadcastMsg := &BroadcastMessage{
		Type:      "room_message",
		Target:    fmt.Sprintf("room:%s", roomID),
		Message:   message,
		ExcludeID: excludeConnID,
	}

	select {
	case h.broadcast <- broadcastMsg:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("broadcast timeout")
	}
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

// JoinRoom adds a connection to a specific room
func (h *WebSocketHub) JoinRoom(roomID, connectionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Add connection to room
	h.rooms[roomID] = append(h.rooms[roomID], connectionID)

	facades.Log().Info("Connection joined room", map[string]interface{}{
		"connection_id": connectionID,
		"room_id":       roomID,
		"room_size":     len(h.rooms[roomID]),
	})
}

// LeaveRoom removes a connection from a specific room
func (h *WebSocketHub) LeaveRoom(roomID, connectionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if roomConns, exists := h.rooms[roomID]; exists {
		for i, connID := range roomConns {
			if connID == connectionID {
				h.rooms[roomID] = append(roomConns[:i], roomConns[i+1:]...)
				break
			}
		}

		// Remove room if no more connections
		if len(h.rooms[roomID]) == 0 {
			delete(h.rooms, roomID)
		}
	}

	facades.Log().Info("Connection left room", map[string]interface{}{
		"connection_id": connectionID,
		"room_id":       roomID,
		"room_size":     len(h.rooms[roomID]),
	})
}

// GetRoomConnections returns all connection IDs in a specific room
func (h *WebSocketHub) GetRoomConnections(roomID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if roomConns, exists := h.rooms[roomID]; exists {
		// Return a copy to avoid race conditions
		connections := make([]string, len(roomConns))
		copy(connections, roomConns)
		return connections
	}

	return []string{}
}

// CloseRoomConnections closes all connections in a specific room
func (h *WebSocketHub) CloseRoomConnections(roomID string) {
	h.mu.RLock()
	roomConns, exists := h.rooms[roomID]
	connections := make([]*WebSocketConnection, 0, len(roomConns))
	if exists {
		for _, connID := range roomConns {
			if conn, ok := h.connections[connID]; ok {
				connections = append(connections, conn)
			}
		}
	}
	h.mu.RUnlock()

	// Close all room connections
	for _, conn := range connections {
		h.UnregisterConnection(conn)
	}

	facades.Log().Info("All connections closed for room", map[string]interface{}{
		"room_id":            roomID,
		"connections_closed": len(connections),
	})
}

// GetRoomConnectionCount returns the number of connections in a room
func (h *WebSocketHub) GetRoomConnectionCount(roomID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if roomConns, exists := h.rooms[roomID]; exists {
		return len(roomConns)
	}
	return 0
}

// GetStats returns current hub statistics
func (h *WebSocketHub) GetStats() *HubStats {
	h.stats.mu.RLock()
	defer h.stats.mu.RUnlock()

	// Return a copy of stats
	return &HubStats{
		TotalConnections:     h.stats.TotalConnections,
		ActiveConnections:    h.stats.ActiveConnections,
		TotalMessages:        h.stats.TotalMessages,
		MessagesPerSecond:    h.stats.MessagesPerSecond,
		ConnectionsCreated:   h.stats.ConnectionsCreated,
		ConnectionsDestroyed: h.stats.ConnectionsDestroyed,
		ErrorCount:           h.stats.ErrorCount,
		LastStatsUpdate:      h.stats.LastStatsUpdate,
	}
}

// NewWebSocketConnection creates a new WebSocket connection
func NewWebSocketConnection(id, userID string, conn *websocket.Conn, hub *WebSocketHub) *WebSocketConnection {
	ctx, cancel := context.WithCancel(context.Background())

	wsConn := &WebSocketConnection{
		ID:            id,
		UserID:        userID,
		Send:          make(chan []byte, hub.config.MessageBufferSize),
		Hub:           hub,
		conn:          conn,
		ctx:           ctx,
		cancel:        cancel,
		lastPing:      time.Now(),
		lastPong:      time.Now(),
		isAlive:       true,
		metadata:      make(map[string]interface{}),
		createdAt:     time.Now(),
		lastActive:    time.Now(),
		subscriptions: make(map[string]bool),
		rateLimiter:   newConnectionRateLimiter(),
	}

	return wsConn
}

// Connection methods

// SendMessage sends a message to the connection
func (c *WebSocketConnection) SendMessage(message []byte) bool {
	if !c.isAlive {
		return false
	}

	select {
	case c.Send <- message:
		c.mu.Lock()
		c.messagesSent++
		c.lastActive = time.Now()
		c.mu.Unlock()
		return true
	default:
		// Channel is full, connection is likely stale
		facades.Log().Warning("Connection send buffer full", map[string]interface{}{
			"connection_id": c.ID,
			"user_id":       c.UserID,
		})
		c.Hub.UnregisterConnection(c)
		return false
	}
}

// SendPing sends a ping message to the connection
func (c *WebSocketConnection) SendPing() {
	if !c.isAlive || c.conn == nil {
		return
	}

	c.mu.Lock()
	c.lastPing = time.Now()
	c.mu.Unlock()

	if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		facades.Log().Warning("Failed to send ping", map[string]interface{}{
			"connection_id": c.ID,
			"user_id":       c.UserID,
			"error":         err.Error(),
		})
		c.markDead()
	}
}

// SendCloseMessage sends a close message to the connection
func (c *WebSocketConnection) SendCloseMessage(message interface{}) {
	if messageBytes, err := json.Marshal(message); err == nil {
		select {
		case c.Send <- messageBytes:
		case <-time.After(time.Second):
			// Timeout sending close message
		}
	}
}

// Close closes the connection gracefully
func (c *WebSocketConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isAlive {
		return
	}

	c.isAlive = false
	c.cancel()

	if c.conn != nil {
		c.conn.Close()
	}

	close(c.Send)
}

// ForceClose forcefully closes the connection
func (c *WebSocketConnection) ForceClose() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.isAlive = false
	c.cancel()

	if c.conn != nil {
		c.conn.Close()
	}

	// Don't close Send channel here to avoid panic in sender goroutines
}

// markDead marks the connection as dead
func (c *WebSocketConnection) markDead() {
	c.mu.Lock()
	c.isAlive = false
	c.mu.Unlock()
}

// UpdateLastPong updates the last pong timestamp
func (c *WebSocketConnection) UpdateLastPong() {
	c.mu.Lock()
	c.lastPong = time.Now()
	c.mu.Unlock()
}

// GetMetadata returns connection metadata
func (c *WebSocketConnection) GetMetadata(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists := c.metadata[key]
	return value, exists
}

// SetMetadata sets connection metadata
func (c *WebSocketConnection) SetMetadata(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metadata[key] = value
}

// Rate limiter methods

func newConnectionRateLimiter() *connectionRateLimiter {
	return &connectionRateLimiter{
		tokens:     10, // Initial burst
		lastRefill: time.Now(),
		limit:      60, // Messages per minute
		burst:      10,
	}
}

func (rl *connectionRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed >= time.Minute {
		rl.tokens = rl.burst
		rl.lastRefill = now
	} else {
		tokensToAdd := int(elapsed.Seconds()) * rl.limit / 60
		if tokensToAdd > 0 {
			rl.tokens = min(rl.burst, rl.tokens+tokensToAdd)
			rl.lastRefill = now
		}
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}
