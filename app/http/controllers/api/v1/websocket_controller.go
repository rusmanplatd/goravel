package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"goravel/app/services"

	goravelhttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/gorilla/websocket"
)

// WebSocketController handles WebSocket connections with enhanced features
type WebSocketController struct {
	hub           *services.WebSocketHub
	circuitBreaker *CircuitBreaker
	messageValidator *MessageValidator
	metrics       *ControllerMetrics
}

// CircuitBreaker provides circuit breaker functionality
type CircuitBreaker struct {
	failures    int64
	lastFailure time.Time
	state       int32 // 0: closed, 1: open, 2: half-open
	threshold   int64
	timeout     time.Duration
	mu          sync.RWMutex
}

// MessageValidator validates WebSocket messages
type MessageValidator struct {
	maxMessageSize int
	allowedTypes   map[string]bool
	rateLimiters   map[string]*MessageRateLimiter
	mu             sync.RWMutex
}

// MessageRateLimiter provides message-level rate limiting
type MessageRateLimiter struct {
	count      int64
	window     time.Time
	limit      int64
	windowSize time.Duration
	mu         sync.Mutex
}

// ControllerMetrics tracks controller performance
type ControllerMetrics struct {
	totalConnections    int64
	activeConnections   int64
	messagesProcessed   int64
	errorsCount         int64
	averageResponseTime int64
	lastUpdate          time.Time
	mu                  sync.RWMutex
}

// WebSocketMessage represents a validated WebSocket message
type WebSocketMessage struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp int64                  `json:"timestamp"`
	ID        string                 `json:"id,omitempty"`
}

// ErrorResponse represents a WebSocket error response
type ErrorResponse struct {
	Type      string `json:"type"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
	RequestID string `json:"request_id,omitempty"`
}

const (
	// Circuit breaker states
	CircuitClosed   = 0
	CircuitOpen     = 1
	CircuitHalfOpen = 2

	// Error codes
	ErrorInvalidMessage     = "INVALID_MESSAGE"
	ErrorRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
	ErrorServiceUnavailable = "SERVICE_UNAVAILABLE"
	ErrorInternalError      = "INTERNAL_ERROR"
	ErrorUnauthorized       = "UNAUTHORIZED"
	ErrorMessageTooLarge    = "MESSAGE_TOO_LARGE"
	ErrorInvalidMessageType = "INVALID_MESSAGE_TYPE"
)

func NewWebSocketController() *WebSocketController {
	return &WebSocketController{
		hub:              services.GetWebSocketHub(),
		circuitBreaker:   NewCircuitBreaker(10, 30*time.Second),
		messageValidator: NewMessageValidator(),
		metrics:          NewControllerMetrics(),
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int64, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
	}
}

// NewMessageValidator creates a new message validator
func NewMessageValidator() *MessageValidator {
	allowedTypes := make(map[string]bool)
	configTypes := facades.Config().Get("websocket.message_types.allowed", []string{})
	for _, msgType := range configTypes.([]string) {
		allowedTypes[msgType] = true
	}

	return &MessageValidator{
		maxMessageSize: facades.Config().GetInt("websocket.connection.max_message_size", 512),
		allowedTypes:   allowedTypes,
		rateLimiters:   make(map[string]*MessageRateLimiter),
	}
}

// NewControllerMetrics creates a new metrics tracker
func NewControllerMetrics() *ControllerMetrics {
	return &ControllerMetrics{
		lastUpdate: time.Now(),
	}
}

// Connect establishes a WebSocket connection with enhanced error handling
func (c *WebSocketController) Connect(ctx goravelhttp.Context) goravelhttp.Response {
	startTime := time.Now()
	defer func() {
		c.metrics.recordResponseTime(time.Since(startTime))
	}()

	// Check circuit breaker
	if !c.circuitBreaker.Allow() {
		facades.Log().Warning("WebSocket connection rejected by circuit breaker", map[string]interface{}{
			"ip": ctx.Request().Ip(),
		})
		return c.errorResponse(ctx, http.StatusServiceUnavailable, ErrorServiceUnavailable, "Service temporarily unavailable")
	}

	// Get user ID from authentication
	userID := c.getUserIDFromContext(ctx)
	if userID == "" {
		c.circuitBreaker.RecordFailure()
		return c.errorResponse(ctx, http.StatusUnauthorized, ErrorUnauthorized, "Authentication required")
	}

	// Upgrade the HTTP connection to WebSocket with enhanced configuration
	upgrader := websocket.Upgrader{
		ReadBufferSize:  facades.Config().GetInt("websocket.connection.read_buffer_size", 1024),
		WriteBufferSize: facades.Config().GetInt("websocket.connection.write_buffer_size", 1024),
		CheckOrigin: func(r *http.Request) bool {
			// Origin validation is handled by middleware
			return true
		},
		EnableCompression: facades.Config().GetBool("websocket.connection.enable_compression", true),
		HandshakeTimeout:  time.Duration(facades.Config().GetInt("websocket.connection.handshake_timeout", 10)) * time.Second,
	}

	// Get the underlying HTTP response writer and request
	responseWriter := ctx.Response().Writer()
	request := ctx.Request().Origin()

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		c.circuitBreaker.RecordFailure()
		c.metrics.recordError()
		facades.Log().Error("Failed to upgrade connection to WebSocket", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID,
			"ip":      ctx.Request().Ip(),
		})
		return c.errorResponse(ctx, http.StatusInternalServerError, ErrorInternalError, "Failed to establish WebSocket connection")
	}

	// Configure connection limits
	conn.SetReadLimit(int64(facades.Config().GetInt("websocket.connection.max_message_size", 512)))
	conn.SetReadDeadline(time.Now().Add(time.Duration(facades.Config().GetInt("websocket.connection.read_timeout", 60)) * time.Second))
	conn.SetWriteDeadline(time.Now().Add(time.Duration(facades.Config().GetInt("websocket.connection.write_timeout", 10)) * time.Second))

	// Create WebSocket connection
	wsConn := services.NewWebSocketConnection(
		fmt.Sprintf("conn_%s_%d", userID, time.Now().UnixNano()),
		userID,
		conn,
		c.hub,
	)

	// Set connection metadata
	wsConn.SetMetadata("ip", ctx.Request().Ip())
	wsConn.SetMetadata("user_agent", ctx.Request().Header("User-Agent", ""))
	wsConn.SetMetadata("connected_at", time.Now())

	// Register the connection
	c.hub.RegisterConnection(wsConn)
	c.metrics.recordConnection()
	c.circuitBreaker.RecordSuccess()

	// Start goroutines to handle reading and writing with enhanced error handling
	go c.handleReadWithRecovery(wsConn, conn)
	go c.handleWriteWithRecovery(wsConn, conn)

	facades.Log().Info("WebSocket connection established successfully", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       userID,
		"ip":            ctx.Request().Ip(),
		"user_agent":    ctx.Request().Header("User-Agent", ""),
	})

	// Return success (the WebSocket connection is now established)
	return ctx.Response().Success().Json(map[string]interface{}{
		"message":       "WebSocket connection established",
		"connection_id": wsConn.ID,
		"user_id":       userID,
		"timestamp":     time.Now().Unix(),
	})
}

// handleReadWithRecovery handles incoming messages with panic recovery
func (c *WebSocketController) handleReadWithRecovery(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("WebSocket read handler panic recovered", map[string]interface{}{
				"panic":         r,
				"connection_id": wsConn.ID,
				"user_id":       wsConn.UserID,
			})
			c.metrics.recordError()
		}
		c.cleanupConnection(wsConn)
	}()

	c.handleRead(wsConn, conn)
}

// handleWriteWithRecovery handles outgoing messages with panic recovery
func (c *WebSocketController) handleWriteWithRecovery(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("WebSocket write handler panic recovered", map[string]interface{}{
				"panic":         r,
				"connection_id": wsConn.ID,
				"user_id":       wsConn.UserID,
			})
			c.metrics.recordError()
		}
	}()

	c.handleWrite(wsConn, conn)
}

// handleRead handles incoming messages from the WebSocket client with validation
func (c *WebSocketController) handleRead(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	defer func() {
		c.hub.UnregisterConnection(wsConn)
		conn.Close()
	}()

	// Set up connection timeouts and limits
	conn.SetReadLimit(int64(c.messageValidator.maxMessageSize))
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		wsConn.UpdateLastPong()
		return nil
	})

	for {
		// Check if connection is still alive
		if connCtx, ok := wsConn.GetMetadata("context"); ok {
			if ctx, ok := connCtx.(context.Context); ok {
				select {
				case <-ctx.Done():
					facades.Log().Info("Connection context cancelled", map[string]interface{}{
						"connection_id": wsConn.ID,
						"user_id":       wsConn.UserID,
					})
					return
				default:
				}
			}
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
				c.metrics.recordError()
			}
			break
		}

		// Validate and handle the message
		if err := c.handleMessageWithValidation(wsConn, message); err != nil {
			c.sendErrorToConnection(wsConn, ErrorInvalidMessage, err.Error())
		}
	}
}

// handleWrite handles outgoing messages to the WebSocket client with enhanced error handling
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
				facades.Log().Error("Failed to get WebSocket writer", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
				c.metrics.recordError()
				return
			}
			
			if _, err := w.Write(message); err != nil {
				facades.Log().Error("Failed to write WebSocket message", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
				c.metrics.recordError()
				w.Close()
				return
			}

			// Add queued messages to the current websocket message
			n := len(wsConn.Send)
			for i := 0; i < n; i++ {
				select {
				case queuedMessage := <-wsConn.Send:
					w.Write([]byte{'\n'})
					w.Write(queuedMessage)
				default:
					break
				}
			}

			if err := w.Close(); err != nil {
				facades.Log().Error("Failed to close WebSocket writer", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
				c.metrics.recordError()
				return
			}

		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				facades.Log().Warning("Failed to send ping message", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
				return
			}
		}
	}
}

// handleMessageWithValidation validates and processes incoming WebSocket messages
func (c *WebSocketController) handleMessageWithValidation(wsConn *services.WebSocketConnection, message []byte) error {
	// Check message size
	if len(message) > c.messageValidator.maxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max: %d)", len(message), c.messageValidator.maxMessageSize)
	}

	// Parse and validate message structure
	var wsMsg WebSocketMessage
	if err := json.Unmarshal(message, &wsMsg); err != nil {
		return fmt.Errorf("invalid JSON format: %v", err)
	}

	// Validate message type
	if !c.messageValidator.isValidMessageType(wsMsg.Type) {
		return fmt.Errorf("invalid message type: %s", wsMsg.Type)
	}

	// Check rate limits
	if !c.messageValidator.checkRateLimit(wsConn.UserID, wsMsg.Type) {
		return fmt.Errorf("rate limit exceeded for message type: %s", wsMsg.Type)
	}

	// Set timestamp if not provided
	if wsMsg.Timestamp == 0 {
		wsMsg.Timestamp = time.Now().Unix()
	}

	// Process the message
	c.metrics.recordMessage()
	return c.processValidatedMessage(wsConn, &wsMsg)
}

// processValidatedMessage processes a validated WebSocket message
func (c *WebSocketController) processValidatedMessage(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	switch msg.Type {
	case "ping":
		return c.handlePing(wsConn, msg)
	case "subscribe":
		return c.handleSubscribe(wsConn, msg)
	case "unsubscribe":
		return c.handleUnsubscribe(wsConn, msg)
	case "heartbeat":
		return c.handleHeartbeat(wsConn, msg)
	default:
		facades.Log().Warning("Unknown message type", map[string]interface{}{
			"type":          msg.Type,
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
		})
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handlePing handles ping messages with enhanced response
func (c *WebSocketController) handlePing(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	response := &WebSocketMessage{
		Type:      "pong",
		Timestamp: time.Now().Unix(),
		ID:        msg.ID,
		Data: map[string]interface{}{
			"server_time": time.Now().Unix(),
			"latency":     time.Now().Unix() - msg.Timestamp,
		},
	}

	return c.sendMessageToConnection(wsConn, response)
}

// handleHeartbeat handles heartbeat messages
func (c *WebSocketController) handleHeartbeat(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	wsConn.UpdateLastPong()
	
	response := &WebSocketMessage{
		Type:      "heartbeat_ack",
		Timestamp: time.Now().Unix(),
		ID:        msg.ID,
		Data: map[string]interface{}{
			"status": "alive",
		},
	}

	return c.sendMessageToConnection(wsConn, response)
}

// handleSubscribe handles subscription to notification types with validation
func (c *WebSocketController) handleSubscribe(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	subscriptionTypes, ok := msg.Data["types"].([]interface{})
	if !ok {
		return errors.New("subscription types must be provided as an array")
	}

	// Validate and process subscription types
	var validTypes []string
	validSubscriptionTypes := map[string]bool{
		"chat_message":   true,
		"notification":   true,
		"task_update":    true,
		"calendar_event": true,
		"system_alert":   true,
		"user_status":    true,
	}

	for _, typeInterface := range subscriptionTypes {
		if subscriptionType, ok := typeInterface.(string); ok {
			if validSubscriptionTypes[subscriptionType] {
				validTypes = append(validTypes, subscriptionType)
			} else {
				facades.Log().Warning("Invalid subscription type", map[string]interface{}{
					"user_id": wsConn.UserID,
					"type":    subscriptionType,
				})
			}
		}
	}

	if len(validTypes) == 0 {
		return errors.New("no valid subscription types provided")
	}

	// Store subscriptions in cache for persistence across connections
	cacheKey := fmt.Sprintf("user_subscriptions:%s", wsConn.UserID)
	facades.Cache().Put(cacheKey, validTypes, 24*time.Hour)

	facades.Log().Info("User subscribed to notifications", map[string]interface{}{
		"connection_id":      wsConn.ID,
		"user_id":            wsConn.UserID,
		"subscription_types": validTypes,
	})

	// Send confirmation with subscribed types
	response := &WebSocketMessage{
		Type:      "subscribed",
		Timestamp: time.Now().Unix(),
		ID:        msg.ID,
		Data: map[string]interface{}{
			"subscription_types": validTypes,
			"status":            "success",
		},
	}

	return c.sendMessageToConnection(wsConn, response)
}

// handleUnsubscribe handles unsubscription from notification types with validation
func (c *WebSocketController) handleUnsubscribe(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	unsubscriptionTypes, ok := msg.Data["types"].([]interface{})
	if !ok {
		return errors.New("unsubscription types must be provided as an array")
	}

	// Get current subscriptions
	cacheKey := fmt.Sprintf("user_subscriptions:%s", wsConn.UserID)
	var currentSubscriptions []string
	err := facades.Cache().Get(cacheKey, &currentSubscriptions)
	if err != nil {
		currentSubscriptions = []string{}
	}

	// Process unsubscription types
	var typesToRemove []string
	for _, typeInterface := range unsubscriptionTypes {
		if unsubscriptionType, ok := typeInterface.(string); ok {
			typesToRemove = append(typesToRemove, unsubscriptionType)
		}
	}

	// Remove specified types from current subscriptions
	var remainingSubscriptions []string
	for _, currentType := range currentSubscriptions {
		shouldRemove := false
		for _, removeType := range typesToRemove {
			if currentType == removeType {
				shouldRemove = true
				break
			}
		}
		if !shouldRemove {
			remainingSubscriptions = append(remainingSubscriptions, currentType)
		}
	}

	// Update subscriptions in cache
	if len(remainingSubscriptions) > 0 {
		facades.Cache().Put(cacheKey, remainingSubscriptions, 24*time.Hour)
	} else {
		facades.Cache().Forget(cacheKey)
	}

	facades.Log().Info("User unsubscribed from notifications", map[string]interface{}{
		"connection_id":           wsConn.ID,
		"user_id":                 wsConn.UserID,
		"unsubscribed_types":      typesToRemove,
		"remaining_subscriptions": remainingSubscriptions,
	})

	// Send confirmation with remaining subscriptions
	response := &WebSocketMessage{
		Type:      "unsubscribed",
		Timestamp: time.Now().Unix(),
		ID:        msg.ID,
		Data: map[string]interface{}{
			"unsubscribed_types":      typesToRemove,
			"remaining_subscriptions": remainingSubscriptions,
			"status":                  "success",
		},
	}

	return c.sendMessageToConnection(wsConn, response)
}

// sendMessageToConnection sends a message to a specific connection
func (c *WebSocketController) sendMessageToConnection(wsConn *services.WebSocketConnection, msg *WebSocketMessage) error {
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	if wsConn.SendMessage(messageBytes) {
		return nil
	}
	return errors.New("failed to send message")
}

// sendErrorToConnection sends an error message to a connection
func (c *WebSocketController) sendErrorToConnection(wsConn *services.WebSocketConnection, code, message string) {
	errorMsg := &ErrorResponse{
		Type:      "error",
		Code:      code,
		Message:   message,
		Timestamp: time.Now().Unix(),
	}

	if errorBytes, err := json.Marshal(errorMsg); err == nil {
		wsConn.SendMessage(errorBytes)
	}

	facades.Log().Warning("WebSocket error sent", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       wsConn.UserID,
		"error_code":    code,
		"error_message": message,
	})
}

// cleanupConnection performs cleanup when a connection is closed
func (c *WebSocketController) cleanupConnection(wsConn *services.WebSocketConnection) {
	c.metrics.recordDisconnection()
	
	facades.Log().Info("WebSocket connection cleanup completed", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       wsConn.UserID,
	})
}

// errorResponse returns a standardized error response
func (c *WebSocketController) errorResponse(ctx goravelhttp.Context, status int, code, message string) goravelhttp.Response {
	c.metrics.recordError()
	
	return ctx.Response().Status(status).Json(map[string]interface{}{
		"error": map[string]interface{}{
			"code":      code,
			"message":   message,
			"timestamp": time.Now().Unix(),
		},
	})
}

// getUserIDFromContext extracts the user ID from the context with validation
func (c *WebSocketController) getUserIDFromContext(ctx goravelhttp.Context) string {
	// Get user ID from context (set by auth middleware)
	userID := ctx.Value("user_id")
	if userID == nil {
		return ""
	}

	// Type assertion with validation
	if userIDStr, ok := userID.(string); ok && userIDStr != "" {
		return userIDStr
	}

	return ""
}

// GetConnectionStats returns enhanced statistics about WebSocket connections
func (c *WebSocketController) GetConnectionStats(ctx goravelhttp.Context) goravelhttp.Response {
	hubStats := c.hub.GetStats()
	controllerStats := c.metrics.getStats()

	stats := map[string]interface{}{
		"hub": map[string]interface{}{
			"total_connections":     hubStats.TotalConnections,
			"active_connections":    hubStats.ActiveConnections,
			"connected_users":       c.hub.GetConnectedUsers(),
			"total_messages":        hubStats.TotalMessages,
			"messages_per_second":   hubStats.MessagesPerSecond,
			"connections_created":   hubStats.ConnectionsCreated,
			"connections_destroyed": hubStats.ConnectionsDestroyed,
			"error_count":           hubStats.ErrorCount,
			"last_stats_update":     hubStats.LastStatsUpdate,
		},
		"controller": controllerStats,
		"circuit_breaker": map[string]interface{}{
			"state":        c.circuitBreaker.getStateString(),
			"failures":     atomic.LoadInt64(&c.circuitBreaker.failures),
			"last_failure": c.circuitBreaker.lastFailure,
		},
		"timestamp": time.Now().Unix(),
	}

	return ctx.Response().Success().Json(stats)
}

// Health check endpoint
func (c *WebSocketController) HealthCheck(ctx goravelhttp.Context) goravelhttp.Response {
	health := map[string]interface{}{
		"status": "healthy",
		"timestamp": time.Now().Unix(),
		"checks": map[string]interface{}{
			"hub": map[string]interface{}{
				"status": "healthy",
				"active_connections": c.hub.GetTotalConnections(),
			},
			"circuit_breaker": map[string]interface{}{
				"status": c.circuitBreaker.getStateString(),
				"failures": atomic.LoadInt64(&c.circuitBreaker.failures),
			},
		},
	}

	// Check if circuit breaker is open
	if c.circuitBreaker.getState() == CircuitOpen {
		health["status"] = "degraded"
		health["checks"].(map[string]interface{})["circuit_breaker"].(map[string]interface{})["status"] = "open"
	}

	return ctx.Response().Success().Json(health)
}

// Circuit breaker methods

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	state := atomic.LoadInt32(&cb.state)
	
	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailure) > cb.timeout {
			atomic.StoreInt32(&cb.state, CircuitHalfOpen)
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) RecordSuccess() {
	atomic.StoreInt64(&cb.failures, 0)
	atomic.StoreInt32(&cb.state, CircuitClosed)
}

func (cb *CircuitBreaker) RecordFailure() {
	failures := atomic.AddInt64(&cb.failures, 1)
	cb.mu.Lock()
	cb.lastFailure = time.Now()
	cb.mu.Unlock()

	if failures >= cb.threshold {
		atomic.StoreInt32(&cb.state, CircuitOpen)
	}
}

func (cb *CircuitBreaker) getState() int32 {
	return atomic.LoadInt32(&cb.state)
}

func (cb *CircuitBreaker) getStateString() string {
	switch cb.getState() {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Message validator methods

func (mv *MessageValidator) isValidMessageType(msgType string) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	return mv.allowedTypes[msgType]
}

func (mv *MessageValidator) checkRateLimit(userID, msgType string) bool {
	mv.mu.Lock()
	defer mv.mu.Unlock()

	key := fmt.Sprintf("%s:%s", userID, msgType)
	limiter, exists := mv.rateLimiters[key]
	if !exists {
		limiter = &MessageRateLimiter{
			limit:      60, // messages per minute
			windowSize: time.Minute,
			window:     time.Now(),
		}
		mv.rateLimiters[key] = limiter
	}

	return limiter.Allow()
}

// Message rate limiter methods

func (mrl *MessageRateLimiter) Allow() bool {
	mrl.mu.Lock()
	defer mrl.mu.Unlock()

	now := time.Now()
	if now.Sub(mrl.window) >= mrl.windowSize {
		mrl.count = 0
		mrl.window = now
	}

	if mrl.count >= mrl.limit {
		return false
	}

	mrl.count++
	return true
}

// Controller metrics methods

func (cm *ControllerMetrics) recordConnection() {
	atomic.AddInt64(&cm.totalConnections, 1)
	atomic.AddInt64(&cm.activeConnections, 1)
}

func (cm *ControllerMetrics) recordDisconnection() {
	atomic.AddInt64(&cm.activeConnections, -1)
}

func (cm *ControllerMetrics) recordMessage() {
	atomic.AddInt64(&cm.messagesProcessed, 1)
}

func (cm *ControllerMetrics) recordError() {
	atomic.AddInt64(&cm.errorsCount, 1)
}

func (cm *ControllerMetrics) recordResponseTime(duration time.Duration) {
	atomic.StoreInt64(&cm.averageResponseTime, duration.Nanoseconds())
}

func (cm *ControllerMetrics) getStats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":     atomic.LoadInt64(&cm.totalConnections),
		"active_connections":    atomic.LoadInt64(&cm.activeConnections),
		"messages_processed":    atomic.LoadInt64(&cm.messagesProcessed),
		"errors_count":          atomic.LoadInt64(&cm.errorsCount),
		"average_response_time": time.Duration(atomic.LoadInt64(&cm.averageResponseTime)).String(),
		"last_update":           cm.lastUpdate,
	}
}

// Legacy methods preserved for backward compatibility but enhanced

// SendTestNotification sends a test notification to a specific user with validation
func (c *WebSocketController) SendTestNotification(ctx goravelhttp.Context) goravelhttp.Response {
	userID := ctx.Request().Input("user_id")
	if userID == "" {
		return c.errorResponse(ctx, http.StatusBadRequest, ErrorInvalidMessage, "User ID is required")
	}

	// Check circuit breaker
	if !c.circuitBreaker.Allow() {
		return c.errorResponse(ctx, http.StatusServiceUnavailable, ErrorServiceUnavailable, "Service temporarily unavailable")
	}

	// Create a test notification message
	testMessage := &WebSocketMessage{
		Type:      "notification",
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"id":      "test_notification",
			"title":   "Test Notification",
			"body":    "This is a test notification sent via WebSocket",
			"message": "Test message content",
		},
	}

	// Send the test notification
	if err := c.hub.SendToUser(userID, testMessage); err != nil {
		c.circuitBreaker.RecordFailure()
		return c.errorResponse(ctx, http.StatusInternalServerError, ErrorInternalError, err.Error())
	}

	c.circuitBreaker.RecordSuccess()
	return ctx.Response().Success().Json(map[string]interface{}{
		"message":   "Test notification sent successfully",
		"user_id":   userID,
		"timestamp": time.Now().Unix(),
	})
}

// BroadcastMessage broadcasts a message to all connected users with validation
func (c *WebSocketController) BroadcastMessage(ctx goravelhttp.Context) goravelhttp.Response {
	// Parse request body
	var request struct {
		Type    string      `json:"type" form:"type"`
		Message interface{} `json:"message" form:"message"`
		Data    interface{} `json:"data" form:"data"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return c.errorResponse(ctx, http.StatusBadRequest, ErrorInvalidMessage, "Invalid request format")
	}

	// Validate message type
	if request.Type == "" {
		return c.errorResponse(ctx, http.StatusBadRequest, ErrorInvalidMessage, "Message type is required")
	}

	// Check circuit breaker
	if !c.circuitBreaker.Allow() {
		return c.errorResponse(ctx, http.StatusServiceUnavailable, ErrorServiceUnavailable, "Service temporarily unavailable")
	}

	// Create broadcast message
	broadcastMessage := &WebSocketMessage{
		Type:      request.Type,
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"message":   request.Message,
			"data":      request.Data,
			"broadcast": true,
		},
	}

	// Send broadcast message
	if err := c.hub.SendToAll(broadcastMessage); err != nil {
		c.circuitBreaker.RecordFailure()
		facades.Log().Error("Failed to broadcast message", map[string]interface{}{
			"error": err.Error(),
			"type":  request.Type,
		})
		return c.errorResponse(ctx, http.StatusInternalServerError, ErrorInternalError, "Failed to broadcast message")
	}

	c.circuitBreaker.RecordSuccess()

	facades.Log().Info("Message broadcasted successfully", map[string]interface{}{
		"type":              request.Type,
		"total_connections": c.hub.GetTotalConnections(),
		"connected_users":   c.hub.GetConnectedUsers(),
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":           "Message broadcasted successfully",
		"type":              request.Type,
		"total_connections": c.hub.GetTotalConnections(),
		"connected_users":   c.hub.GetConnectedUsers(),
		"timestamp":         time.Now().Unix(),
	})
}

// CloseConnection closes a specific WebSocket connection with validation
func (c *WebSocketController) CloseConnection(ctx goravelhttp.Context) goravelhttp.Response {
	connectionID := ctx.Request().Route("connection_id")
	if connectionID == "" {
		return c.errorResponse(ctx, http.StatusBadRequest, ErrorInvalidMessage, "Connection ID is required")
	}

	// Close the specific connection
	c.hub.CloseConnection(connectionID)

	facades.Log().Info("WebSocket connection closed by admin", map[string]interface{}{
		"connection_id": connectionID,
		"admin_action":  true,
		"timestamp":     time.Now().Unix(),
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":       "Connection closed successfully",
		"connection_id": connectionID,
		"timestamp":     time.Now().Unix(),
	})
}

// CloseUserConnections closes all connections for a specific user with validation
func (c *WebSocketController) CloseUserConnections(ctx goravelhttp.Context) goravelhttp.Response {
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return c.errorResponse(ctx, http.StatusBadRequest, ErrorInvalidMessage, "User ID is required")
	}

	// Get connection count before closing
	connectionsBefore := c.hub.GetUserConnections(userID)

	// Close all user connections
	c.hub.CloseUserConnections(userID)

	facades.Log().Info("All WebSocket connections closed for user", map[string]interface{}{
		"user_id":            userID,
		"connections_closed": connectionsBefore,
		"admin_action":       true,
		"timestamp":          time.Now().Unix(),
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":            "All user connections closed successfully",
		"user_id":            userID,
		"connections_closed": connectionsBefore,
		"timestamp":          time.Now().Unix(),
	})
}

// Chat-specific WebSocket methods

// ConnectToChatRoom establishes a WebSocket connection for a specific chat room
func (c *WebSocketController) ConnectToChatRoom(ctx goravelhttp.Context) goravelhttp.Response {
	// Get user ID from authentication
	userID := c.getUserIDFromContext(ctx)
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	// Get room ID from route parameter
	roomID := ctx.Request().Route("room_id")
	if roomID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Room ID is required",
		})
	}

	// TODO: Verify user has access to this chat room
	// This should be implemented based on your chat room permissions logic

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
		facades.Log().Error("Failed to upgrade connection to WebSocket for chat room", map[string]interface{}{
			"error":   err.Error(),
			"room_id": roomID,
			"user_id": userID,
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to establish WebSocket connection",
		})
	}

	// Create WebSocket connection with room context
	wsConn := services.NewWebSocketConnection(
		fmt.Sprintf("chat_room_%s_%s_%d", roomID, userID, time.Now().UnixNano()),
		userID,
		conn,
		c.hub,
	)

	// Register the connection
	c.hub.RegisterConnection(wsConn)

	// Join the chat room
	c.hub.JoinRoom(roomID, wsConn.ID)

	// Start goroutines to handle reading and writing for chat room
	go c.handleChatRoomRead(wsConn, conn, roomID)
	go c.handleChatRoomWrite(wsConn, conn, roomID)

	facades.Log().Info("Chat room WebSocket connection established", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       userID,
		"room_id":       roomID,
	})

	// Return success (the WebSocket connection is now established)
	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "Chat room WebSocket connection established",
		"user_id": userID,
		"room_id": roomID,
	})
}

// ConnectToTypingIndicator establishes a WebSocket connection for typing indicators
func (c *WebSocketController) ConnectToTypingIndicator(ctx goravelhttp.Context) goravelhttp.Response {
	// Get user ID from authentication
	userID := c.getUserIDFromContext(ctx)
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	// Get room ID from route parameter
	roomID := ctx.Request().Route("room_id")
	if roomID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Room ID is required",
		})
	}

	// Upgrade the HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	responseWriter := ctx.Response().Writer()
	request := ctx.Request().Origin()

	conn, err := upgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		facades.Log().Error("Failed to upgrade connection to WebSocket for typing indicators", map[string]interface{}{
			"error":   err.Error(),
			"room_id": roomID,
			"user_id": userID,
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to establish WebSocket connection",
		})
	}

	// Create WebSocket connection for typing indicators
	wsConn := services.NewWebSocketConnection(
		fmt.Sprintf("typing_%s_%s_%d", roomID, userID, time.Now().UnixNano()),
		userID,
		conn,
		c.hub,
	)

	c.hub.RegisterConnection(wsConn)

	go c.handleTypingIndicatorRead(wsConn, conn, roomID)
	go c.handleTypingIndicatorWrite(wsConn, conn, roomID)

	facades.Log().Info("Typing indicator WebSocket connection established", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       userID,
		"room_id":       roomID,
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "Typing indicator WebSocket connection established",
		"user_id": userID,
		"room_id": roomID,
	})
}

// ConnectToUserPresence establishes a WebSocket connection for user presence updates
func (c *WebSocketController) ConnectToUserPresence(ctx goravelhttp.Context) goravelhttp.Response {
	// Get user ID from authentication
	userID := c.getUserIDFromContext(ctx)
	if userID == "" {
		return ctx.Response().Status(401).Json(map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	// Upgrade the HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	responseWriter := ctx.Response().Writer()
	request := ctx.Request().Origin()

	conn, err := upgrader.Upgrade(responseWriter, request, nil)
	if err != nil {
		facades.Log().Error("Failed to upgrade connection to WebSocket for user presence", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID,
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to establish WebSocket connection",
		})
	}

	// Create WebSocket connection for user presence
	wsConn := services.NewWebSocketConnection(
		fmt.Sprintf("presence_%s_%d", userID, time.Now().UnixNano()),
		userID,
		conn,
		c.hub,
	)

	c.hub.RegisterConnection(wsConn)

	go c.handleUserPresenceRead(wsConn, conn)
	go c.handleUserPresenceWrite(wsConn, conn)

	facades.Log().Info("User presence WebSocket connection established", map[string]interface{}{
		"connection_id": wsConn.ID,
		"user_id":       userID,
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "User presence WebSocket connection established",
		"user_id": userID,
	})
}

// Chat WebSocket management methods

// GetChatRoomConnections returns statistics about connections in a specific chat room
func (c *WebSocketController) GetChatRoomConnections(ctx goravelhttp.Context) goravelhttp.Response {
	roomID := ctx.Request().Route("room_id")
	if roomID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Room ID is required",
		})
	}

	// Get connections for the specific room
	connections := c.hub.GetRoomConnections(roomID)

	stats := map[string]interface{}{
		"room_id":           roomID,
		"total_connections": len(connections),
		"connections":       connections,
	}

	return ctx.Response().Success().Json(stats)
}

// BroadcastToChatRoom broadcasts a message to all connections in a specific chat room
func (c *WebSocketController) BroadcastToChatRoom(ctx goravelhttp.Context) goravelhttp.Response {
	roomID := ctx.Request().Route("room_id")
	if roomID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Room ID is required",
		})
	}

	// Parse request body
	var request struct {
		Type    string      `json:"type" form:"type"`
		Message interface{} `json:"message" form:"message"`
		Data    interface{} `json:"data" form:"data"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Invalid request format",
		})
	}

	if request.Type == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Message type is required",
		})
	}

	// Create broadcast message
	broadcastMessage := map[string]interface{}{
		"type":      request.Type,
		"room_id":   roomID,
		"message":   request.Message,
		"data":      request.Data,
		"timestamp": time.Now().Unix(),
		"broadcast": true,
	}

	// Send broadcast message to room
	if err := c.hub.SendToRoom(roomID, broadcastMessage); err != nil {
		facades.Log().Error("Failed to broadcast message to chat room", map[string]interface{}{
			"error":   err.Error(),
			"room_id": roomID,
			"type":    request.Type,
		})
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to broadcast message to chat room",
		})
	}

	connections := c.hub.GetRoomConnections(roomID)

	facades.Log().Info("Message broadcasted to chat room successfully", map[string]interface{}{
		"room_id":           roomID,
		"type":              request.Type,
		"total_connections": len(connections),
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":           "Message broadcasted to chat room successfully",
		"room_id":           roomID,
		"type":              request.Type,
		"total_connections": len(connections),
	})
}

// CloseChatRoomConnections closes all WebSocket connections in a specific chat room
func (c *WebSocketController) CloseChatRoomConnections(ctx goravelhttp.Context) goravelhttp.Response {
	roomID := ctx.Request().Route("room_id")
	if roomID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Room ID is required",
		})
	}

	// Get connection count before closing
	connectionsBefore := c.hub.GetRoomConnections(roomID)

	// Close all room connections
	c.hub.CloseRoomConnections(roomID)

	facades.Log().Info("All WebSocket connections closed for chat room", map[string]interface{}{
		"room_id":            roomID,
		"connections_closed": len(connectionsBefore),
		"admin_action":       true,
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":            "All chat room connections closed successfully",
		"room_id":            roomID,
		"connections_closed": len(connectionsBefore),
	})
}

// Chat-specific message handling methods

// handleChatRoomRead handles incoming messages from chat room WebSocket connections
func (c *WebSocketController) handleChatRoomRead(wsConn *services.WebSocketConnection, conn *websocket.Conn, roomID string) {
	defer func() {
		c.hub.LeaveRoom(roomID, wsConn.ID)
		c.hub.UnregisterConnection(wsConn)
		conn.Close()
	}()

	conn.SetReadLimit(2048) // Larger limit for chat messages
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("Chat room WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
					"room_id":       roomID,
				})
			}
			break
		}

		c.handleChatRoomMessage(wsConn, message, roomID)
	}
}

// handleChatRoomWrite handles outgoing messages to chat room WebSocket connections
func (c *WebSocketController) handleChatRoomWrite(wsConn *services.WebSocketConnection, conn *websocket.Conn, roomID string) {
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
				return
			}
			w.Write(message)

			// Add queued messages
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

// handleChatRoomMessage processes incoming chat room messages
func (c *WebSocketController) handleChatRoomMessage(wsConn *services.WebSocketConnection, message []byte, roomID string) {
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		facades.Log().Error("Failed to unmarshal chat room WebSocket message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
			"room_id":       roomID,
		})
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessageType, "Message type is required")
		return
	}

	switch msgType {
	case "chat_message":
		c.handleChatMessage(wsConn, msg, roomID)
	case "message_reaction":
		c.handleMessageReaction(wsConn, msg, roomID)
	case "message_edit":
		c.handleMessageEdit(wsConn, msg, roomID)
	case "message_delete":
		c.handleMessageDelete(wsConn, msg, roomID)
	case "ping":
		// Send pong response
		response := map[string]interface{}{
			"type":      "pong",
			"room_id":   roomID,
			"timestamp": time.Now().Unix(),
		}
		responseBytes, _ := json.Marshal(response)
		wsConn.Send <- responseBytes
	default:
		facades.Log().Warning("Unknown chat room message type", map[string]interface{}{
			"type":          msgType,
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
			"room_id":       roomID,
		})
	}
}

// handleChatMessage processes new chat messages
func (c *WebSocketController) handleChatMessage(wsConn *services.WebSocketConnection, msg map[string]interface{}, roomID string) {
	content, ok := msg["content"].(string)
	if !ok || content == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "Message content is required")
		return
	}

	// TODO: Save message to database using chat service
	// For now, we'll just broadcast the message to all room members

	// Create broadcast message
	broadcastMessage := map[string]interface{}{
		"type":      "new_message",
		"room_id":   roomID,
		"user_id":   wsConn.UserID,
		"content":   content,
		"timestamp": time.Now().Unix(),
	}

	// Broadcast to all room members
	if err := c.hub.SendToRoom(roomID, broadcastMessage); err != nil {
		facades.Log().Error("Failed to broadcast chat message", map[string]interface{}{
			"error":   err.Error(),
			"room_id": roomID,
			"user_id": wsConn.UserID,
		})
		c.sendErrorToConnection(wsConn, ErrorInternalError, "Failed to send message")
		return
	}

	facades.Log().Info("Chat message broadcasted", map[string]interface{}{
		"room_id": roomID,
		"user_id": wsConn.UserID,
		"content": content,
	})
}

// handleMessageReaction processes message reactions
func (c *WebSocketController) handleMessageReaction(wsConn *services.WebSocketConnection, msg map[string]interface{}, roomID string) {
	messageID, ok := msg["message_id"].(string)
	if !ok || messageID == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "Message ID is required")
		return
	}

	reaction, ok := msg["reaction"].(string)
	if !ok || reaction == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "Reaction is required")
		return
	}

	// TODO: Save reaction to database using chat service

	// Broadcast reaction update
	broadcastMessage := map[string]interface{}{
		"type":       "message_reaction",
		"room_id":    roomID,
		"message_id": messageID,
		"user_id":    wsConn.UserID,
		"reaction":   reaction,
		"timestamp":  time.Now().Unix(),
	}

	c.hub.SendToRoom(roomID, broadcastMessage)
}

// handleMessageEdit processes message edits
func (c *WebSocketController) handleMessageEdit(wsConn *services.WebSocketConnection, msg map[string]interface{}, roomID string) {
	messageID, ok := msg["message_id"].(string)
	if !ok || messageID == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "Message ID is required")
		return
	}

	newContent, ok := msg["content"].(string)
	if !ok || newContent == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "New content is required")
		return
	}

	// TODO: Update message in database using chat service

	// Broadcast message edit
	broadcastMessage := map[string]interface{}{
		"type":       "message_edited",
		"room_id":    roomID,
		"message_id": messageID,
		"user_id":    wsConn.UserID,
		"content":    newContent,
		"timestamp":  time.Now().Unix(),
	}

	c.hub.SendToRoom(roomID, broadcastMessage)
}

// handleMessageDelete processes message deletions
func (c *WebSocketController) handleMessageDelete(wsConn *services.WebSocketConnection, msg map[string]interface{}, roomID string) {
	messageID, ok := msg["message_id"].(string)
	if !ok || messageID == "" {
		c.sendErrorToConnection(wsConn, ErrorInvalidMessage, "Message ID is required")
		return
	}

	// TODO: Delete message from database using chat service

	// Broadcast message deletion
	broadcastMessage := map[string]interface{}{
		"type":       "message_deleted",
		"room_id":    roomID,
		"message_id": messageID,
		"user_id":    wsConn.UserID,
		"timestamp":  time.Now().Unix(),
	}

	c.hub.SendToRoom(roomID, broadcastMessage)
}

// Typing indicator handlers

// handleTypingIndicatorRead handles incoming typing indicator messages
func (c *WebSocketController) handleTypingIndicatorRead(wsConn *services.WebSocketConnection, conn *websocket.Conn, roomID string) {
	defer func() {
		c.hub.UnregisterConnection(wsConn)
		conn.Close()
	}()

	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("Typing indicator WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
					"room_id":       roomID,
				})
			}
			break
		}

		c.handleTypingIndicatorMessage(wsConn, message, roomID)
	}
}

// handleTypingIndicatorWrite handles outgoing typing indicator messages
func (c *WebSocketController) handleTypingIndicatorWrite(wsConn *services.WebSocketConnection, conn *websocket.Conn, roomID string) {
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
				return
			}
			w.Write(message)

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

// handleTypingIndicatorMessage processes typing indicator messages
func (c *WebSocketController) handleTypingIndicatorMessage(wsConn *services.WebSocketConnection, message []byte, roomID string) {
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		facades.Log().Error("Failed to unmarshal typing indicator message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
			"room_id":       roomID,
		})
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		return
	}

	switch msgType {
	case "typing_start":
		c.handleTypingStart(wsConn, roomID)
	case "typing_stop":
		c.handleTypingStop(wsConn, roomID)
	case "ping":
		response := map[string]interface{}{
			"type":      "pong",
			"room_id":   roomID,
			"timestamp": time.Now().Unix(),
		}
		responseBytes, _ := json.Marshal(response)
		wsConn.Send <- responseBytes
	}
}

// handleTypingStart broadcasts typing start indicator
func (c *WebSocketController) handleTypingStart(wsConn *services.WebSocketConnection, roomID string) {
	broadcastMessage := map[string]interface{}{
		"type":      "user_typing_start",
		"room_id":   roomID,
		"user_id":   wsConn.UserID,
		"timestamp": time.Now().Unix(),
	}

	c.hub.SendToRoomExcept(roomID, wsConn.UserID, broadcastMessage)
}

// handleTypingStop broadcasts typing stop indicator
func (c *WebSocketController) handleTypingStop(wsConn *services.WebSocketConnection, roomID string) {
	broadcastMessage := map[string]interface{}{
		"type":      "user_typing_stop",
		"room_id":   roomID,
		"user_id":   wsConn.UserID,
		"timestamp": time.Now().Unix(),
	}

	c.hub.SendToRoomExcept(roomID, wsConn.UserID, broadcastMessage)
}

// User presence handlers

// handleUserPresenceRead handles incoming user presence messages
func (c *WebSocketController) handleUserPresenceRead(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
	defer func() {
		c.hub.UnregisterConnection(wsConn)
		conn.Close()
		// Broadcast user offline status
		c.broadcastUserStatus(wsConn.UserID, "offline")
	}()

	// Broadcast user online status
	c.broadcastUserStatus(wsConn.UserID, "online")

	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				facades.Log().Error("User presence WebSocket read error", map[string]interface{}{
					"error":         err.Error(),
					"connection_id": wsConn.ID,
					"user_id":       wsConn.UserID,
				})
			}
			break
		}

		c.handleUserPresenceMessage(wsConn, message)
	}
}

// handleUserPresenceWrite handles outgoing user presence messages
func (c *WebSocketController) handleUserPresenceWrite(wsConn *services.WebSocketConnection, conn *websocket.Conn) {
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
				return
			}
			w.Write(message)

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

// handleUserPresenceMessage processes user presence messages
func (c *WebSocketController) handleUserPresenceMessage(wsConn *services.WebSocketConnection, message []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		facades.Log().Error("Failed to unmarshal user presence message", map[string]interface{}{
			"error":         err.Error(),
			"connection_id": wsConn.ID,
			"user_id":       wsConn.UserID,
		})
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		return
	}

	switch msgType {
	case "status_update":
		if status, ok := msg["status"].(string); ok {
			c.broadcastUserStatus(wsConn.UserID, status)
		}
	case "ping":
		response := map[string]interface{}{
			"type":      "pong",
			"timestamp": time.Now().Unix(),
		}
		responseBytes, _ := json.Marshal(response)
		wsConn.Send <- responseBytes
	}
}

// broadcastUserStatus broadcasts user status updates
func (c *WebSocketController) broadcastUserStatus(userID, status string) {
	broadcastMessage := map[string]interface{}{
		"type":      "user_status_update",
		"user_id":   userID,
		"status":    status,
		"timestamp": time.Now().Unix(),
	}

	c.hub.SendToAll(broadcastMessage)
}
