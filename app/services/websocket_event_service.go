package services

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
)

// WebSocketEvent represents a websocket event
type WebSocketEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Channel   string                 `json:"channel,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Timestamp int64                  `json:"timestamp"`
	Priority  EventPriority          `json:"priority"`
	TTL       int64                  `json:"ttl,omitempty"` // Time to live in seconds
}

// EventPriority represents the priority of an event
type EventPriority int

const (
	PriorityLow EventPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// EventHandler represents a function that handles websocket events
type EventHandler func(event *WebSocketEvent) error

// WebSocketEventService manages websocket events and broadcasting
type WebSocketEventService struct {
	hub      *WebSocketHub
	handlers map[string][]EventHandler
	mu       sync.RWMutex

	// Event queue for different priorities
	lowPriorityQueue      chan *WebSocketEvent
	normalPriorityQueue   chan *WebSocketEvent
	highPriorityQueue     chan *WebSocketEvent
	criticalPriorityQueue chan *WebSocketEvent

	// Event statistics
	stats EventStats
}

// EventStats tracks event statistics
type EventStats struct {
	TotalEvents     int64            `json:"total_events"`
	EventsByType    map[string]int64 `json:"events_by_type"`
	EventsByChannel map[string]int64 `json:"events_by_channel"`
	FailedEvents    int64            `json:"failed_events"`
	mu              sync.RWMutex
}

var (
	eventServiceInstance *WebSocketEventService
	eventServiceOnce     sync.Once
)

// GetWebSocketEventService returns the singleton event service instance
func GetWebSocketEventService() *WebSocketEventService {
	eventServiceOnce.Do(func() {
		eventServiceInstance = &WebSocketEventService{
			hub:                   GetWebSocketHub(),
			handlers:              make(map[string][]EventHandler),
			lowPriorityQueue:      make(chan *WebSocketEvent, 100),
			normalPriorityQueue:   make(chan *WebSocketEvent, 200),
			highPriorityQueue:     make(chan *WebSocketEvent, 300),
			criticalPriorityQueue: make(chan *WebSocketEvent, 50),
			stats: EventStats{
				EventsByType:    make(map[string]int64),
				EventsByChannel: make(map[string]int64),
			},
		}

		// Start event processors
		go eventServiceInstance.processCriticalEvents()
		go eventServiceInstance.processHighPriorityEvents()
		go eventServiceInstance.processNormalPriorityEvents()
		go eventServiceInstance.processLowPriorityEvents()
	})
	return eventServiceInstance
}

// RegisterHandler registers an event handler for a specific event type
func (s *WebSocketEventService) RegisterHandler(eventType string, handler EventHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handlers[eventType] == nil {
		s.handlers[eventType] = make([]EventHandler, 0)
	}
	s.handlers[eventType] = append(s.handlers[eventType], handler)

	facades.Log().Info("WebSocket event handler registered", map[string]interface{}{
		"event_type": eventType,
	})
}

// UnregisterHandler removes an event handler (simplified implementation)
func (s *WebSocketEventService) UnregisterHandler(eventType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.handlers, eventType)

	facades.Log().Info("WebSocket event handler unregistered", map[string]interface{}{
		"event_type": eventType,
	})
}

// EmitEvent emits a websocket event
func (s *WebSocketEventService) EmitEvent(event *WebSocketEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Set default values
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().Unix()
	}

	// Validate event
	if err := s.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Update statistics
	s.updateStats(event)

	// Queue event based on priority
	switch event.Priority {
	case PriorityCritical:
		select {
		case s.criticalPriorityQueue <- event:
			// Event queued successfully
		default:
			// Queue is full, log error
			facades.Log().Error("Critical priority queue is full, dropping event", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"priority":   event.Priority,
			})
			s.incrementFailedEvents()
			return fmt.Errorf("critical priority queue is full")
		}
	case PriorityHigh:
		select {
		case s.highPriorityQueue <- event:
			// Event queued successfully
		default:
			// Queue is full, log error
			facades.Log().Error("High priority queue is full, dropping event", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"priority":   event.Priority,
			})
			s.incrementFailedEvents()
			return fmt.Errorf("high priority queue is full")
		}
	case PriorityNormal:
		select {
		case s.normalPriorityQueue <- event:
			// Event queued successfully
		default:
			// Queue is full, log error
			facades.Log().Error("Normal priority queue is full, dropping event", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"priority":   event.Priority,
			})
			s.incrementFailedEvents()
			return fmt.Errorf("normal priority queue is full")
		}
	case PriorityLow:
		select {
		case s.lowPriorityQueue <- event:
			// Event queued successfully
		default:
			// Queue is full, log error
			facades.Log().Error("Low priority queue is full, dropping event", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"priority":   event.Priority,
			})
			s.incrementFailedEvents()
			return fmt.Errorf("low priority queue is full")
		}
	default:
		// Default to normal priority
		select {
		case s.normalPriorityQueue <- event:
			// Event queued successfully
		default:
			// Queue is full, log error
			facades.Log().Error("Default priority queue is full, dropping event", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"priority":   event.Priority,
			})
			s.incrementFailedEvents()
			return fmt.Errorf("default priority queue is full")
		}
	}

	return nil
}

// BroadcastToChannel broadcasts an event to a specific channel
func (s *WebSocketEventService) BroadcastToChannel(channel string, event *WebSocketEvent) error {
	event.Channel = channel
	return s.EmitEvent(event)
}

// BroadcastToUser broadcasts an event to a specific user
func (s *WebSocketEventService) BroadcastToUser(userID string, event *WebSocketEvent) error {
	event.UserID = userID
	return s.EmitEvent(event)
}

// BroadcastToAll broadcasts an event to all connected users
func (s *WebSocketEventService) BroadcastToAll(event *WebSocketEvent) error {
	event.Channel = "global"
	return s.EmitEvent(event)
}

// processEvent processes a websocket event
func (s *WebSocketEventService) processEvent(event *WebSocketEvent) {
	// Check TTL
	if event.TTL > 0 && time.Now().Unix()-event.Timestamp > event.TTL {
		facades.Log().Debug("Event expired, skipping", map[string]interface{}{
			"event_id":   event.ID,
			"event_type": event.Type,
			"age":        time.Now().Unix() - event.Timestamp,
			"ttl":        event.TTL,
		})
		return
	}

	// Execute registered handlers
	s.mu.RLock()
	handlers := s.handlers[event.Type]
	s.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler(event); err != nil {
			facades.Log().Error("Event handler failed", map[string]interface{}{
				"event_id":   event.ID,
				"event_type": event.Type,
				"error":      err.Error(),
			})
			s.incrementFailedEvents()
		}
	}

	// Broadcast event based on target
	if err := s.broadcastEvent(event); err != nil {
		facades.Log().Error("Failed to broadcast event", map[string]interface{}{
			"event_id":   event.ID,
			"event_type": event.Type,
			"error":      err.Error(),
		})
		s.incrementFailedEvents()
	}
}

// broadcastEvent broadcasts the event to the appropriate targets
func (s *WebSocketEventService) broadcastEvent(event *WebSocketEvent) error {
	message := map[string]interface{}{
		"id":        event.ID,
		"type":      event.Type,
		"channel":   event.Channel,
		"data":      event.Data,
		"timestamp": event.Timestamp,
		"priority":  event.Priority,
	}

	// Broadcast to specific user
	if event.UserID != "" {
		return s.hub.SendToUser(event.UserID, message)
	}

	// Broadcast to all users (global channel or no specific target)
	return s.hub.SendToAll(message)
}

// Event processors for different priorities
func (s *WebSocketEventService) processCriticalEvents() {
	for event := range s.criticalPriorityQueue {
		s.processEvent(event)
	}
}

func (s *WebSocketEventService) processHighPriorityEvents() {
	for event := range s.highPriorityQueue {
		s.processEvent(event)
	}
}

func (s *WebSocketEventService) processNormalPriorityEvents() {
	for event := range s.normalPriorityQueue {
		s.processEvent(event)
	}
}

func (s *WebSocketEventService) processLowPriorityEvents() {
	for event := range s.lowPriorityQueue {
		s.processEvent(event)
	}
}

// Helper methods

func (s *WebSocketEventService) validateEvent(event *WebSocketEvent) error {
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}

	// Check if event type is allowed
	allowedTypes := facades.Config().Get("websocket.message_types.allowed", []string{})
	allowed := false
	for _, allowedType := range allowedTypes.([]string) {
		if event.Type == allowedType {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("event type '%s' is not allowed", event.Type)
	}

	// Check payload size
	if event.Data != nil {
		dataBytes, err := json.Marshal(event.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal event data: %w", err)
		}

		maxSize := facades.Config().GetInt("websocket.message_types.max_payload_size."+event.Type, 512)
		if len(dataBytes) > maxSize {
			return fmt.Errorf("event data exceeds maximum size of %d bytes", maxSize)
		}
	}

	return nil
}

func (s *WebSocketEventService) updateStats(event *WebSocketEvent) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	s.stats.TotalEvents++
	s.stats.EventsByType[event.Type]++
	if event.Channel != "" {
		s.stats.EventsByChannel[event.Channel]++
	}
}

func (s *WebSocketEventService) incrementFailedEvents() {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	s.stats.FailedEvents++
}

// GetStats returns event statistics
func (s *WebSocketEventService) GetStats() *EventStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	// Create a copy to avoid race conditions
	stats := &EventStats{
		TotalEvents:     s.stats.TotalEvents,
		EventsByType:    make(map[string]int64),
		EventsByChannel: make(map[string]int64),
		FailedEvents:    s.stats.FailedEvents,
	}

	for k, v := range s.stats.EventsByType {
		stats.EventsByType[k] = v
	}

	for k, v := range s.stats.EventsByChannel {
		stats.EventsByChannel[k] = v
	}

	return stats
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("event_%d_%d", time.Now().UnixNano(), time.Now().Unix())
}

// Predefined event creators

// CreateNotificationEvent creates a notification event
func CreateNotificationEvent(userID, title, message string, data map[string]interface{}) *WebSocketEvent {
	if data == nil {
		data = make(map[string]interface{})
	}

	data["title"] = title
	data["message"] = message

	return &WebSocketEvent{
		Type:     "notification",
		UserID:   userID,
		Data:     data,
		Priority: PriorityNormal,
		TTL:      3600, // 1 hour
	}
}

// CreateChatMessageEvent creates a chat message event
func CreateChatMessageEvent(userID, roomID, message string, data map[string]interface{}) *WebSocketEvent {
	if data == nil {
		data = make(map[string]interface{})
	}

	data["room_id"] = roomID
	data["message"] = message

	return &WebSocketEvent{
		Type:     "chat_message",
		UserID:   userID,
		Channel:  fmt.Sprintf("chat_room_%s", roomID),
		Data:     data,
		Priority: PriorityHigh,
		TTL:      300, // 5 minutes
	}
}

// CreateUserStatusEvent creates a user status event
func CreateUserStatusEvent(userID, status string, data map[string]interface{}) *WebSocketEvent {
	if data == nil {
		data = make(map[string]interface{})
	}

	data["status"] = status

	return &WebSocketEvent{
		Type:     "user_status",
		UserID:   userID,
		Data:     data,
		Priority: PriorityLow,
		TTL:      60, // 1 minute
	}
}

// CreateSystemEvent creates a system-wide event
func CreateSystemEvent(eventType, message string, data map[string]interface{}) *WebSocketEvent {
	if data == nil {
		data = make(map[string]interface{})
	}

	data["message"] = message

	return &WebSocketEvent{
		Type:     eventType,
		Channel:  "system",
		Data:     data,
		Priority: PriorityCritical,
		TTL:      1800, // 30 minutes
	}
}
