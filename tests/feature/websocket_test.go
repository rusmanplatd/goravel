package feature

import (
	"encoding/json"
	"testing"
	"time"

	"goravel/app/services"
	"goravel/tests"
)

type WebSocketTestSuite struct {
	tests.TestCase
}

func TestWebSocketHub(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	// Test WebSocket Hub creation
	hub := services.GetWebSocketHub()
	if hub == nil {
		t.Fatal("WebSocket hub should not be nil")
	}

	// Test initial state
	if hub.GetTotalConnections() != 0 {
		t.Errorf("Expected 0 connections, got %d", hub.GetTotalConnections())
	}

	if hub.GetConnectedUsers() != 0 {
		t.Errorf("Expected 0 users, got %d", hub.GetConnectedUsers())
	}
}

func TestWebSocketEventService(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	// Test WebSocket Event Service creation
	eventService := services.GetWebSocketEventService()
	if eventService == nil {
		t.Fatal("WebSocket event service should not be nil")
	}

	// Test event creation
	event := services.CreateNotificationEvent("user123", "Test Title", "Test Message", nil)
	if event == nil {
		t.Fatal("Event should not be nil")
	}

	if event.Type != "notification" {
		t.Errorf("Expected event type 'notification', got '%s'", event.Type)
	}

	if event.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", event.UserID)
	}

	// Test event validation
	event.Type = "" // Invalid event type
	err := eventService.EmitEvent(event)
	if err == nil {
		t.Error("Expected error for invalid event type")
	}
}

func TestWebSocketEventCreators(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	// Test notification event creation
	notificationEvent := services.CreateNotificationEvent("user123", "Test Title", "Test Message", map[string]interface{}{
		"extra": "data",
	})

	if notificationEvent.Type != "notification" {
		t.Errorf("Expected type 'notification', got '%s'", notificationEvent.Type)
	}

	if notificationEvent.UserID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", notificationEvent.UserID)
	}

	if notificationEvent.Data["title"] != "Test Title" {
		t.Errorf("Expected title 'Test Title', got '%v'", notificationEvent.Data["title"])
	}

	if notificationEvent.Priority != services.PriorityNormal {
		t.Errorf("Expected priority %d, got %d", services.PriorityNormal, notificationEvent.Priority)
	}

	// Test chat message event creation
	chatEvent := services.CreateChatMessageEvent("user456", "room789", "Hello World", nil)

	if chatEvent.Type != "chat_message" {
		t.Errorf("Expected type 'chat_message', got '%s'", chatEvent.Type)
	}

	if chatEvent.UserID != "user456" {
		t.Errorf("Expected user ID 'user456', got '%s'", chatEvent.UserID)
	}

	if chatEvent.Channel != "chat_room_room789" {
		t.Errorf("Expected channel 'chat_room_room789', got '%s'", chatEvent.Channel)
	}

	if chatEvent.Priority != services.PriorityHigh {
		t.Errorf("Expected priority %d, got %d", services.PriorityHigh, chatEvent.Priority)
	}

	// Test user status event creation
	statusEvent := services.CreateUserStatusEvent("user789", "online", nil)

	if statusEvent.Type != "user_status" {
		t.Errorf("Expected type 'user_status', got '%s'", statusEvent.Type)
	}

	if statusEvent.UserID != "user789" {
		t.Errorf("Expected user ID 'user789', got '%s'", statusEvent.UserID)
	}

	if statusEvent.Data["status"] != "online" {
		t.Errorf("Expected status 'online', got '%v'", statusEvent.Data["status"])
	}

	if statusEvent.Priority != services.PriorityLow {
		t.Errorf("Expected priority %d, got %d", services.PriorityLow, statusEvent.Priority)
	}

	// Test system event creation
	systemEvent := services.CreateSystemEvent("maintenance", "System maintenance scheduled", nil)

	if systemEvent.Type != "maintenance" {
		t.Errorf("Expected type 'maintenance', got '%s'", systemEvent.Type)
	}

	if systemEvent.Channel != "system" {
		t.Errorf("Expected channel 'system', got '%s'", systemEvent.Channel)
	}

	if systemEvent.Priority != services.PriorityCritical {
		t.Errorf("Expected priority %d, got %d", services.PriorityCritical, systemEvent.Priority)
	}
}

func TestWebSocketConnection(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	// Create a test WebSocket connection
	hub := services.GetWebSocketHub()

	conn := &services.WebSocketConnection{
		ID:     "test_conn_123",
		UserID: "test_user_456",
		Send:   make(chan []byte, 256),
		Hub:    hub,
	}

	// Register the connection
	hub.RegisterConnection(conn)

	// Give some time for the registration to process
	time.Sleep(10 * time.Millisecond)

	// Test connection count
	if hub.GetTotalConnections() != 1 {
		t.Errorf("Expected 1 connection, got %d", hub.GetTotalConnections())
	}

	if hub.GetConnectedUsers() != 1 {
		t.Errorf("Expected 1 user, got %d", hub.GetConnectedUsers())
	}

	// Test user connection check
	if !hub.IsUserConnected("test_user_456") {
		t.Error("User should be connected")
	}

	if hub.IsUserConnected("nonexistent_user") {
		t.Error("Nonexistent user should not be connected")
	}

	// Test user connection count
	userConnections := hub.GetUserConnections("test_user_456")
	if userConnections != 1 {
		t.Errorf("Expected 1 connection for user, got %d", userConnections)
	}

	// Test sending message to user
	testMessage := map[string]interface{}{
		"type":    "test",
		"message": "Hello World",
	}

	err := hub.SendToUser("test_user_456", testMessage)
	if err != nil {
		t.Errorf("Failed to send message to user: %v", err)
	}

	// Check if message was received
	select {
	case msg := <-conn.Send:
		var receivedMessage map[string]interface{}
		if err := json.Unmarshal(msg, &receivedMessage); err != nil {
			t.Errorf("Failed to unmarshal received message: %v", err)
		} else {
			if receivedMessage["type"] != "test" {
				t.Errorf("Expected message type 'test', got '%v'", receivedMessage["type"])
			}
			if receivedMessage["message"] != "Hello World" {
				t.Errorf("Expected message 'Hello World', got '%v'", receivedMessage["message"])
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Message was not received within timeout")
	}

	// Test unregistering connection
	hub.UnregisterConnection(conn)

	// Give some time for the unregistration to process
	time.Sleep(10 * time.Millisecond)

	// Test connection count after unregistration
	if hub.GetTotalConnections() != 0 {
		t.Errorf("Expected 0 connections after unregistration, got %d", hub.GetTotalConnections())
	}

	if hub.GetConnectedUsers() != 0 {
		t.Errorf("Expected 0 users after unregistration, got %d", hub.GetConnectedUsers())
	}
}

func TestWebSocketBroadcast(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	hub := services.GetWebSocketHub()

	// Create multiple test connections
	conn1 := &services.WebSocketConnection{
		ID:     "test_conn_1",
		UserID: "test_user_1",
		Send:   make(chan []byte, 256),
		Hub:    hub,
	}

	conn2 := &services.WebSocketConnection{
		ID:     "test_conn_2",
		UserID: "test_user_2",
		Send:   make(chan []byte, 256),
		Hub:    hub,
	}

	// Register connections
	hub.RegisterConnection(conn1)
	hub.RegisterConnection(conn2)

	// Give some time for registrations to process
	time.Sleep(10 * time.Millisecond)

	// Test broadcasting to all users
	broadcastMessage := map[string]interface{}{
		"type":    "broadcast",
		"message": "Hello Everyone",
	}

	err := hub.SendToAll(broadcastMessage)
	if err != nil {
		t.Errorf("Failed to broadcast message: %v", err)
	}

	// Check if both connections received the message
	for i, conn := range []*services.WebSocketConnection{conn1, conn2} {
		select {
		case msg := <-conn.Send:
			var receivedMessage map[string]interface{}
			if err := json.Unmarshal(msg, &receivedMessage); err != nil {
				t.Errorf("Connection %d: Failed to unmarshal received message: %v", i+1, err)
			} else {
				if receivedMessage["type"] != "broadcast" {
					t.Errorf("Connection %d: Expected message type 'broadcast', got '%v'", i+1, receivedMessage["type"])
				}
				if receivedMessage["message"] != "Hello Everyone" {
					t.Errorf("Connection %d: Expected message 'Hello Everyone', got '%v'", i+1, receivedMessage["message"])
				}
			}
		case <-time.After(100 * time.Millisecond):
			t.Errorf("Connection %d: Message was not received within timeout", i+1)
		}
	}

	// Clean up
	hub.UnregisterConnection(conn1)
	hub.UnregisterConnection(conn2)
}

func TestWebSocketEventStats(t *testing.T) {
	suite := &WebSocketTestSuite{}
	suite.SetupTest()
	defer suite.TearDownTest()

	eventService := services.GetWebSocketEventService()

	// Get initial stats
	initialStats := eventService.GetStats()

	// Create and emit some test events
	event1 := services.CreateNotificationEvent("user1", "Title1", "Message1", nil)
	event2 := services.CreateChatMessageEvent("user2", "room1", "Chat message", nil)
	event3 := services.CreateUserStatusEvent("user3", "online", nil)

	// Emit events (they might fail due to validation, but stats should still be updated)
	eventService.EmitEvent(event1)
	eventService.EmitEvent(event2)
	eventService.EmitEvent(event3)

	// Give some time for events to be processed
	time.Sleep(50 * time.Millisecond)

	// Get updated stats
	updatedStats := eventService.GetStats()

	// Check if stats were updated (at least some events should have been processed)
	if updatedStats.TotalEvents <= initialStats.TotalEvents {
		t.Errorf("Expected total events to increase, initial: %d, updated: %d",
			initialStats.TotalEvents, updatedStats.TotalEvents)
	}

	// Check if event types are tracked
	if len(updatedStats.EventsByType) == 0 {
		t.Error("Expected events by type to be tracked")
	}
}

// Helper methods for test setup
func (suite *WebSocketTestSuite) SetupTest() {
	// Any setup needed for tests
}

func (suite *WebSocketTestSuite) TearDownTest() {
	// Any cleanup needed after tests
}
