package feature

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"
)

func TestChatAdvancedFeatures(t *testing.T) {
	// Setup test data
	setupTestData(t)

	// Test 1: Message Editing
	t.Run("Message Editing", func(t *testing.T) {
		testMessageEditing(t)
	})

	// Test 2: Message Deletion
	t.Run("Message Deletion", func(t *testing.T) {
		testMessageDeletion(t)
	})

	// Test 3: Message Threading
	t.Run("Message Threading", func(t *testing.T) {
		testMessageThreading(t)
	})

	// Test 4: Notification Settings
	t.Run("Notification Settings", func(t *testing.T) {
		testNotificationSettings(t)
	})
}

func testMessageEditing(t *testing.T) {
	// Create a test user and chat room
	user := createTestUser(t)
	chatRoom := createTestChatRoom(t, user.ID)
	message := createTestMessage(t, chatRoom.ID, user.ID, "Original message content")

	// Test editing a message
	editData := map[string]interface{}{
		"content": "Updated message content",
	}
	editJSON, _ := json.Marshal(editData)

	req := httptest.NewRequest("PUT", "/api/v1/chat/rooms/"+chatRoom.ID+"/messages/"+message.ID, strings.NewReader(string(editJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify the message was edited
	var updatedMessage models.ChatMessage
	err = facades.Orm().Query().Where("id", message.ID).First(&updatedMessage)
	assert.NoError(t, err)
	assert.True(t, updatedMessage.IsEdited)
	assert.NotNil(t, updatedMessage.EditedAt)
}

func testMessageDeletion(t *testing.T) {
	// Create a test user and chat room
	user := createTestUser(t)
	chatRoom := createTestChatRoom(t, user.ID)
	message := createTestMessage(t, chatRoom.ID, user.ID, "Message to delete")

	// Test deleting a message
	req := httptest.NewRequest("DELETE", "/api/v1/chat/rooms/"+chatRoom.ID+"/messages/"+message.ID, nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify the message was deleted (soft delete)
	var deletedMessage models.ChatMessage
	err = facades.Orm().Query().Where("id", message.ID).First(&deletedMessage)
	assert.Error(t, err) // Should not find the message
}

func testMessageThreading(t *testing.T) {
	// Create a test user and chat room
	user := createTestUser(t)
	chatRoom := createTestChatRoom(t, user.ID)
	rootMessage := createTestMessage(t, chatRoom.ID, user.ID, "Root message for thread")

	// Test creating a thread
	threadData := map[string]interface{}{
		"title": "Test Thread",
	}
	threadJSON, _ := json.Marshal(threadData)

	req := httptest.NewRequest("POST", "/api/v1/chat/rooms/"+chatRoom.ID+"/messages/"+rootMessage.ID+"/threads", strings.NewReader(string(threadJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Extract thread ID from response
	threadResponseData := response["data"].(map[string]interface{})
	threadID := threadResponseData["id"].(string)

	// Test getting the thread
	req = httptest.NewRequest("GET", "/api/v1/chat/threads/"+threadID, nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Test getting room threads
	req = httptest.NewRequest("GET", "/api/v1/chat/rooms/"+chatRoom.ID+"/threads", nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Test resolving the thread
	resolveData := map[string]interface{}{
		"note": "Thread resolved",
	}
	resolveJSON, _ := json.Marshal(resolveData)

	req = httptest.NewRequest("POST", "/api/v1/chat/threads/"+threadID+"/resolve", strings.NewReader(string(resolveJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
}

func testNotificationSettings(t *testing.T) {
	// Create a test user and chat room
	user := createTestUser(t)
	chatRoom := createTestChatRoom(t, user.ID)

	// Test getting global notification settings
	req := httptest.NewRequest("GET", "/api/v1/chat/notifications/global", nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Test updating global notification settings
	globalSettings := map[string]interface{}{
		"email_notifications":    false,
		"push_notifications":     true,
		"desktop_notifications":  true,
		"mention_notifications":  true,
		"reaction_notifications": false,
		"thread_notifications":   true,
		"is_muted":               false,
		"custom_settings": map[string]interface{}{
			"sound":     "custom",
			"vibration": true,
		},
	}
	globalSettingsJSON, _ := json.Marshal(globalSettings)

	req = httptest.NewRequest("PUT", "/api/v1/chat/notifications/global", strings.NewReader(string(globalSettingsJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Test getting room notification settings
	req = httptest.NewRequest("GET", "/api/v1/chat/rooms/"+chatRoom.ID+"/notifications", nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Test updating room notification settings
	roomSettings := map[string]interface{}{
		"email_notifications":    true,
		"push_notifications":     false,
		"desktop_notifications":  true,
		"mention_notifications":  true,
		"reaction_notifications": true,
		"thread_notifications":   false,
		"is_muted":               true,
		"mute_until":             "2024-12-31T23:59:59Z",
		"custom_settings": map[string]interface{}{
			"room_specific": true,
		},
	}
	roomSettingsJSON, _ := json.Marshal(roomSettings)

	req = httptest.NewRequest("PUT", "/api/v1/chat/rooms/"+chatRoom.ID+"/notifications", strings.NewReader(string(roomSettingsJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+getTestToken(t, user))

	w = httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
}

// Helper functions for test setup
func setupTestData(t *testing.T) {
	// This would typically set up test database and seed data
	// For now, we'll assume the database is already set up
}

// Note: createTestUser function is already defined in auth_test.go

func createTestChatRoom(t *testing.T, userID string) *models.ChatRoom {
	chatRoom := &models.ChatRoom{
		Name:        "Test Room",
		Description: "Test room for testing",
		Type:        "group",
		IsActive:    true,
		TenantID:    "01HXYZ123456789ABCDEFGHIJK", // Example tenant ID
		CreatedBy:   userID,
	}
	err := facades.Orm().Query().Create(chatRoom)
	assert.NoError(t, err)
	return chatRoom
}

func createTestMessage(t *testing.T, roomID, userID, content string) *models.ChatMessage {
	message := &models.ChatMessage{
		ChatRoomID:        roomID,
		SenderID:          userID,
		Type:              "text",
		EncryptedContent:  content, // In real app, this would be encrypted
		Status:            "sent",
		EncryptionVersion: 1,
	}
	err := facades.Orm().Query().Create(message)
	assert.NoError(t, err)
	return message
}

func getTestToken(t *testing.T, user *models.User) string {
	// This would typically generate a JWT token for the user
	// For now, return a placeholder
	return "test-token"
}
