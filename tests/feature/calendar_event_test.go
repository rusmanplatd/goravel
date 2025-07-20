package feature

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"

	"goravel/app/http/requests"
	"goravel/app/models"
)

func TestCalendarEventSystem(t *testing.T) {
	// Setup
	setupTestDatabase(t)

	t.Run("Calendar Event CRUD Operations", func(t *testing.T) {
		testCreateCalendarEvent(t)
		testGetCalendarEvents(t)
		testUpdateCalendarEvent(t)
		testDeleteCalendarEvent(t)
	})

	t.Run("Event Participant Management", func(t *testing.T) {
		testAddParticipant(t)
		testUpdateParticipantResponse(t)
		testRemoveParticipant(t)
		testGetParticipants(t)
	})

	t.Run("Meeting Integration", func(t *testing.T) {
		testCreateEventWithMeeting(t)
		testUpdateMeetingDetails(t)
	})

	t.Run("Event Filtering", func(t *testing.T) {
		testEventFiltering(t)
		testGetMyEvents(t)
	})
}

func testCreateCalendarEvent(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)

	// Test creating new event
	eventData := requests.CreateCalendarEventRequest{
		Title:          "Test Meeting",
		Description:    "Test meeting description",
		StartTime:      time.Now().Add(1 * time.Hour),
		EndTime:        time.Now().Add(2 * time.Hour),
		Location:       "Test Location",
		Color:          "#3B82F6",
		Type:           "meeting",
		IsAllDay:       false,
		IsRecurring:    false,
		Timezone:       "UTC",
		Status:         "scheduled",
		TenantID:       tenant.ID,
		ParticipantIDs: []string{user.ID},
	}

	reqBodyBytes, _ := json.Marshal(eventData)
	req := httptest.NewRequest("POST", "/api/v1/calendar-events", bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, response["data"].(map[string]interface{})["id"].(string))
}

func testGetCalendarEvents(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)

	// Test getting all events
	req := httptest.NewRequest("GET", "/api/v1/calendar-events", nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testUpdateCalendarEvent(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)

	// Test updating event
	updateData := requests.UpdateCalendarEventRequest{
		Title:       "Updated Meeting",
		Description: "Updated meeting description",
		Location:    "Updated Location",
		Color:       "#EF4444",
		Status:      "confirmed",
	}

	reqBodyBytes, _ := json.Marshal(updateData)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/calendar-events/%s", event.ID), bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testDeleteCalendarEvent(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)

	// Test deleting event
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/calendar-events/%s", event.ID), nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
}

func testAddParticipant(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)
	newUser := createTestCalendarUser(t)

	// Test adding participant
	participantData := requests.AddParticipantRequest{
		UserID:       newUser.ID,
		Role:         "attendee",
		IsRequired:   true,
		SendReminder: true,
	}

	reqBodyBytes, _ := json.Marshal(participantData)
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/calendar-events/%s/participants", event.ID), bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testUpdateParticipantResponse(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)
	createTestEventParticipant(t, event.ID, user.ID)

	// Test updating participant response
	responseData := requests.UpdateParticipantResponseRequest{
		ResponseStatus:  "accepted",
		ResponseComment: "I'll be there",
	}

	reqBodyBytes, _ := json.Marshal(responseData)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/calendar-events/%s/participants/%s/response", event.ID, user.ID), bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testRemoveParticipant(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)
	createTestEventParticipant(t, event.ID, user.ID)

	// Test removing participant
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/calendar-events/%s/participants/%s", event.ID, user.ID), nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testGetParticipants(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)
	createTestEventParticipant(t, event.ID, user.ID)

	// Test getting participants
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/calendar-events/%s/participants", event.ID), nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testCreateEventWithMeeting(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)

	// Test creating event with meeting details
	eventData := requests.CreateCalendarEventRequest{
		Title:          "Video Meeting",
		Description:    "Test video meeting",
		StartTime:      time.Now().Add(1 * time.Hour),
		EndTime:        time.Now().Add(2 * time.Hour),
		Location:       "Zoom Meeting",
		Color:          "#3B82F6",
		Type:           "meeting",
		IsAllDay:       false,
		IsRecurring:    false,
		Timezone:       "UTC",
		Status:         "scheduled",
		TenantID:       tenant.ID,
		ParticipantIDs: []string{user.ID},
		Meeting: &requests.CreateMeetingRequest{
			MeetingType: "video",
			Platform:    "zoom",
			MeetingURL:  "https://zoom.us/j/test",
			MeetingID:   "test123",
			Passcode:    "123456",
		},
	}

	reqBodyBytes, _ := json.Marshal(eventData)
	req := httptest.NewRequest("POST", "/api/v1/calendar-events", bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, response["data"].(map[string]interface{})["id"].(string))
}

func testUpdateMeetingDetails(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)

	// Test updating meeting details
	updateData := requests.UpdateCalendarEventRequest{
		Meeting: &requests.UpdateMeetingRequest{
			MeetingType: "video",
			Platform:    "teams",
			MeetingURL:  "https://teams.microsoft.com/l/meetup-join/test",
			MeetingID:   "test456",
			Passcode:    "654321",
		},
	}

	reqBodyBytes, _ := json.Marshal(updateData)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/calendar-events/%s", event.ID), bytes.NewBuffer(reqBodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testEventFiltering(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)

	// Test filtering by type
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/calendar-events?type=%s", event.Type), nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

func testGetMyEvents(t *testing.T) {
	// Create test data
	user := createTestCalendarUser(t)
	tenant := createTestTenant(t)
	event := createTestCalendarEvent(t, user.ID, tenant.ID)
	createTestEventParticipant(t, event.ID, user.ID)

	// Test getting user's events
	req := httptest.NewRequest("GET", "/api/v1/calendar-events/my", nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])
	assert.NotNil(t, response["data"])

	// Cleanup
	cleanupTestEvent(t, event.ID)
}

// Helper functions

func createTestCalendarUser(t *testing.T) *models.User {
	user := &models.User{
		Name:     "Test User",
		Email:    fmt.Sprintf("test%d@example.com", time.Now().Unix()),
		Password: "password123",
		IsActive: true,
	}
	err := facades.Orm().Query().Create(user)
	assert.NoError(t, err)
	return user
}

func createTestTenant(t *testing.T) *models.Tenant {
	tenant := &models.Tenant{
		Name:        "Test Tenant",
		Description: "Test tenant description",
		IsActive:    true,
	}
	err := facades.Orm().Query().Create(tenant)
	assert.NoError(t, err)
	return tenant
}

func createTestCalendarEvent(t *testing.T, createdBy, tenantID string) *models.CalendarEvent {
	event := &models.CalendarEvent{
		Title:       "Test Event",
		Description: "Test event description",
		StartTime:   time.Now().Add(1 * time.Hour),
		EndTime:     time.Now().Add(2 * time.Hour),
		Location:    "Test Location",
		Color:       "#3B82F6",
		Type:        "meeting",
		IsAllDay:    false,
		IsRecurring: false,
		Timezone:    "UTC",
		Status:      "scheduled",
		TenantID:    tenantID,
		CreatedBy:   createdBy,
	}
	err := facades.Orm().Query().Create(event)
	assert.NoError(t, err)
	return event
}

func createTestEventParticipant(t *testing.T, eventID, userID string) *models.EventParticipant {
	participant := &models.EventParticipant{
		EventID:        eventID,
		UserID:         userID,
		Role:           "attendee",
		ResponseStatus: "pending",
		IsRequired:     true,
		SendReminder:   true,
	}
	err := facades.Orm().Query().Create(participant)
	assert.NoError(t, err)
	return participant
}

func cleanupTestEvent(t *testing.T, eventID string) {
	// Delete participants first
	facades.Orm().Query().Where("event_id = ?", eventID).Delete(&models.EventParticipant{})
	// Delete meeting details
	facades.Orm().Query().Where("event_id = ?", eventID).Delete(&models.Meeting{})
	// Delete event
	facades.Orm().Query().Where("id = ?", eventID).Delete(&models.CalendarEvent{})
}
