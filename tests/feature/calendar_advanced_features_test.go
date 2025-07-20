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

func TestCalendarAdvancedFeatures(t *testing.T) {
	// Setup
	setupTestDatabase(t)

	t.Run("Event Reminders", func(t *testing.T) {
		testCreateEventReminder(t)
		testGetEventReminders(t)
	})

	t.Run("Meeting Status Management", func(t *testing.T) {
		testUpdateMeetingStatus(t)
	})

	t.Run("Conflict Detection", func(t *testing.T) {
		testCheckConflicts(t)
	})

	t.Run("Calendar Export", func(t *testing.T) {
		testExportCalendar(t)
	})
}

func testCreateEventReminder(t *testing.T) {
	// Create a test event first
	event := createTestCalendarEvent(t, "test-user", "test-tenant")

	// Create reminder request
	reminderRequest := requests.CreateReminderRequest{
		UserID:        "test-user-id",
		Type:          "email",
		MinutesBefore: 15,
	}

	requestBody, _ := json.Marshal(reminderRequest)
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/calendar-events/%s/reminders", event.ID), bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify reminder was created in database
	var reminder models.EventReminder
	err = facades.Orm().Query().Where("event_id = ? AND user_id = ?", event.ID, "test-user-id").First(&reminder)
	assert.NoError(t, err)
	assert.Equal(t, "email", reminder.Type)
	assert.Equal(t, 15, reminder.MinutesBefore)
}

func testGetEventReminders(t *testing.T) {
	// Create a test event first
	event := createTestCalendarEvent(t)

	// Create a test reminder
	reminder := models.EventReminder{
		EventID:       event.ID,
		UserID:        "test-user-id",
		Type:          "push",
		MinutesBefore: 30,
		ScheduledAt:   time.Now().Add(30 * time.Minute),
		Status:        "pending",
	}
	facades.Orm().Query().Create(&reminder)

	// Get reminders
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/calendar-events/%s/reminders", event.ID), nil)
	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify reminders data
	reminders := response["data"].([]interface{})
	assert.GreaterOrEqual(t, len(reminders), 1)
}

func testUpdateMeetingStatus(t *testing.T) {
	// Create a test event with meeting
	event := createTestCalendarEvent(t)
	_ = createTestMeeting(t, event.ID)

	// Update meeting status
	statusRequest := requests.UpdateMeetingStatusRequest{
		Status:          "in-progress",
		AttendanceCount: 5,
		MeetingMinutes:  "Key decisions made during the meeting",
		RecordingURL:    "https://example.com/recording.mp4",
	}

	requestBody, _ := json.Marshal(statusRequest)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/calendar-events/%s/meeting/status", event.ID), bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify meeting was updated in database
	var updatedMeeting models.Meeting
	err = facades.Orm().Query().Where("event_id = ?", event.ID).First(&updatedMeeting)
	assert.NoError(t, err)
	assert.Equal(t, "in-progress", updatedMeeting.Status)
	assert.Equal(t, 5, updatedMeeting.AttendanceCount)
	assert.Equal(t, "Key decisions made during the meeting", updatedMeeting.MeetingMinutes)
	assert.Equal(t, "https://example.com/recording.mp4", updatedMeeting.RecordingURL)
}

func testCheckConflicts(t *testing.T) {
	// Create test events that might conflict
	event1 := createTestCalendarEvent(t)
	event2 := createTestCalendarEvent(t)

	// Add participants to both events
	participant1 := models.EventParticipant{
		EventID:        event1.ID,
		UserID:         "user1",
		Role:           "attendee",
		ResponseStatus: "accepted",
	}
	facades.Orm().Query().Create(&participant1)

	participant2 := models.EventParticipant{
		EventID:        event2.ID,
		UserID:         "user1", // Same user
		Role:           "attendee",
		ResponseStatus: "accepted",
	}
	facades.Orm().Query().Create(&participant2)

	// Check for conflicts
	conflictRequest := requests.CheckConflictsRequest{
		StartTime: event1.StartTime,
		EndTime:   event1.EndTime,
		UserIDs:   []string{"user1"},
	}

	requestBody, _ := json.Marshal(conflictRequest)
	req := httptest.NewRequest("POST", "/api/v1/calendar-events/check-conflicts", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response["status"])

	// Verify conflict detection
	data := response["data"].(map[string]interface{})
	hasConflicts := data["has_conflicts"].(bool)
	assert.True(t, hasConflicts)
}

func testExportCalendar(t *testing.T) {
	// Create test events
	event1 := createTestCalendarEvent(t)
	event2 := createTestCalendarEvent(t)

	// Add participants
	participant1 := models.EventParticipant{
		EventID:        event1.ID,
		UserID:         "test-user",
		Role:           "attendee",
		ResponseStatus: "accepted",
	}
	facades.Orm().Query().Create(&participant1)

	participant2 := models.EventParticipant{
		EventID:        event2.ID,
		UserID:         "test-user",
		Role:           "attendee",
		ResponseStatus: "accepted",
	}
	facades.Orm().Query().Create(&participant2)

	// Export calendar
	exportRequest := requests.ExportCalendarRequest{
		StartDate:        time.Now().AddDate(0, -1, 0),
		EndDate:          time.Now().AddDate(0, 1, 0),
		UserID:           "test-user",
		IncludeRecurring: true,
		EventTypes:       []string{"meeting", "event"},
	}

	requestBody, _ := json.Marshal(exportRequest)
	req := httptest.NewRequest("POST", "/api/v1/calendar-events/export", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	facades.Route().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify iCal content
	icalContent := w.Body.String()
	assert.Contains(t, icalContent, "BEGIN:VCALENDAR")
	assert.Contains(t, icalContent, "END:VCALENDAR")
	assert.Contains(t, icalContent, "BEGIN:VEVENT")
	assert.Contains(t, icalContent, "END:VEVENT")
}

// Helper functions

func createTestMeeting(t *testing.T, eventID string) *models.Meeting {
	meeting := &models.Meeting{
		EventID:                 eventID,
		MeetingType:             "video",
		Platform:                "zoom",
		MeetingURL:              "https://zoom.us/j/test",
		MeetingID:               "test123",
		Passcode:                "123456",
		MeetingNotes:            "Test meeting notes",
		RecordMeeting:           false,
		AllowJoinBeforeHost:     true,
		MuteParticipantsOnEntry: false,
		WaitingRoom:             "enabled",
		Status:                  "scheduled",
	}

	err := facades.Orm().Query().Create(meeting)
	assert.NoError(t, err)

	return meeting
}
