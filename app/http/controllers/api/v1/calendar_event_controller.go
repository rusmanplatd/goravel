package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type CalendarEventController struct {
	// Dependent services
}

func NewCalendarEventController() *CalendarEventController {
	return &CalendarEventController{
		// Inject services
	}
}

// Index returns all calendar events with filtering
// @Summary Get all calendar events
// @Description Retrieve a list of calendar events with cursor-based pagination and filtering
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param start_date query string false "Start date filter (ISO 8601)"
// @Param end_date query string false "End date filter (ISO 8601)"
// @Param type query string false "Event type filter"
// @Param status query string false "Event status filter"
// @Param participant_id query string false "Filter by participant ID"
// @Param creator_id query string false "Filter by creator ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.CalendarEvent}
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events [get]
func (cec *CalendarEventController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	startDate := ctx.Request().Input("start_date", "")
	endDate := ctx.Request().Input("end_date", "")
	eventType := ctx.Request().Input("type", "")
	status := ctx.Request().Input("status", "")
	participantID := ctx.Request().Input("participant_id", "")
	creatorID := ctx.Request().Input("creator_id", "")

	// Build query
	query := facades.Orm().Query().Model(&models.CalendarEvent{})

	// Apply filters
	if startDate != "" {
		if parsed, err := time.Parse(time.RFC3339, startDate); err == nil {
			query = query.Where("start_time >= ?", parsed)
		}
	}

	if endDate != "" {
		if parsed, err := time.Parse(time.RFC3339, endDate); err == nil {
			query = query.Where("end_time <= ?", parsed)
		}
	}

	if eventType != "" {
		query = query.Where("type = ?", eventType)
	}

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if creatorID != "" {
		query = query.Where("created_by = ?", creatorID)
	}

	if participantID != "" {
		query = query.Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
			Where("event_participants.user_id = ?", participantID)
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	// Preload relationships
	query = query.With("Creator").With("Tenant").With("Participants.User").With("Meeting")

	var events []models.CalendarEvent
	err = query.Find(&events)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendar events",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(events, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   events,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Show returns a specific calendar event
// @Summary Get calendar event by ID
// @Description Retrieve a specific calendar event by its ID
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Success 200 {object} responses.APIResponse{data=models.CalendarEvent}
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendar-events/{id} [get]
func (cec *CalendarEventController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var event models.CalendarEvent
	err := facades.Orm().Query().With("Creator").With("Tenant").
		With("Participants.User").With("Meeting").
		With("ParentEvent").With("RecurringInstances").
		Where("id = ?", id).First(&event)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar event not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      event,
		Timestamp: time.Now(),
	})
}

// Store creates a new calendar event
// @Summary Create calendar event
// @Description Create a new calendar event with optional participants and meeting details
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param event body requests.CreateCalendarEventRequest true "Event data"
// @Success 201 {object} responses.APIResponse{data=models.CalendarEvent}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events [post]
func (cec *CalendarEventController) Store(ctx http.Context) http.Response {
	var request requests.CreateCalendarEventRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate time range
	if request.StartTime.After(request.EndTime) {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Start time must be before end time",
			Timestamp: time.Now(),
		})
	}

	// Create event
	userID := ctx.Request().Input("user_id", "")
	event := models.CalendarEvent{
		Title:           request.Title,
		Description:     request.Description,
		StartTime:       request.StartTime,
		EndTime:         request.EndTime,
		Location:        request.Location,
		Color:           request.Color,
		Type:            request.Type,
		IsAllDay:        request.IsAllDay,
		IsRecurring:     request.IsRecurring,
		RecurrenceRule:  request.RecurrenceRule,
		RecurrenceUntil: request.RecurrenceUntil,
		Timezone:        request.Timezone,
		Status:          request.Status,
		TenantID:        request.TenantID,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	// Start transaction
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start transaction",
			Timestamp: time.Now(),
		})
	}

	// Save event
	if err := tx.Create(&event); err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create calendar event",
			Timestamp: time.Now(),
		})
	}

	// Add participants
	if len(request.ParticipantIDs) > 0 {
		for _, userID := range request.ParticipantIDs {
			participant := models.EventParticipant{
				EventID:        event.ID,
				UserID:         userID,
				Role:           "attendee",
				ResponseStatus: "pending",
				IsRequired:     true,
				SendReminder:   true,
			}
			if err := tx.Create(&participant); err != nil {
				tx.Rollback()
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to add participant",
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Create meeting details if provided
	if request.Meeting != nil {
		meeting := models.Meeting{
			EventID:                 event.ID,
			MeetingType:             request.Meeting.MeetingType,
			Platform:                request.Meeting.Platform,
			MeetingURL:              request.Meeting.MeetingURL,
			MeetingID:               request.Meeting.MeetingID,
			Passcode:                request.Meeting.Passcode,
			MeetingNotes:            request.Meeting.MeetingNotes,
			RecordMeeting:           request.Meeting.RecordMeeting,
			AllowJoinBeforeHost:     request.Meeting.AllowJoinBeforeHost,
			MuteParticipantsOnEntry: request.Meeting.MuteParticipantsOnEntry,
			WaitingRoom:             request.Meeting.WaitingRoom,
		}
		if err := tx.Create(&meeting); err != nil {
			tx.Rollback()
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to create meeting details",
				Timestamp: time.Now(),
			})
		}
	}

	// Commit transaction
	tx.Commit()

	// Reload event with relationships
	facades.Orm().Query().With("Creator").With("Tenant").
		With("Participants.User").With("Meeting").
		Where("id = ?", event.ID).First(&event)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      event,
		Timestamp: time.Now(),
	})
}

// Update updates an existing calendar event
// @Summary Update calendar event
// @Description Update an existing calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param event body requests.UpdateCalendarEventRequest true "Event data"
// @Success 200 {object} responses.APIResponse{data=models.CalendarEvent}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id} [put]
func (cec *CalendarEventController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.UpdateCalendarEventRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find existing event
	var event models.CalendarEvent
	err := facades.Orm().Query().Where("id = ?", id).First(&event)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar event not found",
			Timestamp: time.Now(),
		})
	}

	// Validate time range if both times are provided
	if request.StartTime != nil && request.EndTime != nil {
		if request.StartTime.After(*request.EndTime) {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Start time must be before end time",
				Timestamp: time.Now(),
			})
		}
	}

	// Update fields
	if request.Title != "" {
		event.Title = request.Title
	}
	if request.Description != "" {
		event.Description = request.Description
	}
	if request.StartTime != nil {
		event.StartTime = *request.StartTime
	}
	if request.EndTime != nil {
		event.EndTime = *request.EndTime
	}
	if request.Location != "" {
		event.Location = request.Location
	}
	if request.Color != "" {
		event.Color = request.Color
	}
	if request.Type != "" {
		event.Type = request.Type
	}
	event.IsAllDay = request.IsAllDay
	event.IsRecurring = request.IsRecurring
	if request.RecurrenceRule != "" {
		event.RecurrenceRule = request.RecurrenceRule
	}
	if request.RecurrenceUntil != nil {
		event.RecurrenceUntil = request.RecurrenceUntil
	}
	if request.Timezone != "" {
		event.Timezone = request.Timezone
	}
	if request.Status != "" {
		event.Status = request.Status
	}

	// Start transaction
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start transaction",
			Timestamp: time.Now(),
		})
	}

	// Update event
	if err := tx.Save(&event); err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update calendar event",
			Timestamp: time.Now(),
		})
	}

	// Update meeting details if provided
	if request.Meeting != nil {
		var meeting models.Meeting
		err := tx.Where("event_id = ?", event.ID).First(&meeting)
		if err != nil {
			// Create new meeting record
			meeting = models.Meeting{
				EventID:                 event.ID,
				MeetingType:             request.Meeting.MeetingType,
				Platform:                request.Meeting.Platform,
				MeetingURL:              request.Meeting.MeetingURL,
				MeetingID:               request.Meeting.MeetingID,
				Passcode:                request.Meeting.Passcode,
				MeetingNotes:            request.Meeting.MeetingNotes,
				RecordMeeting:           request.Meeting.RecordMeeting,
				AllowJoinBeforeHost:     request.Meeting.AllowJoinBeforeHost,
				MuteParticipantsOnEntry: request.Meeting.MuteParticipantsOnEntry,
				WaitingRoom:             request.Meeting.WaitingRoom,
			}
			if err := tx.Create(&meeting); err != nil {
				tx.Rollback()
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to create meeting details",
					Timestamp: time.Now(),
				})
			}
		} else {
			// Update existing meeting record
			meeting.MeetingType = request.Meeting.MeetingType
			meeting.Platform = request.Meeting.Platform
			meeting.MeetingURL = request.Meeting.MeetingURL
			meeting.MeetingID = request.Meeting.MeetingID
			meeting.Passcode = request.Meeting.Passcode
			meeting.MeetingNotes = request.Meeting.MeetingNotes
			meeting.RecordMeeting = request.Meeting.RecordMeeting
			meeting.AllowJoinBeforeHost = request.Meeting.AllowJoinBeforeHost
			meeting.MuteParticipantsOnEntry = request.Meeting.MuteParticipantsOnEntry
			meeting.WaitingRoom = request.Meeting.WaitingRoom

			if err := tx.Save(&meeting); err != nil {
				tx.Rollback()
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to update meeting details",
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Commit transaction
	tx.Commit()

	// Reload event with relationships
	facades.Orm().Query().With("Creator").With("Tenant").
		With("Participants.User").With("Meeting").
		Where("id = ?", event.ID).First(&event)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      event,
		Timestamp: time.Now(),
	})
}

// Delete deletes a calendar event
// @Summary Delete calendar event
// @Description Delete a calendar event and all its participants
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id} [delete]
func (cec *CalendarEventController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	// Start transaction
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start transaction",
			Timestamp: time.Now(),
		})
	}

	// Delete participants
	_, err = tx.Where("event_id = ?", id).Delete(&models.EventParticipant{})
	if err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete event participants",
			Timestamp: time.Now(),
		})
	}

	// Delete meeting details
	_, err = tx.Where("event_id = ?", id).Delete(&models.Meeting{})
	if err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete meeting details",
			Timestamp: time.Now(),
		})
	}

	// Delete event
	_, err = tx.Where("id = ?", id).Delete(&models.CalendarEvent{})
	if err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete calendar event",
			Timestamp: time.Now(),
		})
	}

	// Commit transaction
	tx.Commit()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar event deleted successfully",
		Timestamp: time.Now(),
	})
}

// GetParticipants returns all participants for an event
// @Summary Get event participants
// @Description Retrieve all participants for a specific calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Success 200 {object} responses.APIResponse{data=[]models.EventParticipant}
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/participants [get]
func (cec *CalendarEventController) GetParticipants(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var participants []models.EventParticipant
	err := facades.Orm().Query().With("User").Where("event_id = ?", id).Find(&participants)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve participants",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      participants,
		Timestamp: time.Now(),
	})
}

// AddParticipant adds a participant to an event
// @Summary Add participant to event
// @Description Add a new participant to a calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param participant body requests.AddParticipantRequest true "Participant data"
// @Success 201 {object} responses.APIResponse{data=models.EventParticipant}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/participants [post]
func (cec *CalendarEventController) AddParticipant(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.AddParticipantRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Check if event exists
	var event models.CalendarEvent
	err := facades.Orm().Query().Where("id = ?", id).First(&event)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar event not found",
			Timestamp: time.Now(),
		})
	}

	// Check if participant already exists
	var existingParticipant models.EventParticipant
	err = facades.Orm().Query().Where("event_id = ? AND user_id = ?", id, request.UserID).First(&existingParticipant)
	if err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Participant already exists for this event",
			Timestamp: time.Now(),
		})
	}

	// Create participant
	participant := models.EventParticipant{
		EventID:        id,
		UserID:         request.UserID,
		Role:           request.Role,
		ResponseStatus: "pending",
		IsRequired:     request.IsRequired,
		SendReminder:   request.SendReminder,
	}

	if err := facades.Orm().Query().Create(&participant); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add participant",
			Timestamp: time.Now(),
		})
	}

	// Reload with user data
	facades.Orm().Query().With("User").Where("id = ?", participant.ID).First(&participant)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      participant,
		Timestamp: time.Now(),
	})
}

// UpdateParticipantResponse updates a participant's response
// @Summary Update participant response
// @Description Update a participant's response status for an event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param user_id path string true "User ID"
// @Param response body requests.UpdateParticipantResponseRequest true "Response data"
// @Success 200 {object} responses.APIResponse{data=models.EventParticipant}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/participants/{user_id}/response [put]
func (cec *CalendarEventController) UpdateParticipantResponse(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	var request requests.UpdateParticipantResponseRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find participant
	var participant models.EventParticipant
	err := facades.Orm().Query().Where("event_id = ? AND user_id = ?", id, userID).First(&participant)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Participant not found",
			Timestamp: time.Now(),
		})
	}

	// Update response
	now := time.Now()
	participant.ResponseStatus = request.ResponseStatus
	participant.ResponseComment = request.ResponseComment
	participant.RespondedAt = &now

	if err := facades.Orm().Query().Save(&participant); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update participant response",
			Timestamp: time.Now(),
		})
	}

	// Reload with user data
	facades.Orm().Query().With("User").Where("id = ?", participant.ID).First(&participant)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      participant,
		Timestamp: time.Now(),
	})
}

// RemoveParticipant removes a participant from an event
// @Summary Remove participant from event
// @Description Remove a participant from a calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/participants/{user_id} [delete]
func (cec *CalendarEventController) RemoveParticipant(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	// Delete participant
	result, err := facades.Orm().Query().Where("event_id = ? AND user_id = ?", id, userID).Delete(&models.EventParticipant{})
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete participant",
			Timestamp: time.Now(),
		})
	}
	if result.RowsAffected == 0 {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Participant not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Participant removed successfully",
		Timestamp: time.Now(),
	})
}

// GetMyEvents returns events for the authenticated user
// @Summary Get my events
// @Description Retrieve calendar events for the authenticated user
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param start_date query string false "Start date filter (ISO 8601)"
// @Param end_date query string false "End date filter (ISO 8601)"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.CalendarEvent}
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/my [get]
func (cec *CalendarEventController) GetMyEvents(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "") // Get from auth context
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	startDate := ctx.Request().Input("start_date", "")
	endDate := ctx.Request().Input("end_date", "")

	// Build query for events where user is a participant
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID)

	// Apply date filters
	if startDate != "" {
		if parsed, err := time.Parse(time.RFC3339, startDate); err == nil {
			query = query.Where("start_time >= ?", parsed)
		}
	}

	if endDate != "" {
		if parsed, err := time.Parse(time.RFC3339, endDate); err == nil {
			query = query.Where("end_time <= ?", parsed)
		}
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	// Preload relationships
	query = query.With("Creator").With("Tenant").With("Participants.User").With("Meeting")

	var events []models.CalendarEvent
	err = query.Find(&events)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve events",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(events, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   events,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// CreateReminder creates a reminder for an event
// @Summary Create event reminder
// @Description Create a reminder for a calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param reminder body requests.CreateReminderRequest true "Reminder data"
// @Success 201 {object} responses.APIResponse{data=models.EventReminder}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/reminders [post]
func (cec *CalendarEventController) CreateReminder(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.CreateReminderRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Check if event exists
	var event models.CalendarEvent
	err := facades.Orm().Query().Where("id = ?", id).First(&event)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar event not found",
			Timestamp: time.Now(),
		})
	}

	// Calculate scheduled time
	scheduledAt := event.StartTime.Add(-time.Duration(request.MinutesBefore) * time.Minute)

	// Create reminder
	reminder := models.EventReminder{
		EventID:       id,
		UserID:        request.UserID,
		Type:          request.Type,
		MinutesBefore: request.MinutesBefore,
		ScheduledAt:   scheduledAt,
		Status:        "pending",
	}

	if err := facades.Orm().Query().Create(&reminder); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create reminder",
			Timestamp: time.Now(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("User").With("Event").Where("id = ?", reminder.ID).First(&reminder)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      reminder,
		Timestamp: time.Now(),
	})
}

// GetReminders returns all reminders for an event
// @Summary Get event reminders
// @Description Retrieve all reminders for a specific calendar event
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Success 200 {object} responses.APIResponse{data=[]models.EventReminder}
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/reminders [get]
func (cec *CalendarEventController) GetReminders(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var reminders []models.EventReminder
	err := facades.Orm().Query().With("User").Where("event_id = ?", id).Find(&reminders)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve reminders",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      reminders,
		Timestamp: time.Now(),
	})
}

// UpdateMeetingStatus updates the status of a meeting
// @Summary Update meeting status
// @Description Update the status and details of a meeting
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param id path string true "Event ID"
// @Param status body requests.UpdateMeetingStatusRequest true "Meeting status data"
// @Success 200 {object} responses.APIResponse{data=models.Meeting}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/{id}/meeting/status [put]
func (cec *CalendarEventController) UpdateMeetingStatus(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.UpdateMeetingStatusRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find meeting
	var meeting models.Meeting
	err := facades.Orm().Query().Where("event_id = ?", id).First(&meeting)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Meeting not found",
			Timestamp: time.Now(),
		})
	}

	// Update meeting status
	meeting.Status = request.Status
	meeting.AttendanceCount = request.AttendanceCount
	meeting.MeetingMinutes = request.MeetingMinutes
	meeting.RecordingURL = request.RecordingURL

	// Set started/ended times based on status
	now := time.Now()
	if request.Status == "in-progress" && meeting.StartedAt == nil {
		meeting.StartedAt = &now
	} else if request.Status == "completed" && meeting.EndedAt == nil {
		meeting.EndedAt = &now
	}

	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update meeting status",
			Timestamp: time.Now(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("Event").Where("id = ?", meeting.ID).First(&meeting)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      meeting,
		Timestamp: time.Now(),
	})
}

// CheckConflicts checks for scheduling conflicts
// @Summary Check scheduling conflicts
// @Description Check for scheduling conflicts with existing events
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param request body requests.CheckConflictsRequest true "Conflict check data"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendar-events/check-conflicts [post]
func (cec *CalendarEventController) CheckConflicts(ctx http.Context) http.Response {
	var request requests.CheckConflictsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Build query for conflicting events
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id IN ?", request.UserIDs).
		Where("(start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?) OR (start_time >= ? AND end_time <= ?)",
			request.EndTime, request.StartTime, request.EndTime, request.StartTime, request.StartTime, request.EndTime)

	// Exclude specific event if provided
	if request.ExcludeEventID != "" {
		query = query.Where("calendar_events.id != ?", request.ExcludeEventID)
	}

	var conflictingEvents []models.CalendarEvent
	err := query.With("Participants.User").Find(&conflictingEvents)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to check conflicts",
			Timestamp: time.Now(),
		})
	}

	// Group conflicts by user
	conflictsByUser := make(map[string][]models.CalendarEvent)
	for _, event := range conflictingEvents {
		for _, participant := range event.Participants {
			if contains(request.UserIDs, participant.UserID) {
				conflictsByUser[participant.UserID] = append(conflictsByUser[participant.UserID], event)
			}
		}
	}

	hasConflicts := len(conflictingEvents) > 0

	return ctx.Response().Success().Json(responses.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"has_conflicts":      hasConflicts,
			"conflicts_by_user":  conflictsByUser,
			"total_conflicts":    len(conflictingEvents),
			"conflicting_events": conflictingEvents,
		},
		Timestamp: time.Now(),
	})
}

// ExportCalendar exports calendar events to iCal format
// @Summary Export calendar to iCal
// @Description Export calendar events to iCal format
// @Tags calendar-events
// @Accept json
// @Produce text/calendar
// @Param request body requests.ExportCalendarRequest true "Export data"
// @Success 200 {string} string "iCal content"
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendar-events/export [post]
func (cec *CalendarEventController) ExportCalendar(ctx http.Context) http.Response {
	var request requests.ExportCalendarRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Build query for events
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", request.UserID).
		Where("start_time >= ? AND end_time <= ?", request.StartDate, request.EndDate)

	// Apply filters
	if !request.IncludeRecurring {
		query = query.Where("is_recurring = ?", false)
	}

	if len(request.EventTypes) > 0 {
		query = query.Where("type IN ?", request.EventTypes)
	}

	var events []models.CalendarEvent
	err := query.With("Participants.User").With("Meeting").Find(&events)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve events for export",
			Timestamp: time.Now(),
		})
	}

	// Generate iCal content
	icalContent := generateICalContent(events)

	return ctx.Response().Header("Content-Type", "text/calendar").
		Header("Content-Disposition", "attachment; filename=\"calendar.ics\"").
		Success().
		Json(icalContent)
}

// Helper function to check if slice contains value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// Helper function to generate iCal content
func generateICalContent(events []models.CalendarEvent) string {
	var ical strings.Builder

	// iCal header
	ical.WriteString("BEGIN:VCALENDAR\r\n")
	ical.WriteString("VERSION:2.0\r\n")
	ical.WriteString("PRODID:-//Goravel//Calendar//EN\r\n")
	ical.WriteString("CALSCALE:GREGORIAN\r\n")
	ical.WriteString("METHOD:PUBLISH\r\n")

	// Add events
	for _, event := range events {
		ical.WriteString("BEGIN:VEVENT\r\n")
		ical.WriteString(fmt.Sprintf("UID:%s\r\n", event.ID))
		ical.WriteString(fmt.Sprintf("DTSTART:%s\r\n", event.StartTime.Format("20060102T150405Z")))
		ical.WriteString(fmt.Sprintf("DTEND:%s\r\n", event.EndTime.Format("20060102T150405Z")))
		ical.WriteString(fmt.Sprintf("SUMMARY:%s\r\n", event.Title))
		if event.Description != "" {
			ical.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", event.Description))
		}
		if event.Location != "" {
			ical.WriteString(fmt.Sprintf("LOCATION:%s\r\n", event.Location))
		}
		if event.IsRecurring && event.RecurrenceRule != "" {
			ical.WriteString(fmt.Sprintf("RRULE:%s\r\n", event.RecurrenceRule))
		}
		ical.WriteString(fmt.Sprintf("DTSTAMP:%s\r\n", time.Now().Format("20060102T150405Z")))
		ical.WriteString("END:VEVENT\r\n")
	}

	// iCal footer
	ical.WriteString("END:VCALENDAR\r\n")

	return ical.String()
}
