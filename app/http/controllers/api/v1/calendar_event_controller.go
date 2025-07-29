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
	"goravel/app/querybuilder"
	"goravel/app/services"
)

type CalendarEventController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
	auditHelper     *services.AuditHelper
}

func NewCalendarEventController() *CalendarEventController {
	auditService := services.GetAuditService()
	return &CalendarEventController{
		calendarService: services.NewCalendarService(),
		auditService:    auditService,
		auditHelper:     services.NewAuditHelper(auditService),
	}
}

// Index returns all calendar events
// @Summary Get all calendar events
// @Description Retrieve a list of all calendar events with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[title] query string false "Filter by title (partial match)"
// @Param filter[type] query string false "Filter by event type"
// @Param filter[status] query string false "Filter by event status"
// @Param filter[created_by] query string false "Filter by creator ID"
// @Param filter[start_time] query string false "Filter by start time (date range)"
// @Param filter[end_time] query string false "Filter by end time (date range)"
// @Param filter[organization_id] query string false "Filter by organization ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): creator,organization,participants,meeting"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.CalendarEvent}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events [get]
func (cec *CalendarEventController) Index(ctx http.Context) http.Response {
	var events []models.CalendarEvent

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.CalendarEvent{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("title"),
			querybuilder.Exact("type"),
			querybuilder.Exact("status"),
			querybuilder.Exact("created_by"),
			querybuilder.DateRange("start_time"),
			querybuilder.DateRange("end_time"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("title", "type", "status", "start_time", "end_time", "created_at", "updated_at").
		AllowedIncludes("creator", "organization", "participants", "meeting").
		DefaultSort("-created_at")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&events)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendar events: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Calendar events retrieved successfully", result)
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
	err := facades.Orm().Query().With("Creator").With("Organization").
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
		OrganizationID:  request.OrganizationID,
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
		// Log failed event creation
		cec.auditHelper.LogDataOperation(userID, "create", "calendar_event", "", map[string]interface{}{
			"title":      request.Title,
			"start_time": request.StartTime,
			"end_time":   request.EndTime,
			"type":       request.Type,
			"status":     "failed",
			"error":      err.Error(),
		})
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
			EventID:               event.ID,
			MeetingType:           request.Meeting.MeetingType,
			Platform:              request.Meeting.Platform,
			JoinWebUrl:            request.Meeting.MeetingURL,
			VideoTeleconferenceId: request.Meeting.MeetingID,
			Passcode:              request.Meeting.Passcode,
			MeetingNotes:          request.Meeting.MeetingNotes,
			AllowRecording:        request.Meeting.RecordMeeting,
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

	// Log successful event creation
	cec.auditHelper.LogDataOperation(userID, "create", "calendar_event", event.ID, map[string]interface{}{
		"title":             event.Title,
		"start_time":        event.StartTime,
		"end_time":          event.EndTime,
		"type":              event.Type,
		"is_recurring":      event.IsRecurring,
		"participant_count": len(request.ParticipantIDs),
		"has_meeting":       request.Meeting != nil,
		"status":            "success",
	})

	// Reload event with relationships
	facades.Orm().Query().With("Creator").With("Organization").
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
				EventID:               event.ID,
				MeetingType:           request.Meeting.MeetingType,
				Platform:              request.Meeting.Platform,
				JoinWebUrl:            request.Meeting.MeetingURL,
				VideoTeleconferenceId: request.Meeting.MeetingID,
				Passcode:              request.Meeting.Passcode,
				MeetingNotes:          request.Meeting.MeetingNotes,
				AllowRecording:        request.Meeting.RecordMeeting,
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
			meeting.JoinWebUrl = request.Meeting.MeetingURL
			meeting.VideoTeleconferenceId = request.Meeting.MeetingID
			meeting.Passcode = request.Meeting.Passcode
			meeting.MeetingNotes = request.Meeting.MeetingNotes
			meeting.AllowRecording = request.Meeting.RecordMeeting
			// Legacy fields removed - using Teams-like settings instead

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
	facades.Orm().Query().With("Creator").With("Organization").
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
	query = query.With("Creator").With("Organization").With("Participants.User").With("Meeting")

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
			NextCursor: getStringPtr(paginationInfo, "next_cursor"),
			PrevCursor: getStringPtr(paginationInfo, "prev_cursor"),
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

// GetCalendarView returns events in a structured calendar view format
// @Summary Get calendar view
// @Description Retrieve calendar events in daily, weekly, or monthly view format
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param view query string true "View type: day, week, month" Enums(day,week,month)
// @Param date query string false "Reference date (ISO 8601) - defaults to today"
// @Param timezone query string false "Timezone for the view" default(UTC)
// @Param user_id query string false "Filter events for specific user"
// @Param include_all_day query bool false "Include all-day events" default(true)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/view [get]
func (cec *CalendarEventController) GetCalendarView(ctx http.Context) http.Response {
	viewType := ctx.Request().Input("view", "week")
	dateStr := ctx.Request().Input("date", "")
	timezone := ctx.Request().Input("timezone", "UTC")
	userID := ctx.Request().Input("user_id", "")
	includeAllDay := ctx.Request().InputBool("include_all_day", true)

	// Parse reference date
	var referenceDate time.Time
	if dateStr != "" {
		if parsed, err := time.Parse("2006-01-02", dateStr); err == nil {
			referenceDate = parsed
		} else if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
			referenceDate = parsed
		} else {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid date format. Use YYYY-MM-DD or ISO 8601",
				Timestamp: time.Now(),
			})
		}
	} else {
		referenceDate = time.Now()
	}

	// Load timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	referenceDate = referenceDate.In(loc)

	// Calculate date range based on view type
	var startDate, endDate time.Time
	var viewData map[string]interface{}

	switch viewType {
	case "day":
		startDate, endDate = cec.getDayRange(referenceDate)
		viewData, err = cec.getDayViewData(startDate, endDate, userID, includeAllDay)
	case "week":
		startDate, endDate = cec.getWeekRange(referenceDate)
		viewData, err = cec.getWeekViewData(startDate, endDate, userID, includeAllDay)
	case "month":
		startDate, endDate = cec.getMonthRange(referenceDate)
		viewData, err = cec.getMonthViewData(startDate, endDate, userID, includeAllDay)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid view type. Use 'day', 'week', or 'month'",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendar view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Add metadata
	viewData["view_type"] = viewType
	viewData["reference_date"] = referenceDate.Format("2006-01-02")
	viewData["start_date"] = startDate.Format("2006-01-02")
	viewData["end_date"] = endDate.Format("2006-01-02")
	viewData["timezone"] = timezone

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      viewData,
		Timestamp: time.Now(),
	})
}

// GetAvailability returns availability information for users
// @Summary Get user availability
// @Description Get availability information for one or more users within a time range
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param user_ids query string true "Comma-separated user IDs"
// @Param start_time query string true "Start time (ISO 8601)"
// @Param end_time query string true "End time (ISO 8601)"
// @Param timezone query string false "Timezone" default(UTC)
// @Param granularity query string false "Time granularity: 15min, 30min, 1hour" default(30min)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/availability [get]
func (cec *CalendarEventController) GetAvailability(ctx http.Context) http.Response {
	userIDsStr := ctx.Request().Input("user_ids", "")
	startTimeStr := ctx.Request().Input("start_time", "")
	endTimeStr := ctx.Request().Input("end_time", "")
	timezone := ctx.Request().Input("timezone", "UTC")
	granularity := ctx.Request().Input("granularity", "30min")

	if userIDsStr == "" || startTimeStr == "" || endTimeStr == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "user_ids, start_time, and end_time are required",
			Timestamp: time.Now(),
		})
	}

	// Parse user IDs
	userIDs := strings.Split(userIDsStr, ",")
	for i, id := range userIDs {
		userIDs[i] = strings.TrimSpace(id)
	}

	// Parse times
	startTime, err := time.Parse(time.RFC3339, startTimeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid start_time format. Use ISO 8601",
			Timestamp: time.Now(),
		})
	}

	endTime, err := time.Parse(time.RFC3339, endTimeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid end_time format. Use ISO 8601",
			Timestamp: time.Now(),
		})
	}

	// Load timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	startTime = startTime.In(loc)
	endTime = endTime.In(loc)

	// Calculate availability
	availability, err := cec.calculateAvailability(userIDs, startTime, endTime, granularity)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to calculate availability: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      availability,
		Timestamp: time.Now(),
	})
}

// GetEventSuggestions returns smart scheduling suggestions
// @Summary Get event scheduling suggestions
// @Description Get AI-powered scheduling suggestions based on participant availability
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param request body requests.EventSuggestionsRequest true "Suggestion parameters"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/suggestions [post]
func (cec *CalendarEventController) GetEventSuggestions(ctx http.Context) http.Response {
	var request requests.EventSuggestionsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Generate suggestions
	suggestions, err := cec.generateEventSuggestions(&request)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate suggestions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      suggestions,
		Timestamp: time.Now(),
	})
}

// BulkUpdate updates multiple calendar events
// @Summary Bulk update calendar events
// @Description Update multiple calendar events at once
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param request body requests.BulkUpdateEventsRequest true "Bulk update data"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/bulk-update [post]
func (cec *CalendarEventController) BulkUpdate(ctx http.Context) http.Response {
	var request requests.BulkUpdateEventsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	if len(request.EventIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "At least one event ID is required",
			Timestamp: time.Now(),
		})
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

	updatedEvents := []models.CalendarEvent{}
	failedUpdates := []map[string]interface{}{}

	for _, eventID := range request.EventIDs {
		// Find event
		var event models.CalendarEvent
		err := tx.Where("id = ?", eventID).First(&event)
		if err != nil {
			failedUpdates = append(failedUpdates, map[string]interface{}{
				"event_id": eventID,
				"error":    "Event not found",
			})
			continue
		}

		// Apply updates
		updated := false
		if request.Updates.Title != "" {
			event.Title = request.Updates.Title
			updated = true
		}
		if request.Updates.Description != "" {
			event.Description = request.Updates.Description
			updated = true
		}
		if request.Updates.Location != "" {
			event.Location = request.Updates.Location
			updated = true
		}
		if request.Updates.Color != "" {
			event.Color = request.Updates.Color
			updated = true
		}
		if request.Updates.Status != "" {
			event.Status = request.Updates.Status
			updated = true
		}
		if request.Updates.Type != "" {
			event.Type = request.Updates.Type
			updated = true
		}

		// Apply time adjustments
		if request.TimeAdjustment != nil {
			if request.TimeAdjustment.Type == "offset" {
				event.StartTime = event.StartTime.Add(request.TimeAdjustment.Duration)
				event.EndTime = event.EndTime.Add(request.TimeAdjustment.Duration)
				updated = true
			} else if request.TimeAdjustment.Type == "set_duration" {
				event.EndTime = event.StartTime.Add(request.TimeAdjustment.Duration)
				updated = true
			}
		}

		if updated {
			if err := tx.Save(&event); err != nil {
				failedUpdates = append(failedUpdates, map[string]interface{}{
					"event_id": eventID,
					"error":    "Failed to update event: " + err.Error(),
				})
				continue
			}
			updatedEvents = append(updatedEvents, event)
		}
	}

	// Commit transaction
	tx.Commit()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"updated_events":  updatedEvents,
			"updated_count":   len(updatedEvents),
			"failed_updates":  failedUpdates,
			"failed_count":    len(failedUpdates),
			"total_processed": len(request.EventIDs),
		},
		Timestamp: time.Now(),
	})
}

// BulkDelete deletes multiple calendar events
// @Summary Bulk delete calendar events
// @Description Delete multiple calendar events at once
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param request body requests.BulkDeleteEventsRequest true "Bulk delete data"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/bulk-delete [post]
func (cec *CalendarEventController) BulkDelete(ctx http.Context) http.Response {
	var request requests.BulkDeleteEventsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	if len(request.EventIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "At least one event ID is required",
			Timestamp: time.Now(),
		})
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

	deletedCount := 0
	failedDeletes := []map[string]interface{}{}

	for _, eventID := range request.EventIDs {
		// Delete participants first
		_, err := tx.Where("event_id = ?", eventID).Delete(&models.EventParticipant{})
		if err != nil {
			failedDeletes = append(failedDeletes, map[string]interface{}{
				"event_id": eventID,
				"error":    "Failed to delete participants: " + err.Error(),
			})
			continue
		}

		// Delete meeting details
		_, err = tx.Where("event_id = ?", eventID).Delete(&models.Meeting{})
		if err != nil {
			failedDeletes = append(failedDeletes, map[string]interface{}{
				"event_id": eventID,
				"error":    "Failed to delete meeting details: " + err.Error(),
			})
			continue
		}

		// Delete reminders
		_, err = tx.Where("event_id = ?", eventID).Delete(&models.EventReminder{})
		if err != nil {
			failedDeletes = append(failedDeletes, map[string]interface{}{
				"event_id": eventID,
				"error":    "Failed to delete reminders: " + err.Error(),
			})
			continue
		}

		// Delete event
		result, err := tx.Where("id = ?", eventID).Delete(&models.CalendarEvent{})
		if err != nil {
			failedDeletes = append(failedDeletes, map[string]interface{}{
				"event_id": eventID,
				"error":    "Failed to delete event: " + err.Error(),
			})
			continue
		}

		if result.RowsAffected > 0 {
			deletedCount++
		} else {
			failedDeletes = append(failedDeletes, map[string]interface{}{
				"event_id": eventID,
				"error":    "Event not found",
			})
		}
	}

	// Commit transaction
	tx.Commit()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"deleted_count":   deletedCount,
			"failed_deletes":  failedDeletes,
			"failed_count":    len(failedDeletes),
			"total_processed": len(request.EventIDs),
		},
		Timestamp: time.Now(),
	})
}

// BulkReschedule reschedules multiple calendar events
// @Summary Bulk reschedule calendar events
// @Description Reschedule multiple calendar events with conflict detection
// @Tags calendar-events
// @Accept json
// @Produce json
// @Param request body requests.BulkRescheduleEventsRequest true "Bulk reschedule data"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-events/bulk-reschedule [post]
func (cec *CalendarEventController) BulkReschedule(ctx http.Context) http.Response {
	var request requests.BulkRescheduleEventsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	if len(request.EventIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "At least one event ID is required",
			Timestamp: time.Now(),
		})
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

	rescheduledEvents := []models.CalendarEvent{}
	failedReschedules := []map[string]interface{}{}
	conflictingEvents := []map[string]interface{}{}

	for _, eventID := range request.EventIDs {
		// Find event
		var event models.CalendarEvent
		err := tx.With("Participants").Where("id = ?", eventID).First(&event)
		if err != nil {
			failedReschedules = append(failedReschedules, map[string]interface{}{
				"event_id": eventID,
				"error":    "Event not found",
			})
			continue
		}

		// Calculate new times
		var newStartTime, newEndTime time.Time
		duration := event.EndTime.Sub(event.StartTime)

		switch request.RescheduleType {
		case "offset":
			newStartTime = event.StartTime.Add(request.TimeOffset)
			newEndTime = event.EndTime.Add(request.TimeOffset)
		case "set_start":
			newStartTime = request.NewStartTime
			newEndTime = newStartTime.Add(duration)
		case "set_both":
			newStartTime = request.NewStartTime
			newEndTime = request.NewEndTime
		default:
			failedReschedules = append(failedReschedules, map[string]interface{}{
				"event_id": eventID,
				"error":    "Invalid reschedule type",
			})
			continue
		}

		// Check for conflicts if requested
		if request.CheckConflicts {
			userIDs := []string{}
			for _, participant := range event.Participants {
				userIDs = append(userIDs, participant.UserID)
			}

			if len(userIDs) > 0 {
				calendarService := services.NewCalendarService()
				conflicts, err := calendarService.CheckConflicts(newStartTime, newEndTime, userIDs, eventID)
				if err != nil {
					failedReschedules = append(failedReschedules, map[string]interface{}{
						"event_id": eventID,
						"error":    "Failed to check conflicts: " + err.Error(),
					})
					continue
				}

				if conflicts["has_conflicts"].(bool) {
					conflictingEvents = append(conflictingEvents, map[string]interface{}{
						"event_id":       eventID,
						"event_title":    event.Title,
						"new_start_time": newStartTime,
						"new_end_time":   newEndTime,
						"conflicts":      conflicts["conflicting_events"],
					})

					if !request.AllowConflicts {
						failedReschedules = append(failedReschedules, map[string]interface{}{
							"event_id": eventID,
							"error":    "Scheduling conflict detected",
						})
						continue
					}
				}
			}
		}

		// Update event times
		event.StartTime = newStartTime
		event.EndTime = newEndTime

		if err := tx.Save(&event); err != nil {
			failedReschedules = append(failedReschedules, map[string]interface{}{
				"event_id": eventID,
				"error":    "Failed to update event: " + err.Error(),
			})
			continue
		}

		rescheduledEvents = append(rescheduledEvents, event)
	}

	// Commit transaction
	tx.Commit()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status: "success",
		Data: map[string]interface{}{
			"rescheduled_events": rescheduledEvents,
			"rescheduled_count":  len(rescheduledEvents),
			"failed_reschedules": failedReschedules,
			"failed_count":       len(failedReschedules),
			"conflicting_events": conflictingEvents,
			"conflicts_count":    len(conflictingEvents),
			"total_processed":    len(request.EventIDs),
		},
		Timestamp: time.Now(),
	})
}

// Helper methods for calendar views

func (cec *CalendarEventController) getDayRange(date time.Time) (time.Time, time.Time) {
	start := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	end := start.AddDate(0, 0, 1).Add(-time.Nanosecond)
	return start, end
}

func (cec *CalendarEventController) getWeekRange(date time.Time) (time.Time, time.Time) {
	// Start from Monday
	weekday := int(date.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday = 7
	}
	start := date.AddDate(0, 0, -(weekday - 1))
	start = time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
	end := start.AddDate(0, 0, 7).Add(-time.Nanosecond)
	return start, end
}

func (cec *CalendarEventController) getMonthRange(date time.Time) (time.Time, time.Time) {
	start := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, date.Location())
	end := start.AddDate(0, 1, 0).Add(-time.Nanosecond)
	return start, end
}

func (cec *CalendarEventController) getDayViewData(startDate, endDate time.Time, userID string, includeAllDay bool) (map[string]interface{}, error) {
	events, err := cec.getEventsInRange(startDate, endDate, userID, includeAllDay)
	if err != nil {
		return nil, err
	}

	// Group events by hour
	hourlyEvents := make(map[int][]models.CalendarEvent)
	allDayEvents := []models.CalendarEvent{}

	for _, event := range events {
		if event.IsAllDay {
			allDayEvents = append(allDayEvents, event)
		} else {
			hour := event.StartTime.Hour()
			hourlyEvents[hour] = append(hourlyEvents[hour], event)
		}
	}

	return map[string]interface{}{
		"date":           startDate.Format("2006-01-02"),
		"hourly_events":  hourlyEvents,
		"all_day_events": allDayEvents,
		"total_events":   len(events),
	}, nil
}

func (cec *CalendarEventController) getWeekViewData(startDate, endDate time.Time, userID string, includeAllDay bool) (map[string]interface{}, error) {
	events, err := cec.getEventsInRange(startDate, endDate, userID, includeAllDay)
	if err != nil {
		return nil, err
	}

	// Group events by day
	dailyEvents := make(map[string][]models.CalendarEvent)
	weekDays := []string{}

	for d := startDate; d.Before(endDate); d = d.AddDate(0, 0, 1) {
		dayKey := d.Format("2006-01-02")
		weekDays = append(weekDays, dayKey)
		dailyEvents[dayKey] = []models.CalendarEvent{}
	}

	for _, event := range events {
		dayKey := event.StartTime.Format("2006-01-02")
		if _, exists := dailyEvents[dayKey]; exists {
			dailyEvents[dayKey] = append(dailyEvents[dayKey], event)
		}
	}

	return map[string]interface{}{
		"week_start":   startDate.Format("2006-01-02"),
		"week_end":     endDate.Format("2006-01-02"),
		"days":         weekDays,
		"daily_events": dailyEvents,
		"total_events": len(events),
	}, nil
}

func (cec *CalendarEventController) getMonthViewData(startDate, endDate time.Time, userID string, includeAllDay bool) (map[string]interface{}, error) {
	events, err := cec.getEventsInRange(startDate, endDate, userID, includeAllDay)
	if err != nil {
		return nil, err
	}

	// Group events by day
	dailyEvents := make(map[string][]models.CalendarEvent)
	monthDays := []string{}

	for d := startDate; d.Before(endDate); d = d.AddDate(0, 0, 1) {
		dayKey := d.Format("2006-01-02")
		monthDays = append(monthDays, dayKey)
		dailyEvents[dayKey] = []models.CalendarEvent{}
	}

	for _, event := range events {
		dayKey := event.StartTime.Format("2006-01-02")
		if _, exists := dailyEvents[dayKey]; exists {
			dailyEvents[dayKey] = append(dailyEvents[dayKey], event)
		}
	}

	// Calculate week structure for calendar grid
	weeks := cec.calculateWeekStructure(startDate, endDate)

	return map[string]interface{}{
		"month":        startDate.Format("2006-01"),
		"days":         monthDays,
		"daily_events": dailyEvents,
		"weeks":        weeks,
		"total_events": len(events),
	}, nil
}

func (cec *CalendarEventController) getEventsInRange(startDate, endDate time.Time, userID string, includeAllDay bool) ([]models.CalendarEvent, error) {
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate)

	if userID != "" {
		query = query.Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
			Where("event_participants.user_id = ?", userID)
	}

	if !includeAllDay {
		query = query.Where("is_all_day = ?", false)
	}

	query = query.With("Participants.User").With("Meeting").With("Creator")

	var events []models.CalendarEvent
	err := query.Find(&events)
	return events, err
}

func (cec *CalendarEventController) calculateWeekStructure(startDate, endDate time.Time) [][]string {
	var weeks [][]string
	var currentWeek []string

	// Start from the first day of the month, but align to week start (Monday)
	current := startDate
	weekday := int(current.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday = 7
	}
	current = current.AddDate(0, 0, -(weekday - 1))

	for current.Before(endDate.AddDate(0, 0, 7)) {
		if len(currentWeek) == 7 {
			weeks = append(weeks, currentWeek)
			currentWeek = []string{}
		}
		currentWeek = append(currentWeek, current.Format("2006-01-02"))
		current = current.AddDate(0, 0, 1)
	}

	if len(currentWeek) > 0 {
		weeks = append(weeks, currentWeek)
	}

	return weeks
}

func (cec *CalendarEventController) calculateAvailability(userIDs []string, startTime, endTime time.Time, granularity string) (map[string]interface{}, error) {
	// Parse granularity
	var interval time.Duration
	switch granularity {
	case "15min":
		interval = 15 * time.Minute
	case "30min":
		interval = 30 * time.Minute
	case "1hour":
		interval = 1 * time.Hour
	default:
		interval = 30 * time.Minute
	}

	// Get busy times for all users
	busyTimes, err := cec.getBusyTimes(userIDs, startTime, endTime)
	if err != nil {
		return nil, err
	}

	// Generate time slots
	timeSlots := []map[string]interface{}{}
	for current := startTime; current.Before(endTime); current = current.Add(interval) {
		slotEnd := current.Add(interval)
		if slotEnd.After(endTime) {
			slotEnd = endTime
		}

		// Check availability for each user in this slot
		userAvailability := make(map[string]bool)
		for _, userID := range userIDs {
			userAvailability[userID] = !cec.isTimeSlotBusy(current, slotEnd, busyTimes[userID])
		}

		// Count available users
		availableCount := 0
		for _, available := range userAvailability {
			if available {
				availableCount++
			}
		}

		timeSlots = append(timeSlots, map[string]interface{}{
			"start_time":        current.Format(time.RFC3339),
			"end_time":          slotEnd.Format(time.RFC3339),
			"user_availability": userAvailability,
			"available_count":   availableCount,
			"total_users":       len(userIDs),
			"availability_rate": float64(availableCount) / float64(len(userIDs)),
		})
	}

	return map[string]interface{}{
		"time_slots":  timeSlots,
		"granularity": granularity,
		"user_ids":    userIDs,
		"period": map[string]string{
			"start": startTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		},
	}, nil
}

func (cec *CalendarEventController) getBusyTimes(userIDs []string, startTime, endTime time.Time) (map[string][]map[string]time.Time, error) {
	busyTimes := make(map[string][]map[string]time.Time)

	// Initialize empty busy times for all users
	for _, userID := range userIDs {
		busyTimes[userID] = []map[string]time.Time{}
	}

	// Get events for all users in the time range
	var events []models.CalendarEvent
	err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id IN ?", userIDs).
		Where("(start_time < ? AND end_time > ?) OR (start_time >= ? AND start_time < ?)",
			endTime, startTime, startTime, endTime).
		With("Participants").
		Find(&events)

	if err != nil {
		return busyTimes, err
	}

	// Group busy times by user
	for _, event := range events {
		for _, participant := range event.Participants {
			if contains(userIDs, participant.UserID) && participant.ResponseStatus != "declined" {
				busyTimes[participant.UserID] = append(busyTimes[participant.UserID], map[string]time.Time{
					"start": event.StartTime,
					"end":   event.EndTime,
				})
			}
		}
	}

	return busyTimes, nil
}

func (cec *CalendarEventController) isTimeSlotBusy(slotStart, slotEnd time.Time, busyTimes []map[string]time.Time) bool {
	for _, busyTime := range busyTimes {
		// Check if there's any overlap
		if busyTime["start"].Before(slotEnd) && busyTime["end"].After(slotStart) {
			return true
		}
	}
	return false
}

func (cec *CalendarEventController) generateEventSuggestions(request *requests.EventSuggestionsRequest) (map[string]interface{}, error) {
	// Get availability for all participants
	availability, err := cec.calculateAvailability(
		request.ParticipantIDs,
		request.PreferredStartTime,
		request.PreferredEndTime,
		"30min",
	)
	if err != nil {
		return nil, err
	}

	timeSlots := availability["time_slots"].([]map[string]interface{})
	suggestions := []map[string]interface{}{}

	// Find best time slots based on availability
	for _, slot := range timeSlots {
		availabilityRate := slot["availability_rate"].(float64)

		// Only suggest slots with high availability
		if availabilityRate >= request.MinAvailabilityRate {
			// Calculate slot duration
			startTime, _ := time.Parse(time.RFC3339, slot["start_time"].(string))

			// Check if we have enough consecutive slots for the requested duration
			if cec.hasEnoughConsecutiveTime(timeSlots, slot, request.Duration) {
				suggestions = append(suggestions, map[string]interface{}{
					"suggested_start_time": slot["start_time"],
					"suggested_end_time":   startTime.Add(request.Duration).Format(time.RFC3339),
					"availability_rate":    availabilityRate,
					"available_count":      slot["available_count"],
					"total_participants":   slot["total_users"],
					"confidence_score":     cec.calculateConfidenceScore(availabilityRate, startTime, request),
				})
			}
		}
	}

	// Sort suggestions by confidence score
	cec.sortSuggestionsByConfidence(suggestions)

	// Limit to top suggestions
	maxSuggestions := 10
	if len(suggestions) > maxSuggestions {
		suggestions = suggestions[:maxSuggestions]
	}

	return map[string]interface{}{
		"suggestions":     suggestions,
		"total_found":     len(suggestions),
		"search_criteria": request,
	}, nil
}

func (cec *CalendarEventController) hasEnoughConsecutiveTime(timeSlots []map[string]interface{}, currentSlot map[string]interface{}, duration time.Duration) bool {
	// Find current slot index
	currentIndex := -1
	for i, slot := range timeSlots {
		if slot["start_time"] == currentSlot["start_time"] {
			currentIndex = i
			break
		}
	}

	if currentIndex == -1 {
		return false
	}

	// Calculate how many 30-minute slots we need
	slotsNeeded := int(duration.Minutes() / 30)
	if slotsNeeded <= 1 {
		return true
	}

	// Check consecutive slots
	for i := 0; i < slotsNeeded-1; i++ {
		if currentIndex+i+1 >= len(timeSlots) {
			return false
		}

		nextSlot := timeSlots[currentIndex+i+1]
		if nextSlot["availability_rate"].(float64) < 0.8 { // Require high availability for all slots
			return false
		}
	}

	return true
}

func (cec *CalendarEventController) calculateConfidenceScore(availabilityRate float64, startTime time.Time, request *requests.EventSuggestionsRequest) float64 {
	score := availabilityRate * 100

	// Boost score for preferred time ranges
	hour := startTime.Hour()
	if hour >= 9 && hour <= 17 { // Business hours
		score += 10
	}
	if hour >= 10 && hour <= 16 { // Peak business hours
		score += 5
	}

	// Reduce score for very early or very late times
	if hour < 8 || hour > 18 {
		score -= 15
	}

	// Boost score for weekdays
	if startTime.Weekday() >= time.Monday && startTime.Weekday() <= time.Friday {
		score += 5
	}

	return score
}

func (cec *CalendarEventController) sortSuggestionsByConfidence(suggestions []map[string]interface{}) {
	// Simple bubble sort by confidence score (for small arrays)
	n := len(suggestions)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			score1 := suggestions[j]["confidence_score"].(float64)
			score2 := suggestions[j+1]["confidence_score"].(float64)
			if score1 < score2 {
				suggestions[j], suggestions[j+1] = suggestions[j+1], suggestions[j]
			}
		}
	}
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
