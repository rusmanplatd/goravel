package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type EventsController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewEventsController() *EventsController {
	return &EventsController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// List returns events on the specified calendar
// @Summary List events
// @Description Returns events on the specified calendar following Google Calendar API structure
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param timeMin query string false "Lower bound (inclusive) for an event's end time to filter by"
// @Param timeMax query string false "Upper bound (exclusive) for an event's start time to filter by"
// @Param maxResults query int false "Maximum number of events returned" default(250)
// @Param orderBy query string false "Order of the events" Enums(startTime,updated) default(startTime)
// @Param singleEvents query bool false "Whether to expand recurring events" default(false)
// @Param showDeleted query bool false "Whether to include deleted events" default(false)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events [get]
func (ec *EventsController) List(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Parse query parameters
	timeMin := ctx.Request().Query("timeMin", "")
	timeMax := ctx.Request().Query("timeMax", "")
	maxResults := ctx.Request().QueryInt("maxResults", 250)
	orderBy := ctx.Request().Query("orderBy", "startTime")
	showDeleted := ctx.Request().QueryBool("showDeleted", false)

	// Build query
	query := facades.Orm().Query().
		Where("calendar_id = ?", calendarID).
		With("Creator").With("Participants.User")

	if timeMin != "" {
		if minTime, err := time.Parse(time.RFC3339, timeMin); err == nil {
			query = query.Where("end_time >= ?", minTime)
		}
	}

	if timeMax != "" {
		if maxTime, err := time.Parse(time.RFC3339, timeMax); err == nil {
			query = query.Where("start_time < ?", maxTime)
		}
	}

	if !showDeleted {
		query = query.Where("deleted_at IS NULL")
	}

	// Apply ordering
	switch orderBy {
	case "updated":
		query = query.Order("updated_at ASC")
	default:
		query = query.Order("start_time ASC")
	}

	query = query.Limit(maxResults)

	var events []models.CalendarEvent
	err = query.Find(&events)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve events: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Transform to Google Calendar API format
	eventItems := make([]map[string]interface{}, len(events))
	for i, event := range events {
		eventItems[i] = transformEventToGoogleFormat(event)
	}

	response := map[string]interface{}{
		"kind":             "calendar#events",
		"etag":             generateListETag(),
		"summary":          calendar.Name,
		"description":      calendar.Description,
		"updated":          time.Now().Format(time.RFC3339),
		"timeZone":         calendar.Timezone,
		"accessRole":       "owner",
		"defaultReminders": parseDefaultReminders(calendar.DefaultReminders),
		"nextPageToken":    "",
		"items":            eventItems,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Get returns an event
// @Summary Get event
// @Description Returns an event based on its ID
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId} [get]
func (ec *EventsController) Get(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	var event models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		With("Creator").With("Participants.User").
		First(&event)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event not found",
			Timestamp: time.Now(),
		})
	}

	eventData := transformEventToGoogleFormat(event)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// Insert creates an event
// @Summary Create event
// @Description Creates an event following Google Calendar API structure
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param event body object{summary=string,description=string,start=object,end=object,location=string,attendees=[]object} true "Event data"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events [post]
func (ec *EventsController) Insert(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	var request GoogleEventRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Parse start and end times
	startTime, err := parseEventDateTime(request.Start)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid start time format",
			Timestamp: time.Now(),
		})
	}

	endTime, err := parseEventDateTime(request.End)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid end time format",
			Timestamp: time.Now(),
		})
	}

	// Create event
	event := models.CalendarEvent{
		Title:          request.Summary,
		Description:    request.Description,
		StartTime:      startTime,
		EndTime:        endTime,
		Location:       request.Location,
		Color:          "#1976d2", // Default color
		Type:           "event",
		IsAllDay:       request.Start.Date != "",
		Status:         "confirmed",
		Timezone:       calendar.Timezone,
		OrganizationID: organizationId,
		CalendarID:     &calendarID,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	// Handle recurrence
	if len(request.Recurrence) > 0 {
		event.IsRecurring = true
		event.RecurrenceRule = strings.Join(request.Recurrence, "\n")
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
			Message:   "Failed to create event",
			Timestamp: time.Now(),
		})
	}

	// Handle attendees
	if len(request.Attendees) > 0 {
		for _, attendee := range request.Attendees {
			participant := models.EventParticipant{
				EventID:        event.ID,
				UserID:         attendee.Email, // Using email as UserID for now
				ResponseStatus: attendee.ResponseStatus,
				IsRequired:     !attendee.Optional,
			}

			if err := tx.Create(&participant); err != nil {
				tx.Rollback()
				return ctx.Response().Status(500).Json(responses.ErrorResponse{
					Status:    "error",
					Message:   "Failed to add attendees",
					Timestamp: time.Now(),
				})
			}
		}
	}

	tx.Commit()

	eventData := transformEventToGoogleFormat(event)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event created successfully",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// Update updates an event
// @Summary Update event
// @Description Updates an event following Google Calendar API structure
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Param event body object{summary=string,description=string,start=object,end=object,location=string} true "Event data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId} [put]
func (ec *EventsController) Update(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	var event models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		First(&event)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event not found",
			Timestamp: time.Now(),
		})
	}

	var request GoogleEventRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Update event fields
	if request.Summary != "" {
		event.Title = request.Summary
	}
	if request.Description != "" {
		event.Description = request.Description
	}
	if request.Location != "" {
		event.Location = request.Location
	}

	// Update times if provided
	if request.Start.DateTime != "" || request.Start.Date != "" {
		if startTime, err := parseEventDateTime(request.Start); err == nil {
			event.StartTime = startTime
			event.IsAllDay = request.Start.Date != ""
		}
	}

	if request.End.DateTime != "" || request.End.Date != "" {
		if endTime, err := parseEventDateTime(request.End); err == nil {
			event.EndTime = endTime
		}
	}

	// Handle recurrence
	if len(request.Recurrence) > 0 {
		event.IsRecurring = true
		event.RecurrenceRule = strings.Join(request.Recurrence, "\n")
	}

	if err := facades.Orm().Query().Save(&event); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update event",
			Timestamp: time.Now(),
		})
	}

	eventData := transformEventToGoogleFormat(event)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event updated successfully",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// Patch updates an event using patch semantics
// @Summary Patch event
// @Description Updates an event using patch semantics
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Param event body object{summary=string,description=string,start=object,end=object} true "Event data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId} [patch]
func (ec *EventsController) Patch(ctx http.Context) http.Response {
	// Patch is identical to Update in this implementation
	return ec.Update(ctx)
}

// Delete deletes an event
// @Summary Delete event
// @Description Deletes an event
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId} [delete]
func (ec *EventsController) Delete(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	userID := ctx.Value("user_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	var event models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		First(&event)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&event)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete event",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// Move moves an event to another calendar
// @Summary Move event to another calendar
// @Description Moves an event from one calendar to another
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Source Calendar ID"
// @Param eventId path string true "Event ID"
// @Param destination query string true "Destination Calendar ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId}/move [post]
func (ec *EventsController) Move(ctx http.Context) http.Response {
	sourceCalendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	destinationCalendarID := ctx.Request().Query("destination")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	if destinationCalendarID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Destination calendar ID is required",
			Timestamp: time.Now(),
		})
	}

	// Validate source calendar access
	var sourceCalendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", sourceCalendarID, userID, organizationId).
		First(&sourceCalendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Source calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Validate destination calendar access
	var destinationCalendar models.UserCalendar
	err = facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", destinationCalendarID, userID, organizationId).
		First(&destinationCalendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Destination calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Get the event
	var event models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, sourceCalendarID).
		With("Participants.User").
		First(&event)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event not found",
			Timestamp: time.Now(),
		})
	}

	// Cannot move recurring event instances
	if event.ParentEventID != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot move recurring event instances. Move the parent event instead",
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
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update event calendar
	event.CalendarID = &destinationCalendarID
	if err := tx.Save(&event); err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to move event",
			Timestamp: time.Now(),
		})
	}

	// If it's a recurring event, move all instances
	if event.IsRecurring {
		var instances []models.CalendarEvent
		err = tx.Where("parent_event_id = ?", event.ID).Find(&instances)
		if err == nil {
			for _, instance := range instances {
				instance.CalendarID = &destinationCalendarID
				tx.Save(&instance)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to commit move operation",
			Timestamp: time.Now(),
		})
	}

	// Reload event with new calendar data
	err = facades.Orm().Query().
		Where("id = ?", eventID).
		With("Participants.User").
		With("Calendar").
		First(&event)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to reload moved event",
			Timestamp: time.Now(),
		})
	}

	eventData := transformEventToGoogleFormat(event)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event moved successfully",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// QuickAdd creates an event based on a simple text string
// @Summary Quick add event
// @Description Creates an event based on a simple text string
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param text query string true "Quick add text"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/quickAdd [post]
func (ec *EventsController) QuickAdd(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	text := ctx.Request().Query("text", "")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	if text == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Text parameter is required",
			Timestamp: time.Now(),
		})
	}

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ?", calendarID, userID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Parse quick add text (simple implementation)
	event := parseQuickAddText(text)
	event.CalendarID = &calendarID
	event.OrganizationID = organizationId
	event.BaseModel.CreatedBy = &userID

	if err := facades.Orm().Query().Create(&event); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create event",
			Timestamp: time.Now(),
		})
	}

	eventData := transformEventToGoogleFormat(event)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event created successfully",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// Helper types and functions

type GoogleEventRequest struct {
	Summary     string          `json:"summary"`
	Description string          `json:"description"`
	Location    string          `json:"location"`
	Start       EventDateTime   `json:"start"`
	End         EventDateTime   `json:"end"`
	Recurrence  []string        `json:"recurrence"`
	Attendees   []EventAttendee `json:"attendees"`
	Reminders   EventReminders  `json:"reminders"`
}

type EventDateTime struct {
	Date     string `json:"date"`
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

type EventAttendee struct {
	Email          string `json:"email"`
	DisplayName    string `json:"displayName"`
	Optional       bool   `json:"optional"`
	ResponseStatus string `json:"responseStatus"`
}

type EventReminders struct {
	UseDefault bool                     `json:"useDefault"`
	Overrides  []map[string]interface{} `json:"overrides"`
}

func parseEventDateTime(dt EventDateTime) (time.Time, error) {
	if dt.DateTime != "" {
		return time.Parse(time.RFC3339, dt.DateTime)
	}
	if dt.Date != "" {
		return time.Parse("2006-01-02", dt.Date)
	}
	return time.Time{}, fmt.Errorf("invalid datetime format")
}

func transformEventToGoogleFormat(event models.CalendarEvent) map[string]interface{} {
	start := map[string]interface{}{}
	end := map[string]interface{}{}

	if event.IsAllDay {
		start["date"] = event.StartTime.Format("2006-01-02")
		end["date"] = event.EndTime.Format("2006-01-02")
	} else {
		start["dateTime"] = event.StartTime.Format(time.RFC3339)
		start["timeZone"] = event.Timezone
		end["dateTime"] = event.EndTime.Format(time.RFC3339)
		end["timeZone"] = event.Timezone
	}

	result := map[string]interface{}{
		"kind":                    "calendar#event",
		"etag":                    generateETag(&event.UpdatedAt),
		"id":                      event.ID,
		"status":                  event.Status,
		"htmlLink":                fmt.Sprintf("/calendar/event/%s", event.ID),
		"created":                 event.CreatedAt.Format(time.RFC3339),
		"updated":                 event.UpdatedAt.Format(time.RFC3339),
		"summary":                 event.Title,
		"description":             event.Description,
		"location":                event.Location,
		"colorId":                 getColorID(event.Color),
		"start":                   start,
		"end":                     end,
		"endTimeUnspecified":      false,
		"transparency":            "opaque",
		"visibility":              "default",
		"iCalUID":                 fmt.Sprintf("%s@goravel.dev", event.ID),
		"sequence":                0,
		"attendeesOmitted":        false,
		"anyoneCanAddSelf":        false,
		"guestsCanInviteOthers":   true,
		"guestsCanModify":         false,
		"guestsCanSeeOtherGuests": true,
		"privateCopy":             false,
		"locked":                  false,
		"eventType":               "default",
	}

	// Add recurrence if event is recurring
	if event.IsRecurring && event.RecurrenceRule != "" {
		result["recurrence"] = strings.Split(event.RecurrenceRule, "\n")
	}

	// Add attendees if available
	if len(event.Participants) > 0 {
		attendees := make([]map[string]interface{}, len(event.Participants))
		for i, participant := range event.Participants {
			displayName := ""
			if participant.User != nil {
				displayName = participant.User.Name
			}
			attendees[i] = map[string]interface{}{
				"email":          participant.UserID, // Using UserID as email for now
				"displayName":    displayName,
				"optional":       !participant.IsRequired,
				"responseStatus": participant.ResponseStatus,
				"self":           false,
				"organizer":      false,
			}
		}
		result["attendees"] = attendees
	}

	// Add reminders
	result["reminders"] = map[string]interface{}{
		"useDefault": true,
		"overrides":  []map[string]interface{}{},
	}

	return result
}

func parseQuickAddText(text string) models.CalendarEvent {
	// Simple quick add parser - can be made more sophisticated
	now := time.Now()

	event := models.CalendarEvent{
		Title:     text,
		StartTime: now.Add(time.Hour),
		EndTime:   now.Add(2 * time.Hour),
		Type:      "event",
		Status:    "confirmed",
		Timezone:  "UTC",
	}

	// Basic parsing for "Meeting at 3pm" or "Lunch tomorrow"
	if strings.Contains(strings.ToLower(text), "tomorrow") {
		event.StartTime = now.AddDate(0, 0, 1).Truncate(24 * time.Hour).Add(12 * time.Hour)
		event.EndTime = event.StartTime.Add(time.Hour)
	}

	return event
}
