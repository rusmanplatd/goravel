package v1

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type EventInstancesController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewEventInstancesController() *EventInstancesController {
	return &EventInstancesController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// List returns instances of the specified recurring event
// @Summary Get event instances
// @Description Returns instances of the specified recurring event
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Param timeMin query string false "Lower bound for instances' start time"
// @Param timeMax query string false "Upper bound for instances' start time"
// @Param maxResults query int false "Maximum number of instances returned" default(250)
// @Param originalStart query string false "Original start time of the instance to retrieve"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId}/instances [get]
func (eic *EventInstancesController) List(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	userID := ctx.Value("user_id").(string)

	// Parse query parameters
	timeMin := ctx.Request().Query("timeMin", "")
	timeMax := ctx.Request().Query("timeMax", "")
	maxResults := ctx.Request().QueryInt("maxResults", 250)
	originalStart := ctx.Request().Query("originalStart", "")

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

	// Get the parent recurring event
	var parentEvent models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		With("Participants.User").
		First(&parentEvent)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event not found",
			Timestamp: time.Now(),
		})
	}

	if !parentEvent.IsRecurring {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event is not recurring",
			Timestamp: time.Now(),
		})
	}

	// Get existing event instances
	query := facades.Orm().Query().
		Where("parent_event_id = ?", parentEvent.ID).
		With("Participants.User").
		Order("start_time ASC").
		Limit(maxResults)

	// Apply time filters
	if timeMin != "" {
		if minTime, err := time.Parse(time.RFC3339, timeMin); err == nil {
			query = query.Where("start_time >= ?", minTime)
		}
	}

	if timeMax != "" {
		if maxTime, err := time.Parse(time.RFC3339, timeMax); err == nil {
			query = query.Where("start_time < ?", maxTime)
		}
	}

	// Filter by original start time if specified
	if originalStart != "" {
		if origTime, err := time.Parse(time.RFC3339, originalStart); err == nil {
			query = query.Where("start_time = ?", origTime)
		}
	}

	var instances []models.CalendarEvent
	err = query.Find(&instances)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve event instances",
			Timestamp: time.Now(),
		})
	}

	// If no instances exist, generate them from recurrence rule
	if len(instances) == 0 && originalStart == "" {
		instances = eic.generateRecurringInstances(parentEvent, timeMin, timeMax, maxResults)
	}

	// Transform instances to Google Calendar API format
	eventItems := make([]map[string]interface{}, len(instances))
	for i, instance := range instances {
		eventData := transformEventToGoogleFormat(instance)
		// Add recurring event specific fields
		eventData["recurringEventId"] = parentEvent.ID
		eventData["originalStartTime"] = map[string]interface{}{
			"dateTime": instance.StartTime.Format(time.RFC3339),
			"timeZone": instance.Timezone,
		}
		eventItems[i] = eventData
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

// UpdateInstance updates a specific instance of a recurring event
// @Summary Update event instance
// @Description Updates a specific instance of a recurring event
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Param instanceId path string true "Instance ID"
// @Param event body object{summary=string,description=string,start=object,end=object} true "Event data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId}/instances/{instanceId} [put]
func (eic *EventInstancesController) UpdateInstance(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	instanceID := ctx.Request().Route("instanceId")
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

	// Get the parent recurring event
	var parentEvent models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		First(&parentEvent)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Parent event not found",
			Timestamp: time.Now(),
		})
	}

	// Get or create the instance
	var instance models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND parent_event_id = ?", instanceID, parentEvent.ID).
		First(&instance)

	if err != nil {
		// Create new instance if it doesn't exist
		instance = models.CalendarEvent{
			Title:          parentEvent.Title,
			Description:    parentEvent.Description,
			StartTime:      parentEvent.StartTime,
			EndTime:        parentEvent.EndTime,
			Location:       parentEvent.Location,
			Color:          parentEvent.Color,
			Type:           parentEvent.Type,
			IsAllDay:       parentEvent.IsAllDay,
			IsRecurring:    false, // Instances are not recurring themselves
			Timezone:       parentEvent.Timezone,
			Status:         parentEvent.Status,
			OrganizationID: parentEvent.OrganizationID,
			CalendarID:     parentEvent.CalendarID,
			ParentEventID:  &parentEvent.ID,
			BaseModel: models.BaseModel{
				ID:        instanceID,
				CreatedBy: parentEvent.CreatedBy,
			},
		}
	}

	var request GoogleEventRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Update instance fields
	if request.Summary != "" {
		instance.Title = request.Summary
	}
	if request.Description != "" {
		instance.Description = request.Description
	}
	if request.Location != "" {
		instance.Location = request.Location
	}

	// Update times if provided
	if request.Start.DateTime != "" || request.Start.Date != "" {
		if startTime, err := parseEventDateTime(request.Start); err == nil {
			instance.StartTime = startTime
			instance.IsAllDay = request.Start.Date != ""
		}
	}

	if request.End.DateTime != "" || request.End.Date != "" {
		if endTime, err := parseEventDateTime(request.End); err == nil {
			instance.EndTime = endTime
		}
	}

	// Save or update the instance
	if instance.ID == "" {
		instance.ID = instanceID
		err = facades.Orm().Query().Create(&instance)
	} else {
		err = facades.Orm().Query().Save(&instance)
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update event instance",
			Timestamp: time.Now(),
		})
	}

	eventData := transformEventToGoogleFormat(instance)
	eventData["recurringEventId"] = parentEvent.ID

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event instance updated successfully",
		Data:      eventData,
		Timestamp: time.Now(),
	})
}

// DeleteInstance deletes a specific instance of a recurring event
// @Summary Delete event instance
// @Description Deletes a specific instance of a recurring event
// @Tags events
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param eventId path string true "Event ID"
// @Param instanceId path string true "Instance ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/{eventId}/instances/{instanceId} [delete]
func (eic *EventInstancesController) DeleteInstance(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	eventID := ctx.Request().Route("eventId")
	instanceID := ctx.Request().Route("instanceId")
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

	// Get the instance
	var instance models.CalendarEvent
	err = facades.Orm().Query().
		Where("id = ? AND parent_event_id = ?", instanceID, eventID).
		First(&instance)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event instance not found",
			Timestamp: time.Now(),
		})
	}

	// Delete the instance
	_, err = facades.Orm().Query().Delete(&instance)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete event instance",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// Helper function to generate recurring instances
func (eic *EventInstancesController) generateRecurringInstances(parentEvent models.CalendarEvent, timeMin, timeMax string, maxResults int) []models.CalendarEvent {
	instances := make([]models.CalendarEvent, 0)

	// Parse time bounds
	var startBound, endBound time.Time
	var err error

	if timeMin != "" {
		startBound, err = time.Parse(time.RFC3339, timeMin)
		if err != nil {
			startBound = time.Now()
		}
	} else {
		startBound = time.Now()
	}

	if timeMax != "" {
		endBound, err = time.Parse(time.RFC3339, timeMax)
		if err != nil {
			endBound = startBound.AddDate(1, 0, 0) // Default to 1 year
		}
	} else {
		endBound = startBound.AddDate(1, 0, 0) // Default to 1 year
	}

	// Simple recurrence generation (basic implementation)
	// This is a simplified version - in production, you'd want to use a proper RRULE parser
	if parentEvent.RecurrenceRule != "" {
		// For demonstration, generate weekly instances
		current := parentEvent.StartTime
		duration := parentEvent.EndTime.Sub(parentEvent.StartTime)
		count := 0

		for current.Before(endBound) && count < maxResults {
			if current.After(startBound) || current.Equal(startBound) {
				instance := models.CalendarEvent{
					Title:          parentEvent.Title,
					Description:    parentEvent.Description,
					StartTime:      current,
					EndTime:        current.Add(duration),
					Location:       parentEvent.Location,
					Color:          parentEvent.Color,
					Type:           parentEvent.Type,
					IsAllDay:       parentEvent.IsAllDay,
					IsRecurring:    false,
					Timezone:       parentEvent.Timezone,
					Status:         parentEvent.Status,
					OrganizationID: parentEvent.OrganizationID,
					CalendarID:     parentEvent.CalendarID,
					ParentEventID:  &parentEvent.ID,
					BaseModel: models.BaseModel{
						ID:        fmt.Sprintf("%s_%s", parentEvent.ID, current.Format("20060102T150405")),
						CreatedAt: parentEvent.CreatedAt,
						UpdatedAt: parentEvent.UpdatedAt,
						CreatedBy: parentEvent.CreatedBy,
					},
				}
				instances = append(instances, instance)
				count++
			}
			// Simple weekly recurrence for demonstration
			current = current.AddDate(0, 0, 7)
		}
	}

	return instances
}
