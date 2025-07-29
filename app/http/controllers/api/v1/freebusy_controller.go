package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type FreeBusyController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewFreeBusyController() *FreeBusyController {
	return &FreeBusyController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// Query returns free/busy information for a set of calendars
// @Summary Query free/busy information
// @Description Returns free/busy information for a set of calendars
// @Tags freebusy
// @Accept json
// @Produce json
// @Param request body object{timeMin=string,timeMax=string,timeZone=string,items=[]object} true "FreeBusy query"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /freeBusy [post]
func (fbc *FreeBusyController) Query(ctx http.Context) http.Response {
	var request struct {
		TimeMin  string                   `json:"timeMin" binding:"required"`
		TimeMax  string                   `json:"timeMax" binding:"required"`
		TimeZone string                   `json:"timeZone"`
		Items    []map[string]interface{} `json:"items" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Parse time range
	timeMin, err := time.Parse(time.RFC3339, request.TimeMin)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid timeMin format",
			Timestamp: time.Now(),
		})
	}

	timeMax, err := time.Parse(time.RFC3339, request.TimeMax)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid timeMax format",
			Timestamp: time.Now(),
		})
	}

	userID := ctx.Value("user_id").(string)
	calendars := make(map[string]interface{})
	groups := make(map[string]interface{})

	// Process each calendar/item requested
	for _, item := range request.Items {
		calendarID, ok := item["id"].(string)
		if !ok {
			continue
		}

		// Validate calendar access
		var calendar models.UserCalendar
		err := facades.Orm().Query().
			Where("id = ? AND user_id = ?", calendarID, userID).
			First(&calendar)

		if err != nil {
			// Calendar not found or no access
			calendars[calendarID] = map[string]interface{}{
				"errors": []map[string]interface{}{
					{
						"domain": "global",
						"reason": "notFound",
					},
				},
			}
			continue
		}

		// Get busy periods for this calendar
		var events []models.CalendarEvent
		err = facades.Orm().Query().
			Where("calendar_id = ? AND start_time < ? AND end_time > ? AND status != ?",
				calendarID, timeMax, timeMin, "cancelled").
			Find(&events)

		if err != nil {
			calendars[calendarID] = map[string]interface{}{
				"errors": []map[string]interface{}{
					{
						"domain": "global",
						"reason": "internalError",
					},
				},
			}
			continue
		}

		// Build busy periods
		busyPeriods := make([]map[string]interface{}, 0)
		for _, event := range events {
			busyPeriods = append(busyPeriods, map[string]interface{}{
				"start": event.StartTime.Format(time.RFC3339),
				"end":   event.EndTime.Format(time.RFC3339),
			})
		}

		calendars[calendarID] = map[string]interface{}{
			"busy": busyPeriods,
		}
	}

	response := map[string]interface{}{
		"kind":      "calendar#freeBusy",
		"timeMin":   request.TimeMin,
		"timeMax":   request.TimeMax,
		"calendars": calendars,
		"groups":    groups,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetAvailability returns availability for a user across all their calendars
// @Summary Get user availability
// @Description Returns availability information for a user across all their calendars
// @Tags freebusy
// @Accept json
// @Produce json
// @Param timeMin query string true "Start time for availability query"
// @Param timeMax query string true "End time for availability query"
// @Param timeZone query string false "Time zone for the query" default(UTC)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /users/me/availability [get]
func (fbc *FreeBusyController) GetAvailability(ctx http.Context) http.Response {
	timeMin := ctx.Request().Query("timeMin", "")
	timeMax := ctx.Request().Query("timeMax", "")
	timeZone := ctx.Request().Query("timeZone", "UTC")

	if timeMin == "" || timeMax == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "timeMin and timeMax are required",
			Timestamp: time.Now(),
		})
	}

	// Parse time range
	startTime, err := time.Parse(time.RFC3339, timeMin)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid timeMin format",
			Timestamp: time.Now(),
		})
	}

	endTime, err := time.Parse(time.RFC3339, timeMax)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid timeMax format",
			Timestamp: time.Now(),
		})
	}

	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Get all user's calendars
	var calendars []models.UserCalendar
	err = facades.Orm().Query().
		Where("user_id = ? AND organization_id = ? AND is_visible = ?", userID, organizationId, true).
		Find(&calendars)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendars",
			Timestamp: time.Now(),
		})
	}

	// Collect all calendar IDs
	calendarIDs := make([]string, len(calendars))
	for i, calendar := range calendars {
		calendarIDs[i] = calendar.ID
	}

	// Get all busy events across user's calendars
	var events []models.CalendarEvent
	err = facades.Orm().Query().
		Where("calendar_id IN ? AND start_time < ? AND end_time > ? AND status != ?",
			calendarIDs, endTime, startTime, "cancelled").
		Order("start_time ASC").
		Find(&events)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve events",
			Timestamp: time.Now(),
		})
	}

	// Build busy periods
	busyPeriods := make([]map[string]interface{}, len(events))
	for i, event := range events {
		busyPeriods[i] = map[string]interface{}{
			"start":    event.StartTime.Format(time.RFC3339),
			"end":      event.EndTime.Format(time.RFC3339),
			"summary":  event.Title,
			"calendar": event.CalendarID,
		}
	}

	// Calculate free periods
	freePeriods := calculateFreePeriods(startTime, endTime, events)

	response := map[string]interface{}{
		"timeMin":     timeMin,
		"timeMax":     timeMax,
		"timeZone":    timeZone,
		"busy":        busyPeriods,
		"free":        freePeriods,
		"calendars":   len(calendars),
		"totalEvents": len(events),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Helper function to calculate free periods
func calculateFreePeriods(startTime, endTime time.Time, events []models.CalendarEvent) []map[string]interface{} {
	freePeriods := make([]map[string]interface{}, 0)

	if len(events) == 0 {
		// Entire period is free
		freePeriods = append(freePeriods, map[string]interface{}{
			"start": startTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		})
		return freePeriods
	}

	// Sort events by start time
	sortedEvents := make([]models.CalendarEvent, len(events))
	copy(sortedEvents, events)

	currentTime := startTime

	for _, event := range sortedEvents {
		eventStart := event.StartTime
		eventEnd := event.EndTime

		// If there's a gap before this event
		if currentTime.Before(eventStart) {
			freePeriods = append(freePeriods, map[string]interface{}{
				"start": currentTime.Format(time.RFC3339),
				"end":   eventStart.Format(time.RFC3339),
			})
		}

		// Move current time to end of this event
		if eventEnd.After(currentTime) {
			currentTime = eventEnd
		}
	}

	// If there's time left after the last event
	if currentTime.Before(endTime) {
		freePeriods = append(freePeriods, map[string]interface{}{
			"start": currentTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		})
	}

	return freePeriods
}
