package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type CalendarsController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewCalendarsController() *CalendarsController {
	return &CalendarsController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// Get returns metadata for a calendar
// @Summary Get calendar metadata
// @Description Returns metadata for a calendar following Google Calendar API structure
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId} [get]
func (cc *CalendarsController) Get(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

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

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// Insert creates a secondary calendar
// @Summary Create secondary calendar
// @Description Creates a new secondary calendar
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendar body object{summary=string,description=string,location=string,timeZone=string} true "Calendar data"
// @Success 201 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars [post]
func (cc *CalendarsController) Insert(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var request struct {
		Summary     string `json:"summary" binding:"required"`
		Description string `json:"description"`
		Location    string `json:"location"`
		TimeZone    string `json:"timeZone"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	calendar := models.UserCalendar{
		Name:           request.Summary,
		Description:    request.Description,
		Timezone:       request.TimeZone,
		Type:           "secondary",
		IsVisible:      true,
		IsDefault:      false,
		UserID:         userID,
		OrganizationID: organizationId,
		Color:          "#1976d2",
	}

	if err := facades.Orm().Query().Create(&calendar); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create calendar",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar created successfully",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// Update updates metadata for a calendar
// @Summary Update calendar metadata
// @Description Updates metadata for a calendar
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param calendar body object{summary=string,description=string,location=string,timeZone=string} true "Calendar data"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId} [put]
func (cc *CalendarsController) Update(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

	var request struct {
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Location    string `json:"location"`
		TimeZone    string `json:"timeZone"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

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

	// Update fields
	if request.Summary != "" {
		calendar.Name = request.Summary
	}
	if request.Description != "" {
		calendar.Description = request.Description
	}
	if request.TimeZone != "" {
		calendar.Timezone = request.TimeZone
	}

	if err := facades.Orm().Query().Save(&calendar); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update calendar",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar updated successfully",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// Patch updates metadata for a calendar using patch semantics
// @Summary Patch calendar metadata
// @Description Updates metadata for a calendar using patch semantics
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param calendar body object{summary=string,description=string,location=string,timeZone=string} true "Calendar data"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId} [patch]
func (cc *CalendarsController) Patch(ctx http.Context) http.Response {
	// Patch is identical to Update in this implementation
	return cc.Update(ctx)
}

// Delete deletes a secondary calendar
// @Summary Delete secondary calendar
// @Description Deletes a secondary calendar. Use calendars.clear for clearing all events on primary calendars
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId} [delete]
func (cc *CalendarsController) Delete(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND type != ?", calendarID, userID, "primary").
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found or cannot delete primary calendar",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&calendar)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete calendar",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// Clear clears a primary calendar
// @Summary Clear primary calendar
// @Description Clears a primary calendar. This operation deletes all events associated with the primary calendar
// @Tags calendars
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/clear [post]
func (cc *CalendarsController) Clear(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

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

	// Delete all events in this calendar
	_, err = facades.Orm().Query().
		Where("calendar_id = ?", calendarID).
		Delete(&models.CalendarEvent{})

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to clear calendar",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}
