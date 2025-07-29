package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type UserCalendarController struct {
	userCalendarService *services.UserCalendarService
	auditService        *services.AuditService
}

func NewUserCalendarController() *UserCalendarController {
	return &UserCalendarController{
		userCalendarService: services.NewUserCalendarService(),
		auditService:        services.GetAuditService(),
	}
}

// Index returns all user calendars
// @Summary Get user calendars
// @Description Retrieve all calendars for the authenticated user
// @Tags user-calendars
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]models.UserCalendar}
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars [get]
func (ucc *UserCalendarController) Index(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	calendars, err := ucc.userCalendarService.GetUserCalendars(userID, organizationId)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendars: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendars retrieved successfully",
		Data:      calendars,
		Timestamp: time.Now(),
	})
}

// Store creates a new calendar
// @Summary Create calendar
// @Description Create a new calendar for the authenticated user
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param calendar body object{name=string,description=string,color=string,type=string,is_visible=bool,timezone=string,visibility=string} true "Calendar data"
// @Success 201 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars [post]
func (ucc *UserCalendarController) Store(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Validate required fields
	name := ctx.Request().Input("name")
	if name == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar name is required",
			Timestamp: time.Now(),
		})
	}

	data := map[string]interface{}{
		"name":        name,
		"description": ctx.Request().Input("description", ""),
		"color":       ctx.Request().Input("color", "#1976d2"),
		"type":        ctx.Request().Input("type", "personal"),
		"is_visible":  ctx.Request().InputBool("is_visible", true),
		"timezone":    ctx.Request().Input("timezone", "UTC"),
		"visibility":  ctx.Request().Input("visibility", "private"),
	}

	calendar, err := ucc.userCalendarService.CreateCalendar(userID, organizationId, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create calendar: " + err.Error(),
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

// Show returns a specific calendar
// @Summary Get calendar by ID
// @Description Retrieve a specific calendar by ID
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 404 {object} responses.ErrorResponse
// @Router /user-calendars/{id} [get]
func (ucc *UserCalendarController) Show(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
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
		Message:   "Calendar retrieved successfully",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// Update updates an existing calendar
// @Summary Update calendar
// @Description Update an existing calendar
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Param calendar body object{name=string,description=string,color=string,type=string,is_visible=bool,is_default=bool,timezone=string,visibility=string} true "Calendar data"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/{id} [put]
func (ucc *UserCalendarController) Update(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	data := make(map[string]interface{})

	if name := ctx.Request().Input("name"); name != "" {
		data["name"] = name
	}
	if description := ctx.Request().Input("description"); description != "" {
		data["description"] = description
	}
	if color := ctx.Request().Input("color"); color != "" {
		data["color"] = color
	}
	if calType := ctx.Request().Input("type"); calType != "" {
		data["type"] = calType
	}
	if ctx.Request().Input("is_visible") != "" {
		data["is_visible"] = ctx.Request().InputBool("is_visible")
	}
	if ctx.Request().Input("is_default") != "" {
		data["is_default"] = ctx.Request().InputBool("is_default")
	}
	if timezone := ctx.Request().Input("timezone"); timezone != "" {
		data["timezone"] = timezone
	}
	if visibility := ctx.Request().Input("visibility"); visibility != "" {
		data["visibility"] = visibility
	}

	calendar, err := ucc.userCalendarService.UpdateCalendar(calendarID, userID, organizationId, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update calendar: " + err.Error(),
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

// Destroy deletes a calendar
// @Summary Delete calendar
// @Description Delete a calendar and migrate its events to the default calendar
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/{id} [delete]
func (ucc *UserCalendarController) Destroy(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	err := ucc.userCalendarService.DeleteCalendar(calendarID, userID, organizationId)
	if err != nil {
		status := 500
		if err.Error() == "cannot delete default calendar" {
			status = 400
		} else if err.Error() == "calendar not found" {
			status = 404
		}

		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar deleted successfully",
		Data:      map[string]interface{}{"deleted_calendar_id": calendarID},
		Timestamp: time.Now(),
	})
}

// ToggleVisibility toggles calendar visibility
// @Summary Toggle calendar visibility
// @Description Toggle the visibility of a calendar
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/{id}/toggle-visibility [post]
func (ucc *UserCalendarController) ToggleVisibility(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	calendar, err := ucc.userCalendarService.ToggleCalendarVisibility(calendarID, userID, organizationId)
	if err != nil {
		status := 500
		if err.Error() == "calendar not found" {
			status = 404
		}

		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar visibility toggled successfully",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// Reorder updates calendar order
// @Summary Reorder calendars
// @Description Update the display order of calendars
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param calendar_ids body object{calendar_ids=[]string} true "Array of calendar IDs in desired order"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/reorder [post]
func (ucc *UserCalendarController) Reorder(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var requestData struct {
		CalendarIDs []string `json:"calendar_ids"`
	}

	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(requestData.CalendarIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar IDs are required",
			Timestamp: time.Now(),
		})
	}

	err := ucc.userCalendarService.ReorderCalendars(userID, organizationId, requestData.CalendarIDs)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to reorder calendars: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendars reordered successfully",
		Data:      map[string]interface{}{"reordered_count": len(requestData.CalendarIDs)},
		Timestamp: time.Now(),
	})
}

// GetWithEvents returns a calendar with its events
// @Summary Get calendar with events
// @Description Retrieve a calendar with its events for a specific date range
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(today)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(30 days from start)
// @Success 200 {object} responses.APIResponse{data=models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/{id}/events [get]
func (ucc *UserCalendarController) GetWithEvents(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	// Parse date range
	startDateStr := ctx.Request().Input("start_date", time.Now().Format("2006-01-02"))
	endDateStr := ctx.Request().Input("end_date", time.Now().AddDate(0, 0, 30).Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid start_date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid end_date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	calendar, err := ucc.userCalendarService.GetCalendarWithEvents(calendarID, userID, organizationId, startDate, endDate)
	if err != nil {
		status := 500
		if err.Error() == "calendar not found" {
			status = 404
		}

		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar with events retrieved successfully",
		Data:      calendar,
		Timestamp: time.Now(),
	})
}

// GetStatistics returns calendar statistics
// @Summary Get calendar statistics
// @Description Get statistics for a specific calendar
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param id path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/{id}/statistics [get]
func (ucc *UserCalendarController) GetStatistics(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	calendarID := ctx.Request().Route("id")

	stats, err := ucc.userCalendarService.GetCalendarStatistics(calendarID, userID, organizationId)
	if err != nil {
		status := 500
		if err.Error() == "calendar not found" {
			status = 404
		}

		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar statistics retrieved successfully",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// Search searches calendars
// @Summary Search calendars
// @Description Search calendars by name or description
// @Tags user-calendars
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Success 200 {object} responses.APIResponse{data=[]models.UserCalendar}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /user-calendars/search [get]
func (ucc *UserCalendarController) Search(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)
	query := ctx.Request().Input("q")

	if query == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search query is required",
			Timestamp: time.Now(),
		})
	}

	calendars, err := ucc.userCalendarService.SearchCalendars(userID, organizationId, query)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to search calendars: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar search completed successfully",
		Data:      calendars,
		Timestamp: time.Now(),
	})
}
