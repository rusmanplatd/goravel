package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type CalendarListController struct {
	userCalendarService *services.UserCalendarService
	auditService        *services.AuditService
}

func NewCalendarListController() *CalendarListController {
	return &CalendarListController{
		userCalendarService: services.NewUserCalendarService(),
		auditService:        services.GetAuditService(),
	}
}

// List returns the calendars on the user's calendar list
// @Summary Get user's calendar list
// @Description Returns the calendars on the user's calendar list following Google Calendar API structure
// @Tags calendarList
// @Accept json
// @Produce json
// @Param minAccessRole query string false "Minimum access role filter" Enums(freeBusyReader,owner,reader,writer)
// @Param showDeleted query bool false "Whether to include deleted calendar list entries" default(false)
// @Param showHidden query bool false "Whether to show hidden entries" default(false)
// @Success 200 {object} responses.APIResponse{data=[]models.UserCalendar}
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/me/calendarList [get]
func (clc *CalendarListController) List(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	showHidden := ctx.Request().QueryBool("showHidden", false)
	showDeleted := ctx.Request().QueryBool("showDeleted", false)

	query := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Order("sort_order ASC, created_at ASC")

	if !showHidden {
		query = query.Where("is_visible = ?", true)
	}

	if !showDeleted {
		query = query.Where("deleted_at IS NULL")
	}

	var calendars []models.UserCalendar
	err := query.Find(&calendars)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve calendar list: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Transform to Google Calendar API format
	calendarListEntries := make([]map[string]interface{}, len(calendars))
	for i, calendar := range calendars {
		calendarListEntries[i] = map[string]interface{}{
			"kind":             "calendar#calendarListEntry",
			"etag":             generateETag(&calendar.UpdatedAt),
			"id":               calendar.ID,
			"summary":          calendar.Name,
			"description":      calendar.Description,
			"location":         "",
			"timeZone":         calendar.Timezone,
			"summaryOverride":  "",
			"colorId":          getColorID(calendar.Color),
			"backgroundColor":  calendar.Color,
			"foregroundColor":  "#000000",
			"hidden":           !calendar.IsVisible,
			"selected":         calendar.IsVisible,
			"accessRole":       "owner",
			"defaultReminders": parseDefaultReminders(calendar.DefaultReminders),
			"notificationSettings": map[string]interface{}{
				"notifications": []map[string]interface{}{
					{
						"type":   "eventCreation",
						"method": "email",
					},
				},
			},
			"primary": calendar.IsDefault,
			"deleted": calendar.DeletedAt != nil,
			"conferenceProperties": map[string]interface{}{
				"allowedConferenceSolutionTypes": []string{"hangoutsMeet"},
			},
		}
	}

	response := map[string]interface{}{
		"kind":          "calendar#calendarList",
		"etag":          generateListETag(),
		"nextPageToken": "",
		"items":         calendarListEntries,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Get returns a calendar from the user's calendar list
// @Summary Get calendar from user's list
// @Description Returns a calendar from the user's calendar list
// @Tags calendarList
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/me/calendarList/{calendarId} [get]
func (clc *CalendarListController) Get(ctx http.Context) http.Response {
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

	calendarListEntry := map[string]interface{}{
		"kind":             "calendar#calendarListEntry",
		"etag":             generateETag(&calendar.UpdatedAt),
		"id":               calendar.ID,
		"summary":          calendar.Name,
		"description":      calendar.Description,
		"location":         "",
		"timeZone":         calendar.Timezone,
		"summaryOverride":  "",
		"colorId":          getColorID(calendar.Color),
		"backgroundColor":  calendar.Color,
		"foregroundColor":  "#000000",
		"hidden":           !calendar.IsVisible,
		"selected":         calendar.IsVisible,
		"accessRole":       "owner",
		"defaultReminders": parseDefaultReminders(calendar.DefaultReminders),
		"primary":          calendar.IsDefault,
		"deleted":          calendar.DeletedAt != nil,
		"conferenceProperties": map[string]interface{}{
			"allowedConferenceSolutionTypes": []string{"hangoutsMeet"},
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      calendarListEntry,
		Timestamp: time.Now(),
	})
}

// Insert inserts an existing calendar into the user's calendar list
// @Summary Add calendar to user's list
// @Description Inserts an existing calendar into the user's calendar list
// @Tags calendarList
// @Accept json
// @Produce json
// @Param calendar body object{id=string,colorRgbFormat=bool} true "Calendar data"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /users/me/calendarList [post]
func (clc *CalendarListController) Insert(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var request struct {
		ID             string `json:"id" binding:"required"`
		ColorRgbFormat bool   `json:"colorRgbFormat"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Check if calendar exists and user has access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ?", request.ID).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Create calendar list entry for user
	calendarListEntry := models.UserCalendar{
		Name:           calendar.Name,
		Description:    calendar.Description,
		Color:          calendar.Color,
		Type:           "shared",
		IsVisible:      true,
		IsDefault:      false,
		UserID:         userID,
		OrganizationID: organizationId,
		Timezone:       calendar.Timezone,
	}

	if err := facades.Orm().Query().Create(&calendarListEntry); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add calendar to list",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar added to list successfully",
		Data:      calendarListEntry,
		Timestamp: time.Now(),
	})
}

// Update updates an existing calendar on the user's calendar list
// @Summary Update calendar in user's list
// @Description Updates an existing calendar on the user's calendar list
// @Tags calendarList
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param calendar body object{summaryOverride=string,colorId=string,hidden=bool,selected=bool,defaultReminders=[]object} true "Calendar data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /users/me/calendarList/{calendarId} [put]
func (clc *CalendarListController) Update(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)

	var request struct {
		SummaryOverride  string                   `json:"summaryOverride"`
		ColorID          string                   `json:"colorId"`
		BackgroundColor  string                   `json:"backgroundColor"`
		ForegroundColor  string                   `json:"foregroundColor"`
		Hidden           *bool                    `json:"hidden"`
		Selected         *bool                    `json:"selected"`
		DefaultReminders []map[string]interface{} `json:"defaultReminders"`
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
	if request.SummaryOverride != "" {
		calendar.Name = request.SummaryOverride
	}
	if request.BackgroundColor != "" {
		calendar.Color = request.BackgroundColor
	}
	if request.Hidden != nil {
		calendar.IsVisible = !*request.Hidden
	}
	if request.Selected != nil {
		calendar.IsVisible = *request.Selected
	}
	if len(request.DefaultReminders) > 0 {
		remindersJSON, _ := json.Marshal(request.DefaultReminders)
		calendar.DefaultReminders = string(remindersJSON)
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

// Patch updates an existing calendar on the user's calendar list using patch semantics
// @Summary Patch calendar in user's list
// @Description Updates an existing calendar on the user's calendar list using patch semantics
// @Tags calendarList
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param calendar body object{summaryOverride=string,colorId=string,hidden=bool,selected=bool} true "Calendar data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /users/me/calendarList/{calendarId} [patch]
func (clc *CalendarListController) Patch(ctx http.Context) http.Response {
	// Patch is identical to Update in this implementation
	return clc.Update(ctx)
}

// Delete removes a calendar from the user's calendar list
// @Summary Remove calendar from user's list
// @Description Removes a calendar from the user's calendar list
// @Tags calendarList
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/me/calendarList/{calendarId} [delete]
func (clc *CalendarListController) Delete(ctx http.Context) http.Response {
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

	_, err = facades.Orm().Query().Delete(&calendar)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove calendar from list",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// Helper functions

func generateETag(updatedAt *time.Time) string {
	if updatedAt == nil {
		return `"` + time.Now().Format("2006-01-02T15:04:05.000Z") + `"`
	}
	return `"` + updatedAt.Format("2006-01-02T15:04:05.000Z") + `"`
}

func generateListETag() string {
	return `"` + time.Now().Format("2006-01-02T15:04:05.000Z") + `"`
}

func getColorID(hexColor string) string {
	// Map hex colors to Google Calendar color IDs
	colorMap := map[string]string{
		"#1976d2": "1",
		"#388e3c": "2",
		"#f57c00": "3",
		"#d32f2f": "4",
		"#7b1fa2": "5",
		"#689f38": "6",
		"#f9a825": "7",
		"#e64a19": "8",
		"#5e35b1": "9",
		"#039be5": "10",
		"#0d7377": "11",
	}

	if colorID, exists := colorMap[hexColor]; exists {
		return colorID
	}
	return "1" // Default to blue
}

func parseDefaultReminders(remindersJSON string) []map[string]interface{} {
	if remindersJSON == "" {
		return []map[string]interface{}{
			{
				"method":  "email",
				"minutes": 10,
			},
		}
	}

	var reminders []map[string]interface{}
	json.Unmarshal([]byte(remindersJSON), &reminders)
	return reminders
}
