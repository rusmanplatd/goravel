package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type SettingsController struct {
	calendarPreferenceService *services.CalendarPreferenceService
	auditService              *services.AuditService
}

func NewSettingsController() *SettingsController {
	return &SettingsController{
		calendarPreferenceService: services.NewCalendarPreferenceService(),
		auditService:              services.GetAuditService(),
	}
}

// List returns all user settings
// @Summary Get all user settings
// @Description Returns all user settings for the authenticated user
// @Tags settings
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/me/settings [get]
func (sc *SettingsController) List(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Get user's calendar preferences
	var preferences models.CalendarPreference
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		First(&preferences)

	if err != nil {
		// Create default preferences if none exist
		preferences = models.CalendarPreference{
			UserID:               userID,
			OrganizationID:       organizationId,
			DefaultView:          "week",
			WeekStartsOn:         1,
			DefaultEventDuration: 60,
			WorkingHoursStart:    "09:00",
			WorkingHoursEnd:      "17:00",
			WorkingDays:          "[1,2,3,4,5]",
			TimeFormat:           "24h",
			DateFormat:           "YYYY-MM-DD",
			Timezone:             "UTC",
			Language:             "en-US",
			ShowWeekends:         true,
			ShowDeclinedEvents:   false,
		}
		facades.Orm().Query().Create(&preferences)
	}

	// Transform to Google Calendar API format
	settings := []map[string]interface{}{
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "defaultView",
			"value": preferences.DefaultView,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "weekStart",
			"value": preferences.WeekStartsOn,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "defaultEventLength",
			"value": preferences.DefaultEventDuration,
		},
		{
			"kind": "calendar#setting",
			"etag": generateETag(&preferences.UpdatedAt),
			"id":   "workingHours",
			"value": map[string]interface{}{
				"start": preferences.WorkingHoursStart,
				"end":   preferences.WorkingHoursEnd,
				"days":  preferences.WorkingDays,
			},
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "format24HourTime",
			"value": preferences.TimeFormat == "24h",
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "dateFormat",
			"value": preferences.DateFormat,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "timezone",
			"value": preferences.Timezone,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "locale",
			"value": preferences.Language,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "showWeekends",
			"value": preferences.ShowWeekends,
		},
		{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "showDeclinedEvents",
			"value": preferences.ShowDeclinedEvents,
		},
	}

	response := map[string]interface{}{
		"kind":  "calendar#settings",
		"etag":  generateListETag(),
		"items": settings,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Get returns a single user setting
// @Summary Get user setting
// @Description Returns a single user setting by ID
// @Tags settings
// @Accept json
// @Produce json
// @Param setting path string true "Setting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/me/settings/{setting} [get]
func (sc *SettingsController) Get(ctx http.Context) http.Response {
	settingID := ctx.Request().Route("setting")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Get user's calendar preferences
	var preferences models.CalendarPreference
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		First(&preferences)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Settings not found",
			Timestamp: time.Now(),
		})
	}

	var setting map[string]interface{}

	switch settingID {
	case "defaultView":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "defaultView",
			"value": preferences.DefaultView,
		}
	case "weekStart":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "weekStart",
			"value": preferences.WeekStartsOn,
		}
	case "defaultEventLength":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "defaultEventLength",
			"value": preferences.DefaultEventDuration,
		}
	case "format24HourTime":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "format24HourTime",
			"value": preferences.TimeFormat == "24h",
		}
	case "timezone":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "timezone",
			"value": preferences.Timezone,
		}
	case "locale":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "locale",
			"value": preferences.Language,
		}
	case "showWeekends":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "showWeekends",
			"value": preferences.ShowWeekends,
		}
	case "showDeclinedEvents":
		setting = map[string]interface{}{
			"kind":  "calendar#setting",
			"etag":  generateETag(&preferences.UpdatedAt),
			"id":    "showDeclinedEvents",
			"value": preferences.ShowDeclinedEvents,
		}
	default:
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Setting not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      setting,
		Timestamp: time.Now(),
	})
}

// UpdateSetting updates a user setting
// @Summary Update user setting
// @Description Updates a specific user setting
// @Tags settings
// @Accept json
// @Produce json
// @Param setting path string true "Setting ID"
// @Param value body object{value=interface{}} true "Setting value"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /users/me/settings/{setting} [put]
func (sc *SettingsController) UpdateSetting(ctx http.Context) http.Response {
	settingID := ctx.Request().Route("setting")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var request struct {
		Value interface{} `json:"value" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Get user's calendar preferences
	var preferences models.CalendarPreference
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		First(&preferences)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Settings not found",
			Timestamp: time.Now(),
		})
	}

	// Update the specific setting
	switch settingID {
	case "defaultView":
		if value, ok := request.Value.(string); ok {
			preferences.DefaultView = value
		}
	case "weekStart":
		if value, ok := request.Value.(float64); ok {
			preferences.WeekStartsOn = int(value)
		}
	case "defaultEventLength":
		if value, ok := request.Value.(float64); ok {
			preferences.DefaultEventDuration = int(value)
		}
	case "format24HourTime":
		if value, ok := request.Value.(bool); ok {
			if value {
				preferences.TimeFormat = "24h"
			} else {
				preferences.TimeFormat = "12h"
			}
		}
	case "timezone":
		if value, ok := request.Value.(string); ok {
			preferences.Timezone = value
		}
	case "locale":
		if value, ok := request.Value.(string); ok {
			preferences.Language = value
		}
	case "showWeekends":
		if value, ok := request.Value.(bool); ok {
			preferences.ShowWeekends = value
		}
	case "showDeclinedEvents":
		if value, ok := request.Value.(bool); ok {
			preferences.ShowDeclinedEvents = value
		}
	default:
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Setting not found",
			Timestamp: time.Now(),
		})
	}

	if err := facades.Orm().Query().Save(&preferences); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update setting",
			Timestamp: time.Now(),
		})
	}

	// Return updated setting
	return sc.Get(ctx)
}
