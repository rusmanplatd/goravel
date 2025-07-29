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

type AnalyticsController struct {
	calendarAnalyticsService *services.CalendarAnalyticsService
	auditService             *services.AuditService
}

func NewAnalyticsController() *AnalyticsController {
	return &AnalyticsController{
		calendarAnalyticsService: services.NewCalendarAnalyticsService(),
		auditService:             services.GetAuditService(),
	}
}

// GetCalendarUsage returns calendar usage statistics
// @Summary Get calendar usage analytics
// @Description Returns comprehensive calendar usage statistics and metrics
// @Tags analytics
// @Accept json
// @Produce json
// @Param timeRange query string false "Time range (7d, 30d, 90d, 1y)" default(30d)
// @Param calendarId query string false "Specific calendar ID for focused analytics"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /analytics/usage [get]
func (ac *AnalyticsController) GetCalendarUsage(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Parse query parameters
	timeRange := ctx.Request().Query("timeRange", "30d")
	calendarID := ctx.Request().Query("calendarId", "")

	// Calculate time bounds
	endTime := time.Now()
	var startTime time.Time

	switch timeRange {
	case "7d":
		startTime = endTime.AddDate(0, 0, -7)
	case "30d":
		startTime = endTime.AddDate(0, 0, -30)
	case "90d":
		startTime = endTime.AddDate(0, 0, -90)
	case "1y":
		startTime = endTime.AddDate(-1, 0, 0)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range. Use: 7d, 30d, 90d, 1y",
			Timestamp: time.Now(),
		})
	}

	// Get user's calendars for filtering
	var userCalendars []models.UserCalendar
	calendarQuery := facades.Orm().Query().Where("user_id = ? AND organization_id = ?", userID, organizationId)
	if calendarID != "" {
		calendarQuery = calendarQuery.Where("id = ?", calendarID)
	}
	calendarQuery.Find(&userCalendars)

	if len(userCalendars) == 0 {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No accessible calendars found",
			Timestamp: time.Now(),
		})
	}

	calendarIDs := make([]string, len(userCalendars))
	for i, cal := range userCalendars {
		calendarIDs[i] = cal.ID
	}

	// Get basic event statistics
	totalEvents, _ := facades.Orm().Query().
		Model(&models.CalendarEvent{}).
		Where("calendar_id IN ? AND created_at BETWEEN ? AND ?", calendarIDs, startTime, endTime).
		Count()

	// Build analytics response
	analytics := map[string]interface{}{
		"kind":      "calendar#analytics",
		"timeRange": timeRange,
		"period": map[string]string{
			"start": startTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		},
		"calendarId": calendarID,
		"metrics": map[string]interface{}{
			"totalEvents": totalEvents,
			"calendars":   len(userCalendars),
			"timeSpan":    fmt.Sprintf("%s to %s", startTime.Format("2006-01-02"), endTime.Format("2006-01-02")),
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar analytics retrieved successfully",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GetEventTrends returns event creation trends
// @Summary Get event trends
// @Description Returns trends in event creation over time
// @Tags analytics
// @Accept json
// @Produce json
// @Param timeRange query string false "Time range for trends" default(30d)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /analytics/trends [get]
func (ac *AnalyticsController) GetEventTrends(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	timeRange := ctx.Request().Query("timeRange", "30d")

	// Calculate time bounds
	endTime := time.Now()
	var startTime time.Time

	switch timeRange {
	case "7d":
		startTime = endTime.AddDate(0, 0, -7)
	case "30d":
		startTime = endTime.AddDate(0, 0, -30)
	case "90d":
		startTime = endTime.AddDate(0, 0, -90)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range",
			Timestamp: time.Now(),
		})
	}

	// Get user's calendars
	var userCalendars []models.UserCalendar
	facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Find(&userCalendars)

	calendarIDs := make([]string, len(userCalendars))
	for i, cal := range userCalendars {
		calendarIDs[i] = cal.ID
	}

	// Get recent events count
	recentEvents, _ := facades.Orm().Query().
		Model(&models.CalendarEvent{}).
		Where("calendar_id IN ? AND created_at BETWEEN ? AND ?", calendarIDs, startTime, endTime).
		Count()

	response := map[string]interface{}{
		"kind":      "calendar#trends",
		"timeRange": timeRange,
		"period": map[string]string{
			"start": startTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		},
		"trends": map[string]interface{}{
			"eventsCreated": recentEvents,
			"timeSpan":      fmt.Sprintf("%s to %s", startTime.Format("2006-01-02"), endTime.Format("2006-01-02")),
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetCalendarInsights returns basic calendar insights
// @Summary Get calendar insights
// @Description Returns basic insights about calendar usage patterns
// @Tags analytics
// @Accept json
// @Produce json
// @Param timeRange query string false "Analysis time range" default(30d)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /analytics/insights [get]
func (ac *AnalyticsController) GetCalendarInsights(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	timeRange := ctx.Request().Query("timeRange", "30d")

	// Calculate time bounds
	endTime := time.Now()
	var startTime time.Time

	switch timeRange {
	case "7d":
		startTime = endTime.AddDate(0, 0, -7)
	case "30d":
		startTime = endTime.AddDate(0, 0, -30)
	case "90d":
		startTime = endTime.AddDate(0, 0, -90)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range",
			Timestamp: time.Now(),
		})
	}

	// Get user's calendars
	var userCalendars []models.UserCalendar
	facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Find(&userCalendars)

	calendarIDs := make([]string, len(userCalendars))
	for i, cal := range userCalendars {
		calendarIDs[i] = cal.ID
	}

	// Get total events for analysis
	totalEvents, _ := facades.Orm().Query().
		Model(&models.CalendarEvent{}).
		Where("calendar_id IN ? AND created_at BETWEEN ? AND ?", calendarIDs, startTime, endTime).
		Count()

	// Generate basic insights
	insights := make([]map[string]interface{}, 0)

	// Insight 1: Event volume
	if totalEvents > 50 {
		insights = append(insights, map[string]interface{}{
			"type":        "productivity",
			"title":       "High Calendar Activity",
			"description": fmt.Sprintf("You have %d events scheduled, indicating high calendar utilization.", totalEvents),
			"severity":    "info",
		})
	} else if totalEvents < 10 {
		insights = append(insights, map[string]interface{}{
			"type":        "productivity",
			"title":       "Low Calendar Activity",
			"description": fmt.Sprintf("You have only %d events scheduled.", totalEvents),
			"severity":    "info",
		})
	}

	// Insight 2: Calendar count
	if len(userCalendars) > 5 {
		insights = append(insights, map[string]interface{}{
			"type":        "organization",
			"title":       "Multiple Calendars",
			"description": fmt.Sprintf("You have %d calendars, which helps organize different aspects of your schedule.", len(userCalendars)),
			"severity":    "info",
		})
	}

	response := map[string]interface{}{
		"kind":      "calendar#insights",
		"timeRange": timeRange,
		"period": map[string]string{
			"start": startTime.Format(time.RFC3339),
			"end":   endTime.Format(time.RFC3339),
		},
		"insights":  insights,
		"generated": time.Now().Format(time.RFC3339),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Calendar insights generated successfully",
		Data:      response,
		Timestamp: time.Now(),
	})
}
