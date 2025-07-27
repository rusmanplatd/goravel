package v1

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/services"
)

type CalendarAnalyticsController struct {
	analyticsService *services.CalendarAnalyticsService
}

func NewCalendarAnalyticsController() *CalendarAnalyticsController {
	return &CalendarAnalyticsController{
		analyticsService: services.NewCalendarAnalyticsService(),
	}
}

// GetUserAnalytics returns analytics for a specific user
// @Summary Get user calendar analytics
// @Description Retrieve comprehensive analytics for a user's calendar usage
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/users/{user_id} [get]
func (cac *CalendarAnalyticsController) GetUserAnalytics(ctx http.Context) http.Response {
	userID := ctx.Request().Route("user_id")

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get analytics
	analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user analytics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GetTenantAnalytics returns analytics for a tenant/organization
// @Summary Get tenant calendar analytics
// @Description Retrieve comprehensive analytics for a tenant's calendar usage
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/tenants/{tenant_id} [get]
func (cac *CalendarAnalyticsController) GetTenantAnalytics(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("tenant_id")

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get analytics
	analytics, err := cac.analyticsService.GetTenantAnalytics(tenantID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tenant analytics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GenerateReport generates a comprehensive calendar report
// @Summary Generate calendar report
// @Description Generate a detailed calendar report for users or tenants
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param report_type query string true "Report type: user or tenant" Enums(user,tenant)
// @Param target_id query string true "Target ID (user ID or tenant ID)"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Param format query string false "Report format: json or pdf" Enums(json,pdf) default(json)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/reports [get]
func (cac *CalendarAnalyticsController) GenerateReport(ctx http.Context) http.Response {
	reportType := ctx.Request().Input("report_type", "")
	targetID := ctx.Request().Input("target_id", "")
	format := ctx.Request().Input("format", "json")

	if reportType == "" || targetID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "report_type and target_id are required",
			Timestamp: time.Now(),
		})
	}

	if reportType != "user" && reportType != "tenant" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "report_type must be 'user' or 'tenant'",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Generate report
	report, err := cac.analyticsService.GenerateCalendarReport(reportType, targetID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate report: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Handle different formats
	switch format {
	case "json":
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:    "success",
			Data:      report,
			Timestamp: time.Now(),
		})
	case "pdf":
		// For now, return JSON with a note about PDF generation
		// In a full implementation, you'd generate a PDF here
		report["note"] = "PDF generation not implemented yet. Use format=json for now."
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:    "success",
			Data:      report,
			Timestamp: time.Now(),
		})
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unsupported format. Use 'json' or 'pdf'",
			Timestamp: time.Now(),
		})
	}
}

// GetMeetingEffectivenessReport returns meeting effectiveness metrics
// @Summary Get meeting effectiveness report
// @Description Get detailed meeting effectiveness metrics for analysis
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id query string false "User ID for user-specific report"
// @Param tenant_id query string false "Tenant ID for organization-wide report"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/meeting-effectiveness [get]
func (cac *CalendarAnalyticsController) GetMeetingEffectivenessReport(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	tenantID := ctx.Request().Input("tenant_id", "")

	if userID == "" && tenantID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Either user_id or tenant_id is required",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	var report map[string]interface{}

	if userID != "" {
		// Get user-specific meeting effectiveness
		analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve meeting effectiveness data: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		report = map[string]interface{}{
			"type":            "user",
			"target_id":       userID,
			"meeting_metrics": analytics["meeting_metrics"],
			"period_start":    startDate,
			"period_end":      endDate,
		}
	} else {
		// Get tenant-wide meeting effectiveness
		analytics, err := cac.analyticsService.GetTenantAnalytics(tenantID, startDate, endDate)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve meeting effectiveness data: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		report = map[string]interface{}{
			"type":             "tenant",
			"target_id":        tenantID,
			"meeting_patterns": analytics["meeting_patterns"],
			"overview":         analytics["overview"],
			"period_start":     startDate,
			"period_end":       endDate,
		}
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      report,
		Timestamp: time.Now(),
	})
}

// GetProductivityInsights returns productivity insights based on calendar data
// @Summary Get productivity insights
// @Description Get productivity insights and recommendations based on calendar patterns
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id query string true "User ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/productivity-insights [get]
func (cac *CalendarAnalyticsController) GetProductivityInsights(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "user_id is required",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get user analytics
	analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve productivity insights: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Extract productivity-related data
	insights := map[string]interface{}{
		"user_id":               userID,
		"period_start":          startDate,
		"period_end":            endDate,
		"productivity_insights": analytics["productivity_insights"],
		"time_distribution":     analytics["time_distribution"],
		"collaboration_metrics": analytics["collaboration_metrics"],
	}

	// Add recommendations based on the data
	recommendations := cac.generateProductivityRecommendations(analytics)
	insights["recommendations"] = recommendations

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      insights,
		Timestamp: time.Now(),
	})
}

// Helper methods

func (cac *CalendarAnalyticsController) parseDateRange(ctx http.Context) (time.Time, time.Time, error) {
	// Default to last 30 days
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	// Parse start_date if provided
	if startDateStr := ctx.Request().Input("start_date", ""); startDateStr != "" {
		parsed, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date format. Use YYYY-MM-DD")
		}
		startDate = parsed
	}

	// Parse end_date if provided
	if endDateStr := ctx.Request().Input("end_date", ""); endDateStr != "" {
		parsed, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date format. Use YYYY-MM-DD")
		}
		endDate = parsed
	}

	// Validate date range
	if startDate.After(endDate) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_date must be before end_date")
	}

	// Limit range to prevent excessive queries
	if endDate.Sub(startDate) > 365*24*time.Hour {
		return time.Time{}, time.Time{}, fmt.Errorf("date range cannot exceed 365 days")
	}

	return startDate, endDate, nil
}

func (cac *CalendarAnalyticsController) generateProductivityRecommendations(analytics map[string]interface{}) []map[string]interface{} {
	recommendations := []map[string]interface{}{}

	// Extract productivity insights
	if productivityData, ok := analytics["productivity_insights"].(map[string]interface{}); ok {
		// Check meeting density
		if meetingDensity, ok := productivityData["meeting_density_per_day"].(float64); ok {
			if meetingDensity > 6 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "meeting_overload",
					"priority":    "high",
					"title":       "High Meeting Density Detected",
					"description": "You have more than 6 meetings per day on average. Consider consolidating meetings or declining non-essential ones.",
					"metric":      meetingDensity,
				})
			}
		}

		// Check focus time
		if focusTime, ok := productivityData["avg_focus_time_minutes"].(float64); ok {
			if focusTime < 30 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "low_focus_time",
					"priority":    "medium",
					"title":       "Limited Focus Time",
					"description": "Your average focus time between meetings is less than 30 minutes. Try to block longer periods for deep work.",
					"metric":      focusTime,
				})
			}
		}

		// Check response rate
		if responseRate, ok := productivityData["invitation_response_rate"].(float64); ok {
			if responseRate < 0.8 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "low_response_rate",
					"priority":    "low",
					"title":       "Low Meeting Response Rate",
					"description": "You respond to less than 80% of meeting invitations. Consider improving your meeting response habits.",
					"metric":      responseRate,
				})
			}
		}
	}

	// Check time distribution
	if timeData, ok := analytics["time_distribution"].(map[string]interface{}); ok {
		if timeByType, ok := timeData["time_by_type"].([]interface{}); ok {
			// Look for meeting type imbalances
			var totalMeetingTime float64
			var meetingTypeCount int

			for _, typeData := range timeByType {
				if typeMap, ok := typeData.(map[string]interface{}); ok {
					if minutes, ok := typeMap["total_minutes"].(float64); ok {
						totalMeetingTime += minutes
						meetingTypeCount++
					}
				}
			}

			if meetingTypeCount > 0 && totalMeetingTime > 20*60 { // More than 20 hours per period
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "meeting_time_high",
					"priority":    "medium",
					"title":       "High Meeting Time",
					"description": "You spend significant time in meetings. Consider if all meetings are necessary and look for optimization opportunities.",
					"metric":      totalMeetingTime / 60, // Convert to hours
				})
			}
		}
	}

	return recommendations
}
