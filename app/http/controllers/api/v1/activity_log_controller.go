package v1

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
	"goravel/app/services"
)

type ActivityLogController struct {
	activityLogger   *models.ActivityLogger
	analyticsService *services.AuditAnalyticsService
}

func NewActivityLogController() *ActivityLogController {
	return &ActivityLogController{
		activityLogger:   models.NewActivityLogger(),
		analyticsService: services.NewAuditAnalyticsService(),
	}
}

// Index returns all activity logs for the current organization
// @Summary Get all activity logs
// @Description Retrieve a list of all activity logs for the current organization with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[log_name] query string false "Filter by log name (partial match)"
// @Param filter[category] query string false "Filter by category"
// @Param filter[severity] query string false "Filter by severity level"
// @Param filter[status] query string false "Filter by status"
// @Param filter[subject_type] query string false "Filter by subject type"
// @Param filter[subject_id] query string false "Filter by subject ID"
// @Param filter[causer_type] query string false "Filter by causer type"
// @Param filter[causer_id] query string false "Filter by causer ID"
// @Param filter[ip_address] query string false "Filter by IP address"
// @Param filter[risk_score_min] query int false "Minimum risk score"
// @Param filter[risk_score_max] query int false "Maximum risk score"
// @Param filter[date_from] query string false "Start date (YYYY-MM-DD)"
// @Param filter[date_to] query string false "End date (YYYY-MM-DD)"
// @Param search query string false "Search in description and properties"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-event_timestamp")
// @Param include query string false "Include relationships (comma-separated): causer_user,subject_user,organization"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.ActivityLog}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs [get]
func (alc *ActivityLogController) Index(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog

	// Create query builder with organization context and allowed filters, sorts, and includes
	qb := querybuilder.For(&models.ActivityLog{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("log_name"),
			querybuilder.Exact("category"),
			querybuilder.Exact("severity"),
			querybuilder.Exact("status"),
			querybuilder.Exact("subject_type"),
			querybuilder.Exact("subject_id"),
			querybuilder.Exact("causer_type"),
			querybuilder.Exact("causer_id"),
			querybuilder.Exact("ip_address"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("log_name", "category", "severity", "status", "subject_type", "causer_type", "event_timestamp", "created_at", "risk_score").
		AllowedIncludes("causer_user", "subject_user", "organization").
		DefaultSort("-event_timestamp")

	// Apply organization constraint to the base query
	query := qb.Build().Where("organization_id = ?", organizationId)

	// Apply search if provided
	if searchTerm := ctx.Request().Query("search", ""); searchTerm != "" {
		query = query.Where("description LIKE ? OR properties LIKE ?", "%"+searchTerm+"%", "%"+searchTerm+"%")
	}

	// Create a new query builder with the constrained query
	constrainedQB := querybuilder.For(query).WithRequest(ctx)

	// Use AutoPaginate for unified pagination support
	result, err := constrainedQB.AutoPaginate(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activity logs: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Activity logs retrieved successfully", result)
}

// Show returns a specific activity log
// @Summary Get activity log by ID
// @Description Retrieve a specific activity log by its ID
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param id path string true "Activity Log ID"
// @Success 200 {object} http.Json{data=models.ActivityLog}
// @Failure 404 {object} http.Json{error=string}
// @Router /activity-logs/{id} [get]
func (alc *ActivityLogController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	organizationId := ctx.Value("organization_id")

	var activity models.ActivityLog
	err := facades.Orm().Query().
		Where("id = ? AND organization_id = ?", id, organizationId).
		With("CauserUser").
		With("SubjectUser").
		With("Organization").
		First(&activity)

	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Activity log not found",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": activity,
	})
}

// Dashboard returns dashboard metrics for activity logs
// @Summary Get activity log dashboard metrics
// @Description Retrieve comprehensive dashboard metrics for activity logs
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param time_range query string false "Time range: 1h, 24h, 7d, 30d" default("24h")
// @Success 200 {object} http.Json{data=services.DashboardMetrics}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/dashboard [get]
func (alc *ActivityLogController) Dashboard(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	// Parse time range
	timeRangeStr := ctx.Request().Query("time_range", "24h")
	timeRange, err := alc.parseTimeRange(timeRangeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get dashboard metrics
	metrics, err := alc.analyticsService.GetDashboardMetrics(organizationId.(string), timeRange)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve dashboard metrics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data":         metrics,
		"time_range":   timeRangeStr,
		"generated_at": time.Now(),
	})
}

// Analytics returns advanced analytics for activity logs
// @Summary Get activity log analytics
// @Description Retrieve advanced analytics and insights for activity logs
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param time_range query string false "Time range: 1h, 24h, 7d, 30d" default("7d")
// @Param analysis_type query string false "Analysis type: trends, patterns, anomalies, threats" default("trends")
// @Success 200 {object} http.Json{data=interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/analytics [get]
func (alc *ActivityLogController) Analytics(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	// Parse parameters
	timeRangeStr := ctx.Request().Query("time_range", "7d")
	analysisType := ctx.Request().Query("analysis_type", "trends")

	timeRange, err := alc.parseTimeRange(timeRangeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	var data interface{}
	var analysisName string

	switch analysisType {
	case "anomalies":
		anomalies, err := alc.analyticsService.DetectAnomalies(organizationId.(string), timeRange)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to detect anomalies: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		data = anomalies
		analysisName = "Anomaly Detection Results"

	case "threats":
		report, err := alc.analyticsService.GenerateThreatIntelligenceReport(organizationId.(string), timeRange)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to generate threat report: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		data = report
		analysisName = "Threat Intelligence Report"

	case "patterns":
		patterns, err := alc.getActivityPatterns(organizationId.(string), timeRange)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to analyze patterns: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		data = patterns
		analysisName = "Activity Pattern Analysis"

	case "trends":
		fallthrough
	default:
		trends, err := alc.getActivityTrends(organizationId.(string), timeRange)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to analyze trends: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		data = trends
		analysisName = "Activity Trend Analysis"
	}

	return ctx.Response().Success().Json(http.Json{
		"data":          data,
		"analysis_type": analysisType,
		"analysis_name": analysisName,
		"time_range":    timeRangeStr,
		"generated_at":  time.Now(),
	})
}

// SecurityAlerts returns security-related alerts and incidents
// @Summary Get security alerts
// @Description Retrieve security alerts and incidents from activity logs
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param severity query string false "Filter by severity: low, medium, high, critical"
// @Param status query string false "Filter by status: open, investigating, resolved"
// @Param limit query int false "Number of alerts to return" default(50)
// @Success 200 {object} http.Json{data=[]services.SecurityAlert}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/security-alerts [get]
func (alc *ActivityLogController) SecurityAlerts(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	// Parse parameters
	severity := ctx.Request().Query("severity", "")
	status := ctx.Request().Query("status", "")
	limit := ctx.Request().QueryInt("limit", 50)

	// Build query for security alerts
	query := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND (risk_score > 70 OR severity IN (?, ?) OR category = ?)",
			organizationId, models.SeverityHigh, models.SeverityCritical, models.CategorySecurity)

	// Apply filters
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// Get activities
	var activities []models.ActivityLog
	err := query.OrderBy("event_timestamp DESC").Limit(limit).Find(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve security alerts: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert to security alerts format
	var alerts []map[string]interface{}
	for _, activity := range activities {
		alert := map[string]interface{}{
			"id":           activity.ID,
			"event_type":   activity.LogName,
			"description":  activity.Description,
			"severity":     activity.Severity,
			"risk_score":   activity.RiskScore,
			"user_id":      activity.SubjectID,
			"ip_address":   activity.IPAddress,
			"timestamp":    activity.EventTimestamp,
			"status":       status, // Default or filtered status
			"category":     activity.Category,
			"threat_level": activity.ThreatLevel,
		}

		// Parse properties for additional context
		if activity.Properties != nil {
			var properties map[string]interface{}
			if err := json.Unmarshal(activity.Properties, &properties); err == nil {
				alert["properties"] = properties
			}
		}

		alerts = append(alerts, alert)
	}

	return ctx.Response().Success().Json(http.Json{
		"data":  alerts,
		"count": len(alerts),
		"filters": map[string]string{
			"severity": severity,
			"status":   status,
		},
		"generated_at": time.Now(),
	})
}

// Stats returns statistical summary of activity logs
// @Summary Get activity log statistics
// @Description Retrieve statistical summary and metrics for activity logs
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param time_range query string false "Time range: 1h, 24h, 7d, 30d" default("24h")
// @Success 200 {object} http.Json{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/stats [get]
func (alc *ActivityLogController) Stats(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	// Parse time range
	timeRangeStr := ctx.Request().Query("time_range", "24h")
	timeRange, err := alc.parseTimeRange(timeRangeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get statistics from activity logger
	stats, err := alc.activityLogger.GetActivityStats(organizationId.(string), timeRange.StartTime)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve statistics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Add additional computed statistics
	additionalStats, err := alc.getAdditionalStats(organizationId.(string), timeRange)
	if err == nil {
		for key, value := range additionalStats {
			stats[key] = value
		}
	}

	return ctx.Response().Success().Json(http.Json{
		"data":       stats,
		"time_range": timeRangeStr,
		"period": map[string]interface{}{
			"start": timeRange.StartTime,
			"end":   timeRange.EndTime,
		},
		"generated_at": time.Now(),
	})
}

// Export exports activity logs in various formats
// @Summary Export activity logs
// @Description Export activity logs in CSV, JSON, or XML format
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param format query string false "Export format: csv, json, xml" default("csv")
// @Param time_range query string false "Time range: 1h, 24h, 7d, 30d" default("24h")
// @Param filter[category] query string false "Filter by category"
// @Param filter[severity] query string false "Filter by severity level"
// @Success 200 {object} http.Json{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/export [get]
func (alc *ActivityLogController) Export(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	// Parse parameters
	format := ctx.Request().Query("format", "csv")
	timeRangeStr := ctx.Request().Query("time_range", "24h")
	category := ctx.Request().Query("filter[category]", "")
	severity := ctx.Request().Query("filter[severity]", "")

	// Validate format
	if format != "csv" && format != "json" && format != "xml" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid export format. Supported formats: csv, json, xml",
			Timestamp: time.Now(),
		})
	}

	timeRange, err := alc.parseTimeRange(timeRangeStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid time range: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Build query
	query := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationId, timeRange.StartTime, timeRange.EndTime)

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// Get activities
	var activities []models.ActivityLog
	err = query.OrderBy("event_timestamp DESC").Limit(10000).Find(&activities) // Limit for performance
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activities for export: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Generate export data
	exportData, contentType, err := alc.generateExportData(activities, format)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate export data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// For API response, return metadata about the export
	exportInfo := map[string]interface{}{
		"format":       format,
		"count":        len(activities),
		"time_range":   timeRangeStr,
		"content_type": contentType,
		"size_bytes":   len(exportData),
		"generated_at": time.Now(),
		"filters": map[string]string{
			"category": category,
			"severity": severity,
		},
	}

	// In a real implementation, you might want to:
	// 1. Save the export to a file and return a download URL
	// 2. Stream the data directly as a file download
	// 3. Queue the export as a background job for large datasets

	return ctx.Response().Success().Json(http.Json{
		"data":    exportInfo,
		"message": "Export generated successfully",
	})
}

// GetActivitiesForSubject returns activities for a specific subject
// @Summary Get activities for subject
// @Description Retrieve activities for a specific subject with cursor-based pagination
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param subject_type query string true "Subject type"
// @Param subject_id query string true "Subject ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ActivityLog}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/subject [get]
func (alc *ActivityLogController) GetActivitiesForSubject(ctx http.Context) http.Response {
	subjectType := ctx.Request().Query("subject_type", "")
	subjectID := ctx.Request().Query("subject_id", "")
	organizationId := ctx.Value("organization_id")

	if subjectType == "" || subjectID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Subject type and subject ID are required",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)

	// Build query
	query := facades.Orm().Query().
		Where("subject_type = ? AND subject_id = ? AND organization_id = ?", subjectType, subjectID, organizationId)

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog
	err = query.Find(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activities",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(activities) > limit
	if hasMore {
		activities = activities[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(activities, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   activities,
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

// GetActivitiesForCauser returns activities caused by a specific user
// @Summary Get activities for causer
// @Description Retrieve activities caused by a specific user with cursor-based pagination
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param causer_type query string true "Causer type"
// @Param causer_id query string true "Causer ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ActivityLog}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/causer [get]
func (alc *ActivityLogController) GetActivitiesForCauser(ctx http.Context) http.Response {
	causerType := ctx.Request().Query("causer_type", "")
	causerID := ctx.Request().Query("causer_id", "")
	organizationId := ctx.Value("organization_id")

	if causerType == "" || causerID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Causer type and causer ID are required",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)

	// Build query
	query := facades.Orm().Query().
		Where("causer_type = ? AND causer_id = ? AND organization_id = ?", causerType, causerID, organizationId)

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog
	err = query.Find(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activities",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(activities) > limit
	if hasMore {
		activities = activities[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(activities, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   activities,
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

// GetActivitiesByLogName returns activities by log name
// @Summary Get activities by log name
// @Description Retrieve activities by log name with cursor-based pagination
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param log_name query string true "Log name"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ActivityLog}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/log-name [get]
func (alc *ActivityLogController) GetActivitiesByLogName(ctx http.Context) http.Response {
	logName := ctx.Request().Query("log_name", "")
	organizationId := ctx.Value("organization_id")

	if logName == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Log name is required",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)

	// Build query
	query := facades.Orm().Query().
		Where("log_name = ? AND organization_id = ?", logName, organizationId)

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog
	err = query.Find(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activities",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(activities) > limit
	if hasMore {
		activities = activities[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(activities, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   activities,
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

// GetActivitiesInDateRange returns activities within a date range
// @Summary Get activities in date range
// @Description Retrieve activities within a date range with cursor-based pagination
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param start_date query string true "Start date (YYYY-MM-DD)"
// @Param end_date query string true "End date (YYYY-MM-DD)"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ActivityLog}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs/date-range [get]
func (alc *ActivityLogController) GetActivitiesInDateRange(ctx http.Context) http.Response {
	startDateStr := ctx.Request().Query("start_date", "")
	endDateStr := ctx.Request().Query("end_date", "")
	organizationId := ctx.Value("organization_id")

	if startDateStr == "" || endDateStr == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Start date and end date are required",
			Timestamp: time.Now(),
		})
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid start date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid end date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)

	// Build query
	query := facades.Orm().Query().
		Where("event_timestamp BETWEEN ? AND ? AND organization_id = ?", startDate, endDate, organizationId)

	// Apply cursor-based pagination
	query, err = helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog
	err = query.Find(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve activities",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(activities) > limit
	if hasMore {
		activities = activities[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(activities, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   activities,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringPtr(paginationInfo, "next_cursor"),
			PrevCursor: getStringPtr(paginationInfo, "prev_cursor"),

			HasPrev: getBoolValue(paginationInfo, "has_prev"),
			Count:   getIntValue(paginationInfo, "count"),
			Limit:   getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Store creates a new activity log entry
// @Summary Create a new activity log
// @Description Create a new activity log entry for a organization
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param activity_log body models.ActivityLog true "Activity log data"
// @Success 201 {object} http.Json{data=models.ActivityLog,message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} http.Json{error=string}
// @Router /activity-logs [post]
func (alc *ActivityLogController) Store(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Organization context required",
		})
	}

	var request struct {
		LogName     string                 `json:"log_name"`
		Description string                 `json:"description"`
		Category    string                 `json:"category"`
		Severity    string                 `json:"severity"`
		Status      string                 `json:"status"`
		SubjectType string                 `json:"subject_type"`
		SubjectID   string                 `json:"subject_id"`
		CauserType  string                 `json:"causer_type"`
		CauserID    string                 `json:"causer_id"`
		Properties  map[string]interface{} `json:"properties"`
		Tags        []string               `json:"tags"`
		RiskScore   int                    `json:"risk_score"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	activity := &models.ActivityLog{
		LogName:        request.LogName,
		Description:    request.Description,
		Category:       models.ActivityLogCategory(request.Category),
		Severity:       models.ActivityLogSeverity(request.Severity),
		Status:         models.ActivityLogStatus(request.Status),
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		CauserType:     request.CauserType,
		CauserID:       request.CauserID,
		RiskScore:      request.RiskScore,
		EventTimestamp: time.Now(),
		OrganizationID: organizationId.(string),
	}

	// Set properties if provided
	if request.Properties != nil {
		if err := activity.SetPropertiesMap(request.Properties); err != nil {
			return ctx.Response().Status(500).Json(http.Json{
				"error": "Failed to set properties",
			})
		}
	}

	// Set tags if provided
	if request.Tags != nil {
		if err := activity.SetTagsSlice(request.Tags); err != nil {
			return ctx.Response().Status(500).Json(http.Json{
				"error": "Failed to set tags",
			})
		}
	}

	err := alc.activityLogger.LogActivity(activity)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to create activity log",
		})
	}

	return ctx.Response().Status(201).Json(http.Json{
		"data":    activity,
		"message": "Activity log created successfully",
	})
}

// Helper methods

func (alc *ActivityLogController) parseTimeRange(timeRangeStr string) (services.TimeRange, error) {
	now := time.Now()
	var startTime time.Time

	switch timeRangeStr {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
	case "24h":
		startTime = now.Add(-24 * time.Hour)
	case "7d":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		return services.TimeRange{}, fmt.Errorf("unsupported time range: %s", timeRangeStr)
	}

	return services.TimeRange{
		StartTime: startTime,
		EndTime:   now,
	}, nil
}

func (alc *ActivityLogController) getActivityTrends(organizationId string, timeRange services.TimeRange) (map[string]interface{}, error) {
	// This would implement trend analysis
	// For now, return basic trend data
	var results []struct {
		Hour  int   `json:"hour"`
		Count int64 `json:"count"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("HOUR(event_timestamp) as hour, COUNT(*) as count").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationId, timeRange.StartTime, timeRange.EndTime).
		Group("HOUR(event_timestamp)").
		OrderBy("hour ASC").
		Find(&results)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hourly_distribution": results,
		"analysis_type":       "hourly_trends",
		"period":              "hourly",
	}, nil
}

func (alc *ActivityLogController) getActivityPatterns(organizationId string, timeRange services.TimeRange) (map[string]interface{}, error) {
	// This would implement pattern analysis
	// For now, return basic pattern data
	var userPatterns []struct {
		SubjectID string `json:"subject_id"`
		Count     int64  `json:"count"`
		Pattern   string `json:"pattern"`
	}

	err := facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("subject_id, COUNT(*) as count, 'frequent_user' as pattern").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND subject_id IS NOT NULL",
			organizationId, timeRange.StartTime, timeRange.EndTime).
		Group("subject_id").
		Having("count > 100").
		OrderBy("count DESC").
		Limit(20).
		Find(&userPatterns)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"user_patterns": userPatterns,
		"analysis_type": "behavioral_patterns",
		"pattern_types": []string{"frequent_user", "unusual_access", "bulk_operations"},
	}, nil
}

func (alc *ActivityLogController) getAdditionalStats(organizationId string, timeRange services.TimeRange) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Unique users count
	var uniqueUsers int64
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("COUNT(DISTINCT subject_id)").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND subject_id IS NOT NULL",
			organizationId, timeRange.StartTime, timeRange.EndTime).
		Pluck("unique_users", &uniqueUsers)
	stats["unique_users"] = uniqueUsers

	// Unique IPs count
	var uniqueIPs int64
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("COUNT(DISTINCT ip_address)").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ? AND ip_address IS NOT NULL",
			organizationId, timeRange.StartTime, timeRange.EndTime).
		Pluck("unique_ips", &uniqueIPs)
	stats["unique_ips"] = uniqueIPs

	// Average risk score
	var avgRiskScore float64
	facades.Orm().Query().
		Model(&models.ActivityLog{}).
		Select("AVG(risk_score)").
		Where("organization_id = ? AND event_timestamp BETWEEN ? AND ?",
			organizationId, timeRange.StartTime, timeRange.EndTime).
		Pluck("avg_risk_score", &avgRiskScore)
	stats["average_risk_score"] = avgRiskScore

	return stats, nil
}

func (alc *ActivityLogController) generateExportData(activities []models.ActivityLog, format string) ([]byte, string, error) {
	switch format {
	case "json":
		data, err := json.MarshalIndent(activities, "", "  ")
		return data, "application/json", err

	case "csv":
		// Implement CSV generation
		var csvData strings.Builder
		csvData.WriteString("ID,LogName,Description,Category,Severity,Status,SubjectID,CauserID,IPAddress,EventTimestamp,RiskScore\n")

		for _, activity := range activities {
			csvData.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s",%d`,
				activity.ID,
				activity.LogName,
				strings.ReplaceAll(activity.Description, `"`, `""`),
				activity.Category,
				activity.Severity,
				activity.Status,
				activity.SubjectID,
				activity.CauserID,
				activity.IPAddress,
				activity.EventTimestamp.Format("2006-01-02 15:04:05"),
				activity.RiskScore,
			))
			csvData.WriteString("\n")
		}

		return []byte(csvData.String()), "text/csv", nil

	case "xml":
		// Implement basic XML generation
		var xmlData strings.Builder
		xmlData.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
		xmlData.WriteString("\n<activities>\n")

		for _, activity := range activities {
			xmlData.WriteString("  <activity>\n")
			xmlData.WriteString(fmt.Sprintf("    <id>%s</id>\n", activity.ID))
			xmlData.WriteString(fmt.Sprintf("    <log_name>%s</log_name>\n", activity.LogName))
			xmlData.WriteString(fmt.Sprintf("    <description><![CDATA[%s]]></description>\n", activity.Description))
			xmlData.WriteString(fmt.Sprintf("    <category>%s</category>\n", activity.Category))
			xmlData.WriteString(fmt.Sprintf("    <severity>%s</severity>\n", activity.Severity))
			xmlData.WriteString(fmt.Sprintf("    <event_timestamp>%s</event_timestamp>\n", activity.EventTimestamp.Format("2006-01-02T15:04:05Z")))
			xmlData.WriteString("  </activity>\n")
		}

		xmlData.WriteString("</activities>")
		return []byte(xmlData.String()), "application/xml", nil

	default:
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}
}

// Utility functions for pagination helpers (these functions are already defined elsewhere)
