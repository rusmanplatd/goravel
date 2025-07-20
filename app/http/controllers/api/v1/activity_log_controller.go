package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ActivityLogController struct {
	activityLogger *models.ActivityLogger
}

func NewActivityLogController() *ActivityLogController {
	return &ActivityLogController{
		activityLogger: models.NewActivityLogger(),
	}
}

// Index returns all activity logs for a tenant
// @Summary Get all activity logs
// @Description Retrieve a list of all activity logs with cursor-based pagination
// @Tags activity-logs
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ActivityLog}
// @Failure 500 {object} responses.ErrorResponse
// @Router /activity-logs [get]
func (alc *ActivityLogController) Index(ctx http.Context) http.Response {
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Tenant context required",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)

	// Build query
	query := facades.Orm().Query().Where("tenant_id = ?", tenantID)

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
			Message:   "Failed to retrieve activity logs",
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
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Show returns a specific activity log
func (alc *ActivityLogController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var activity models.ActivityLog
	err := facades.Orm().Query().
		Where("id = ? AND tenant_id = ?", id, tenantID).
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
	tenantID := ctx.Value("tenant_id")

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
		Where("subject_type = ? AND subject_id = ? AND tenant_id = ?", subjectType, subjectID, tenantID)

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
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
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
	tenantID := ctx.Value("tenant_id")

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
		Where("causer_type = ? AND causer_id = ? AND tenant_id = ?", causerType, causerID, tenantID)

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
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
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
	tenantID := ctx.Value("tenant_id")

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
		Where("log_name = ? AND tenant_id = ?", logName, tenantID)

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
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
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
	tenantID := ctx.Value("tenant_id")

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
		Where("created_at BETWEEN ? AND ? AND tenant_id = ?", startDate, endDate, tenantID)

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
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Store creates a new activity log entry
func (alc *ActivityLogController) Store(ctx http.Context) http.Response {
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Tenant context required",
		})
	}

	var request struct {
		LogName     string                 `json:"log_name"`
		Description string                 `json:"description"`
		SubjectType string                 `json:"subject_type"`
		SubjectID   string                 `json:"subject_id"`
		CauserType  string                 `json:"causer_type"`
		CauserID    string                 `json:"causer_id"`
		Properties  map[string]interface{} `json:"properties"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	activity := &models.ActivityLog{
		LogName:     request.LogName,
		Description: request.Description,
		SubjectType: request.SubjectType,
		SubjectID:   request.SubjectID,
		CauserType:  request.CauserType,
		CauserID:    request.CauserID,
		TenantID:    tenantID.(string),
	}

	// Set properties if provided
	if request.Properties != nil {
		propsJSON, err := json.Marshal(request.Properties)
		if err != nil {
			return ctx.Response().Status(500).Json(http.Json{
				"error": "Failed to marshal properties",
			})
		}
		activity.Properties = propsJSON
	}

	err := facades.Orm().Query().Create(activity)
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
