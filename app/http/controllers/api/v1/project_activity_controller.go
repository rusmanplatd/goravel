package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectActivityController struct{}

func NewProjectActivityController() *ProjectActivityController {
	return &ProjectActivityController{}
}

// ListActivities lists all activities for a project
// @Summary List project activities
// @Description Get all activities for a project with filtering and sorting
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {array} models.ActivityLog
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities [get]
func (pac *ProjectActivityController) ListActivities(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var activities []models.ActivityLog

	query := querybuilder.For(&models.ActivityLog{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("action"),
			querybuilder.Exact("entity_type"),
			querybuilder.Exact("user_id"),
			querybuilder.Partial("description"),
		).
		AllowedSorts("action", "entity_type", "created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("subject_type = ? AND subject_id = ?", "Project", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&activities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project activities: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project activities retrieved successfully", result)
}

// CreateActivity creates a new project activity
// @Summary Create project activity
// @Description Create a new activity entry for a project
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectActivityRequest true "Activity data"
// @Success 201 {object} models.ActivityLog
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities [post]
func (pac *ProjectActivityController) CreateActivity(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectActivityRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID (assuming it's available in context)
	userID := ctx.Value("user_id").(string)

	// Create activity log entry
	activity := models.ActivityLog{
		LogName:     request.Action,
		Description: request.Description,
		CauserType:  "User",
		CauserID:    userID,
		SubjectType: "Project",
		SubjectID:   projectID,
		IPAddress:   ctx.Request().Ip(),
		UserAgent:   ctx.Request().Header("User-Agent"),
	}

	// Set optional fields
	if request.Category != "" {
		activity.Category = models.ActivityLogCategory(request.Category)
	} else {
		activity.Category = models.CategorySystem
	}

	if request.Severity != "" {
		activity.Severity = models.ActivityLogSeverity(request.Severity)
	} else {
		activity.Severity = models.SeverityInfo
	}

	if request.Metadata != nil {
		metadataJSON, _ := json.Marshal(request.Metadata)
		activity.Properties = metadataJSON
	}

	if err := facades.Orm().Query().Create(&activity); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project activity: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project activity created successfully",
		Data:      activity,
		Timestamp: time.Now(),
	})
}

// GetActivity retrieves a specific project activity
// @Summary Get project activity
// @Description Get a specific project activity by ID
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param activity_id path string true "Activity ID"
// @Success 200 {object} models.ActivityLog
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities/{activity_id} [get]
func (pac *ProjectActivityController) GetActivity(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	activityID := ctx.Request().Route("activity_id")

	var activity models.ActivityLog
	if err := facades.Orm().Query().
		Where("id = ? AND subject_type = ? AND subject_id = ?", activityID, "Project", projectID).
		First(&activity); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project activity not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project activity retrieved successfully",
		Data:      activity,
		Timestamp: time.Now(),
	})
}

// ListMentions lists all mentions in a project
// @Summary List project mentions
// @Description Get all mentions for users in a project
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {array} models.ActivityLog
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/mentions [get]
func (pac *ProjectActivityController) ListMentions(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var mentions []models.ActivityLog

	query := querybuilder.For(&models.ActivityLog{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("action"),
			querybuilder.Exact("entity_type"),
		).
		AllowedSorts("created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("subject_type = ? AND subject_id = ? AND (log_name = ? OR properties LIKE ?)",
			"Project", projectID, "mention", "%\"mentioned_user\":\""+userID+"\"%")

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&mentions)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project mentions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project mentions retrieved successfully", result)
}

// CreateMention creates a mention activity
// @Summary Create project mention
// @Description Create a mention for a user in a project
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectMentionRequest true "Mention data"
// @Success 201 {object} models.ActivityLog
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/mentions [post]
func (pac *ProjectActivityController) CreateMention(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectMentionRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID
	userID := ctx.Value("user_id").(string)

	// Create mention metadata
	metadata := map[string]interface{}{
		"mentioned_user": request.MentionedUserID,
		"context":        request.Context,
		"item_id":        request.ItemID,
		"comment":        request.Comment,
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Create mention activity
	mention := models.ActivityLog{
		LogName:     "mention",
		Description: request.Description,
		CauserType:  "User",
		CauserID:    userID,
		SubjectType: "Project",
		SubjectID:   projectID,
		Category:    models.CategoryUser,
		Severity:    models.SeverityInfo,
		Properties:  metadataJSON,
		IPAddress:   ctx.Request().Ip(),
		UserAgent:   ctx.Request().Header("User-Agent"),
	}

	if err := facades.Orm().Query().Create(&mention); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project mention: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project mention created successfully",
		Data:      mention,
		Timestamp: time.Now(),
	})
}

// GetActivitySummary gets activity summary for a project
// @Summary Get project activity summary
// @Description Get activity summary with counts and recent activities
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities/summary [get]
func (pac *ProjectActivityController) GetActivitySummary(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Get activity counts by action
	var actionCounts []struct {
		Action string `json:"action"`
		Count  int64  `json:"count"`
	}

	facades.Orm().Query().Model(&models.ActivityLog{}).
		Select("log_name, COUNT(*) as count").
		Where("subject_type = ? AND subject_id = ?", "Project", projectID).
		Group("log_name").
		Scan(&actionCounts)

	// Get recent activities (last 10)
	var recentActivities []models.ActivityLog
	facades.Orm().Query().
		Where("subject_type = ? AND subject_id = ?", "Project", projectID).
		Order("created_at DESC").
		Limit(10).
		Find(&recentActivities)

	// Get total activity count
	totalCount, _ := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("subject_type = ? AND subject_id = ?", "Project", projectID).
		Count()

	// Get unique contributors count
	contributorCount, _ := facades.Orm().Query().Model(&models.ActivityLog{}).
		Select("DISTINCT causer_id").
		Where("subject_type = ? AND subject_id = ?", "Project", projectID).
		Count()

	summary := map[string]interface{}{
		"total_activities":    totalCount,
		"unique_contributors": contributorCount,
		"action_counts":       actionCounts,
		"recent_activities":   recentActivities,
		"project_id":          projectID,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project activity summary retrieved successfully",
		Data:      summary,
		Timestamp: time.Now(),
	})
}

// GetUserActivityFeed gets personalized activity feed for a user in a project
// @Summary Get user activity feed
// @Description Get personalized activity feed for the current user in a project
// @Tags project-activity
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {array} models.ActivityLog
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities/feed [get]
func (pac *ProjectActivityController) GetUserActivityFeed(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var feedActivities []models.ActivityLog

	// Get activities related to the user (their actions, mentions, assignments, etc.)
	query := querybuilder.For(&models.ActivityLog{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("action"),
			querybuilder.Exact("entity_type"),
		).
		AllowedSorts("created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("subject_type = ? AND subject_id = ? AND (causer_id = ? OR properties LIKE ?)",
			"Project", projectID, userID, "%\"mentioned_user\":\""+userID+"\"%")

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&feedActivities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user activity feed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "User activity feed retrieved successfully", result)
}
