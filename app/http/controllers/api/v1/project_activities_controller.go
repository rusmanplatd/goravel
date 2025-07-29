package v1

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectActivitiesController struct{}

func NewProjectActivitiesController() *ProjectActivitiesController {
	return &ProjectActivitiesController{}
}

// ListActivities lists all activities for a project
// @Summary List project activities
// @Description Get all activities for a project (GitHub Projects v2 style activity feed)
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Param action query string false "Filter by activity action"
// @Param user_id query string false "Filter by user ID"
// @Success 200 {array} models.ActivityLog
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities [get]
func (pac *ProjectActivitiesController) ListActivities(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var activities []models.ActivityLog

	query := querybuilder.For(&models.ActivityLog{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("log_name"),
			querybuilder.Exact("causer_id"),
			querybuilder.Exact("subject_type"),
			querybuilder.Exact("category"),
			querybuilder.Exact("severity"),
		).
		AllowedSorts("created_at", "log_name", "severity").
		DefaultSort("-created_at").
		AllowedIncludes("causer_user").
		Build().
		Where("subject_id = ? AND subject_type = ?", projectID, "Project")

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
// @Description Create a new activity log entry for a project
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectActivityRequest true "Activity data"
// @Success 201 {object} models.ActivityLog
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/activities [post]
func (pac *ProjectActivitiesController) CreateActivity(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request requests.ProjectActivityRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert metadata to JSON
	var propertiesJSON json.RawMessage
	if request.Metadata != nil {
		jsonBytes, err := json.Marshal(request.Metadata)
		if err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid metadata format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		propertiesJSON = jsonBytes
	}

	// Create activity log entry
	activity := models.ActivityLog{
		LogName:     request.Action,
		Description: request.Description,
		Category:    models.ActivityLogCategory(request.Category),
		Severity:    models.ActivityLogSeverity(request.Severity),
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
		Properties:  propertiesJSON,
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

// CreateMention creates a mention in a project
// @Summary Create project mention
// @Description Create a mention of a user in a project context (GitHub Projects v2 style)
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectMentionRequest true "Mention data"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/mentions [post]
func (pac *ProjectActivitiesController) CreateMention(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request requests.ProjectMentionRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create metadata for the mention
	metadata := map[string]interface{}{
		"mentioned_user_id": request.MentionedUserID,
		"context":           request.Context,
		"item_id":           request.ItemID,
		"comment":           request.Comment,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create mention metadata: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create activity for the mention
	mentionActivity := models.ActivityLog{
		LogName:     "user_mentioned",
		Description: request.Description,
		Category:    models.CategoryUser, // Use the constant from models
		Severity:    models.SeverityInfo,
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
		Properties:  metadataJSON,
	}

	if err := facades.Orm().Query().Create(&mentionActivity); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create mention: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// TODO: Send notification to mentioned user
	// This would integrate with the notification system

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:  "success",
		Message: "User mentioned successfully",
		Data: map[string]interface{}{
			"activity_id":       mentionActivity.ID,
			"mentioned_user_id": request.MentionedUserID,
			"context":           request.Context,
		},
		Timestamp: time.Now(),
	})
}

// GetProjectStats gets project statistics and insights
// @Summary Get project statistics
// @Description Get comprehensive statistics for a project (GitHub Projects v2 style)
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/stats [get]
func (pac *ProjectActivitiesController) GetProjectStats(ctx http.Context) http.Response {
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

	// Get task statistics
	var taskStats struct {
		Total      int64 `json:"total"`
		Todo       int64 `json:"todo"`
		InProgress int64 `json:"in_progress"`
		Done       int64 `json:"done"`
		Cancelled  int64 `json:"cancelled"`
		Drafts     int64 `json:"drafts"`
	}

	// Total tasks
	taskStats.Total, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND type != ?", projectID, "draft_issue").
		Count()

	// Tasks by status
	taskStats.Todo, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND type != ?", projectID, "todo", "draft_issue").
		Count()

	taskStats.InProgress, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND type != ?", projectID, "in_progress", "draft_issue").
		Count()

	taskStats.Done, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND type != ?", projectID, "done", "draft_issue").
		Count()

	taskStats.Cancelled, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND type != ?", projectID, "cancelled", "draft_issue").
		Count()

	// Draft issues
	taskStats.Drafts, _ = facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND type = ?", projectID, "draft_issue").
		Count()

	// Get activity statistics (last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var activityCount int64
	activityCount, _ = facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("subject_id = ? AND subject_type = ? AND created_at >= ?", projectID, "Project", thirtyDaysAgo).
		Count()

	// Get contributor count
	var contributorCount int64
	contributorCount, _ = facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("subject_id = ? AND subject_type = ? AND created_at >= ?", projectID, "Project", thirtyDaysAgo).
		Distinct("causer_id").
		Count()

	// Calculate progress percentage
	var progressPercentage float64
	if taskStats.Total > 0 {
		progressPercentage = float64(taskStats.Done) / float64(taskStats.Total) * 100
	}

	stats := map[string]interface{}{
		"project_id": projectID,
		"tasks":      taskStats,
		"progress": map[string]interface{}{
			"percentage": progressPercentage,
			"completed":  taskStats.Done,
			"total":      taskStats.Total,
		},
		"activity": map[string]interface{}{
			"recent_activities": activityCount,
			"contributors":      contributorCount,
			"period_days":       30,
		},
		"state": map[string]interface{}{
			"current":     project.State,
			"is_archived": project.IsArchived,
			"visibility":  project.Visibility,
		},
		"generated_at": time.Now(),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project statistics retrieved successfully",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// GetProjectTimeline gets project activity timeline
// @Summary Get project timeline
// @Description Get chronological timeline of project activities (GitHub Projects v2 style)
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param days query int false "Number of days to include" default(30)
// @Param group_by query string false "Group by period" Enums(day,week,month) default(day)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/timeline [get]
func (pac *ProjectActivitiesController) GetProjectTimeline(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	days := ctx.Request().InputInt("days", 30)
	groupBy := ctx.Request().Input("group_by", "day")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Get activities for the specified period
	startDate := time.Now().AddDate(0, 0, -days)
	var activities []models.ActivityLog

	err := facades.Orm().Query().
		With("CauserUser").
		Where("subject_id = ? AND subject_type = ? AND created_at >= ?", projectID, "Project", startDate).
		Order("created_at DESC").
		Find(&activities)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project timeline: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Group activities by time period
	timeline := make(map[string][]models.ActivityLog)
	for _, activity := range activities {
		var key string
		switch groupBy {
		case "week":
			year, week := activity.CreatedAt.ISOWeek()
			key = fmt.Sprintf("%d-W%02d", year, week)
		case "month":
			key = activity.CreatedAt.Format("2006-01")
		default: // day
			key = activity.CreatedAt.Format("2006-01-02")
		}

		if timeline[key] == nil {
			timeline[key] = []models.ActivityLog{}
		}
		timeline[key] = append(timeline[key], activity)
	}

	response := map[string]interface{}{
		"project_id": projectID,
		"timeline":   timeline,
		"period": map[string]interface{}{
			"days":     days,
			"group_by": groupBy,
			"from":     startDate,
			"to":       time.Now(),
		},
		"total_activities": len(activities),
		"generated_at":     time.Now(),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project timeline retrieved successfully",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetProjectContributors gets project contributors and their activity
// @Summary Get project contributors
// @Description Get list of project contributors with their activity statistics
// @Tags project-activities
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param days query int false "Number of days to analyze" default(30)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/contributors [get]
func (pac *ProjectActivitiesController) GetProjectContributors(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	days := ctx.Request().InputInt("days", 30)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	startDate := time.Now().AddDate(0, 0, -days)

	// Get contributor statistics
	type ContributorStat struct {
		UserID        string    `json:"user_id"`
		ActivityCount int64     `json:"activity_count"`
		LastActivity  time.Time `json:"last_activity"`
	}

	var contributorStats []ContributorStat
	err := facades.Orm().Query().Raw(`
		SELECT 
			causer_id as user_id,
			COUNT(*) as activity_count,
			MAX(created_at) as last_activity
		FROM activity_logs 
		WHERE subject_id = ? AND subject_type = ? AND created_at >= ? AND causer_id IS NOT NULL
		GROUP BY causer_id
		ORDER BY activity_count DESC
	`, projectID, "Project", startDate).Scan(&contributorStats)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve contributor statistics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get user details for contributors
	var userIDs []string
	for _, stat := range contributorStats {
		userIDs = append(userIDs, stat.UserID)
	}

	var users []models.User
	if len(userIDs) > 0 {
		facades.Orm().Query().Where("id IN ?", userIDs).Find(&users)
	}

	// Create user lookup map
	userMap := make(map[string]models.User)
	for _, user := range users {
		userMap[user.ID] = user
	}

	// Build contributor response
	contributors := make([]map[string]interface{}, 0, len(contributorStats))
	for _, stat := range contributorStats {
		contributor := map[string]interface{}{
			"user_id":        stat.UserID,
			"activity_count": stat.ActivityCount,
			"last_activity":  stat.LastActivity,
		}

		if user, exists := userMap[stat.UserID]; exists {
			contributor["user"] = map[string]interface{}{
				"id":     user.ID,
				"name":   user.Name,
				"email":  user.Email,
				"avatar": user.Avatar,
			}
		}

		contributors = append(contributors, contributor)
	}

	response := map[string]interface{}{
		"project_id":         projectID,
		"contributors":       contributors,
		"period_days":        days,
		"total_contributors": len(contributors),
		"generated_at":       time.Now(),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project contributors retrieved successfully",
		Data:      response,
		Timestamp: time.Now(),
	})
}
