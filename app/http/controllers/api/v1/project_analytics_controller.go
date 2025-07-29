package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectAnalyticsController struct{}

func NewProjectAnalyticsController() *ProjectAnalyticsController {
	return &ProjectAnalyticsController{}
}

// GetProjectInsights returns GitHub Projects-like insights and analytics
// @Summary Get project insights
// @Description Get comprehensive project insights including velocity, burndown, and trends
// @Tags project-analytics
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param period query string false "Time period: 7d, 30d, 90d" default("30d")
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/insights [get]
func (pac *ProjectAnalyticsController) GetProjectInsights(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	period := ctx.Request().Query("period", "30d")

	// Get project
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Calculate period start date
	var startDate time.Time
	switch period {
	case "7d":
		startDate = time.Now().AddDate(0, 0, -7)
	case "90d":
		startDate = time.Now().AddDate(0, 0, -90)
	default: // 30d
		startDate = time.Now().AddDate(0, 0, -30)
	}

	// Get task metrics
	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID).Count()
	completedTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status IN ?", projectID, []string{"done", "completed"}).Count()
	recentlyCreated, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND created_at >= ?", projectID, startDate).Count()
	recentlyCompleted, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status IN ? AND updated_at >= ?", projectID, []string{"done", "completed"}, startDate).Count()

	// Calculate velocity (tasks completed per day)
	daysSinceStart := int64(time.Since(startDate).Hours() / 24)
	if daysSinceStart == 0 {
		daysSinceStart = 1
	}
	velocity := float64(recentlyCompleted) / float64(daysSinceStart)

	// Get task distribution by status
	todoTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status = ?", projectID, "todo").Count()
	inProgressTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status = ?", projectID, "in_progress").Count()

	// Get task distribution by priority
	highPriorityTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND priority = ?", projectID, "high").Count()
	mediumPriorityTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND priority = ?", projectID, "medium").Count()
	lowPriorityTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND priority = ?", projectID, "low").Count()

	// Calculate completion rate
	completionRate := float64(0)
	if totalTasks > 0 {
		completionRate = (float64(completedTasks) / float64(totalTasks)) * 100
	}

	// Estimate completion date based on velocity
	remainingTasks := totalTasks - completedTasks
	var estimatedCompletionDate *time.Time
	if velocity > 0 && remainingTasks > 0 {
		daysToComplete := float64(remainingTasks) / velocity
		estimatedDate := time.Now().AddDate(0, 0, int(daysToComplete))
		estimatedCompletionDate = &estimatedDate
	}

	insights := map[string]interface{}{
		"project": map[string]interface{}{
			"id":         project.ID,
			"name":       project.Name,
			"status":     project.Status,
			"created_at": project.CreatedAt,
		},
		"period": map[string]interface{}{
			"range":      period,
			"start_date": startDate,
			"end_date":   time.Now(),
		},
		"summary": map[string]interface{}{
			"total_items":          totalTasks,
			"completed_items":      completedTasks,
			"completion_rate":      completionRate,
			"velocity":             velocity,
			"estimated_completion": estimatedCompletionDate,
		},
		"activity": map[string]interface{}{
			"recently_created":   recentlyCreated,
			"recently_completed": recentlyCompleted,
		},
		"distribution": map[string]interface{}{
			"by_status": map[string]interface{}{
				"todo":        todoTasks,
				"in_progress": inProgressTasks,
				"completed":   completedTasks,
			},
			"by_priority": map[string]interface{}{
				"high":   highPriorityTasks,
				"medium": mediumPriorityTasks,
				"low":    lowPriorityTasks,
			},
		},
		"trends": map[string]interface{}{
			"creation_trend":   float64(recentlyCreated) / float64(daysSinceStart),
			"completion_trend": velocity,
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project insights retrieved successfully",
		Data:      insights,
		Timestamp: time.Now(),
	})
}

// GetProjectVelocity returns project velocity metrics
// @Summary Get project velocity
// @Description Get project velocity metrics over time
// @Tags project-analytics
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/velocity [get]
func (pac *ProjectAnalyticsController) GetProjectVelocity(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Get project
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Calculate velocity for different periods
	now := time.Now()

	// Last 7 days
	week7DaysAgo := now.AddDate(0, 0, -7)
	week14DaysAgo := now.AddDate(0, 0, -14)
	thisWeekCompleted, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status IN ? AND updated_at >= ?", projectID, []string{"done", "completed"}, week7DaysAgo).Count()
	lastWeekCompleted, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status IN ? AND updated_at >= ? AND updated_at < ?", projectID, []string{"done", "completed"}, week14DaysAgo, week7DaysAgo).Count()

	// Last 30 days
	thirtyDaysAgo := now.AddDate(0, 0, -30)
	sixtyDaysAgo := now.AddDate(0, 0, -60)
	thisMonthCompleted, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status IN ? AND updated_at >= ?", projectID, []string{"done", "completed"}, thirtyDaysAgo).Count()
	lastMonthCompleted, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status IN ? AND updated_at >= ? AND updated_at < ?", projectID, []string{"done", "completed"}, sixtyDaysAgo, thirtyDaysAgo).Count()

	velocity := map[string]interface{}{
		"project": map[string]interface{}{
			"id":   project.ID,
			"name": project.Name,
		},
		"weekly": map[string]interface{}{
			"current_week":  thisWeekCompleted,
			"previous_week": lastWeekCompleted,
			"velocity":      float64(thisWeekCompleted) / 7.0,
			"trend":         calculateTrend(thisWeekCompleted, lastWeekCompleted),
		},
		"monthly": map[string]interface{}{
			"current_month":  thisMonthCompleted,
			"previous_month": lastMonthCompleted,
			"velocity":       float64(thisMonthCompleted) / 30.0,
			"trend":          calculateTrend(thisMonthCompleted, lastMonthCompleted),
		},
		"generated_at": now,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project velocity retrieved successfully",
		Data:      velocity,
		Timestamp: time.Now(),
	})
}

// GetProjectBurndown returns burndown chart data
// @Summary Get project burndown
// @Description Get burndown chart data for project progress tracking
// @Tags project-analytics
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/burndown [get]
func (pac *ProjectAnalyticsController) GetProjectBurndown(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	// Get project
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID).Count()
	completedTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status IN ?", projectID, []string{"done", "completed"}).Count()

	// Generate burndown data points (simplified)
	burndownData := []map[string]interface{}{}

	// Add current data point
	burndownData = append(burndownData, map[string]interface{}{
		"date":      time.Now().Format("2006-01-02"),
		"remaining": totalTasks - completedTasks,
		"completed": completedTasks,
		"total":     totalTasks,
	})

	burndown := map[string]interface{}{
		"project": map[string]interface{}{
			"id":   project.ID,
			"name": project.Name,
		},
		"summary": map[string]interface{}{
			"total_items":     totalTasks,
			"completed_items": completedTasks,
			"remaining_items": totalTasks - completedTasks,
			"completion_rate": func() float64 {
				if totalTasks > 0 {
					return (float64(completedTasks) / float64(totalTasks)) * 100
				}
				return 0
			}(),
		},
		"data_points":  burndownData,
		"generated_at": time.Now(),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project burndown retrieved successfully",
		Data:      burndown,
		Timestamp: time.Now(),
	})
}

// Helper function to calculate trend
func calculateTrend(current, previous int64) string {
	if previous == 0 {
		if current > 0 {
			return "up"
		}
		return "stable"
	}

	if current > previous {
		return "up"
	} else if current < previous {
		return "down"
	}
	return "stable"
}
