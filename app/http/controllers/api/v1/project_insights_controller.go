package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectInsightsController struct{}

func NewProjectInsightsController() *ProjectInsightsController {
	return &ProjectInsightsController{}
}

// GetProjectOverview provides a comprehensive project overview
// @Summary Get project overview
// @Description Get comprehensive project analytics and insights
// @Tags project-insights
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/insights/overview [get]
func (pic *ProjectInsightsController) GetProjectOverview(ctx http.Context) http.Response {
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

	now := time.Now()
	thirtyDaysAgo := now.AddDate(0, 0, -30)
	sevenDaysAgo := now.AddDate(0, 0, -7)

	// Task statistics
	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ?", projectID).Count()

	completedTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "done").Count()

	inProgressTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "in_progress").Count()

	todoTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "todo").Count()

	overdueTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status != ? AND due_date < ?", projectID, "done", now).Count()

	// Recent activity
	recentlyCompletedTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND updated_at >= ?", projectID, "done", sevenDaysAgo).Count()

	recentlyCreatedTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND created_at >= ?", projectID, sevenDaysAgo).Count()

	// Milestone statistics
	totalMilestones, _ := facades.Orm().Query().Model(&models.Milestone{}).
		Where("project_id = ?", projectID).Count()

	completedMilestones, _ := facades.Orm().Query().Model(&models.Milestone{}).
		Where("project_id = ? AND status = ?", projectID, "closed").Count()

	overdueMilestones, _ := facades.Orm().Query().Model(&models.Milestone{}).
		Where("project_id = ? AND status = ? AND due_date < ?", projectID, "open", now).Count()

	// Team statistics
	activeUsers, _ := facades.Orm().Query().Table("user_projects").
		Where("project_id = ?", projectID).Count()

	// Progress calculation
	var progressPercentage float64
	if totalTasks > 0 {
		progressPercentage = float64(completedTasks) / float64(totalTasks) * 100
	}

	// Velocity calculation (tasks completed in last 30 days)
	velocity, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND updated_at >= ?", projectID, "done", thirtyDaysAgo).Count()

	// Health score calculation
	healthScore := pic.calculateHealthScore(
		progressPercentage,
		float64(overdueTasks),
		float64(totalTasks),
		float64(overdueMilestones),
		float64(totalMilestones),
	)

	overview := map[string]interface{}{
		"project_id":   projectID,
		"project_name": project.Name,
		"generated_at": now,

		// Task metrics
		"tasks": map[string]interface{}{
			"total":              totalTasks,
			"completed":          completedTasks,
			"in_progress":        inProgressTasks,
			"todo":               todoTasks,
			"overdue":            overdueTasks,
			"recently_completed": recentlyCompletedTasks,
			"recently_created":   recentlyCreatedTasks,
			"completion_rate":    progressPercentage,
		},

		// Milestone metrics
		"milestones": map[string]interface{}{
			"total":     totalMilestones,
			"completed": completedMilestones,
			"overdue":   overdueMilestones,
		},

		// Team metrics
		"team": map[string]interface{}{
			"active_users": activeUsers,
		},

		// Performance metrics
		"performance": map[string]interface{}{
			"velocity":     velocity,
			"health_score": healthScore,
			"progress":     progressPercentage,
		},

		// Time-based metrics
		"time_metrics": map[string]interface{}{
			"start_date":  project.StartDate,
			"end_date":    project.EndDate,
			"days_active": pic.calculateDaysActive(project.CreatedAt, now),
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project overview retrieved successfully",
		Data:      overview,
		Timestamp: time.Now(),
	})
}

// GetTaskAnalytics provides detailed task analytics
// @Summary Get task analytics
// @Description Get detailed task analytics with trends and breakdowns
// @Tags project-insights
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param period query string false "Time period (7d, 30d, 90d, 1y)" default("30d")
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/insights/tasks [get]
func (pic *ProjectInsightsController) GetTaskAnalytics(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	period := ctx.Request().Query("period", "30d")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Calculate date range
	now := time.Now()
	var startDate time.Time
	switch period {
	case "7d":
		startDate = now.AddDate(0, 0, -7)
	case "30d":
		startDate = now.AddDate(0, 0, -30)
	case "90d":
		startDate = now.AddDate(0, 0, -90)
	case "1y":
		startDate = now.AddDate(-1, 0, 0)
	default:
		startDate = now.AddDate(0, 0, -30)
	}

	// Task status breakdown
	var statusBreakdown []map[string]interface{}
	statuses := []string{"todo", "in_progress", "done", "cancelled"}
	for _, status := range statuses {
		count, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND status = ?", projectID, status).Count()
		statusBreakdown = append(statusBreakdown, map[string]interface{}{
			"status": status,
			"count":  count,
		})
	}

	// Priority breakdown
	var priorityBreakdown []map[string]interface{}
	priorities := []string{"low", "medium", "high", "critical"}
	for _, priority := range priorities {
		count, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND priority = ?", projectID, priority).Count()
		priorityBreakdown = append(priorityBreakdown, map[string]interface{}{
			"priority": priority,
			"count":    count,
		})
	}

	// Assignee breakdown
	type AssigneeStats struct {
		AssigneeID   *string `json:"assignee_id"`
		AssigneeName string  `json:"assignee_name"`
		TaskCount    int64   `json:"task_count"`
	}

	var assigneeStats []AssigneeStats
	facades.Orm().Query().Table("tasks").
		Select("assignee_id, COUNT(*) as task_count").
		Where("project_id = ? AND assignee_id IS NOT NULL", projectID).
		Group("assignee_id").
		Scan(&assigneeStats)

	// Fill in assignee names
	for i := range assigneeStats {
		if assigneeStats[i].AssigneeID != nil {
			var user models.User
			if err := facades.Orm().Query().Where("id = ?", *assigneeStats[i].AssigneeID).First(&user); err == nil {
				assigneeStats[i].AssigneeName = user.Name
			}
		}
	}

	// Task creation trend (daily for the period)
	var creationTrend []map[string]interface{}
	days := int(now.Sub(startDate).Hours() / 24)
	for i := 0; i <= days; i++ {
		date := startDate.AddDate(0, 0, i)
		nextDate := date.AddDate(0, 0, 1)

		count, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, date, nextDate).Count()

		creationTrend = append(creationTrend, map[string]interface{}{
			"date":  date.Format("2006-01-02"),
			"count": count,
		})
	}

	// Task completion trend
	var completionTrend []map[string]interface{}
	for i := 0; i <= days; i++ {
		date := startDate.AddDate(0, 0, i)
		nextDate := date.AddDate(0, 0, 1)

		count, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND status = ? AND updated_at >= ? AND updated_at < ?",
				projectID, "done", date, nextDate).Count()

		completionTrend = append(completionTrend, map[string]interface{}{
			"date":  date.Format("2006-01-02"),
			"count": count,
		})
	}

	analytics := map[string]interface{}{
		"project_id":   projectID,
		"period":       period,
		"start_date":   startDate,
		"end_date":     now,
		"generated_at": now,

		"breakdowns": map[string]interface{}{
			"status":   statusBreakdown,
			"priority": priorityBreakdown,
			"assignee": assigneeStats,
		},

		"trends": map[string]interface{}{
			"creation":   creationTrend,
			"completion": completionTrend,
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task analytics retrieved successfully",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GetVelocityMetrics provides velocity and performance metrics
// @Summary Get velocity metrics
// @Description Get team velocity and performance metrics
// @Tags project-insights
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/insights/velocity [get]
func (pic *ProjectInsightsController) GetVelocityMetrics(ctx http.Context) http.Response {
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

	now := time.Now()

	// Calculate velocity for different periods
	velocityMetrics := map[string]interface{}{
		"daily":   pic.calculateVelocity(projectID, 1),
		"weekly":  pic.calculateVelocity(projectID, 7),
		"monthly": pic.calculateVelocity(projectID, 30),
	}

	// Calculate average cycle time (time from creation to completion)
	var avgCycleTime float64
	var cycleTimeQuery = `
		SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600) as avg_hours
		FROM tasks 
		WHERE project_id = ? AND status = 'done' AND updated_at > created_at
	`
	facades.Orm().Query().Raw(cycleTimeQuery, projectID).Scan(&avgCycleTime)

	// Calculate lead time (time from first assignment to completion)
	var avgLeadTime float64
	// This would require tracking assignment history, simplified for now
	avgLeadTime = avgCycleTime * 1.2 // Rough estimation

	// Throughput (tasks completed per week over last 8 weeks)
	var throughput []map[string]interface{}
	for i := 0; i < 8; i++ {
		weekStart := now.AddDate(0, 0, -(i+1)*7)
		weekEnd := now.AddDate(0, 0, -i*7)

		count, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND status = ? AND updated_at >= ? AND updated_at < ?",
				projectID, "done", weekStart, weekEnd).Count()

		throughput = append([]map[string]interface{}{{
			"week_start": weekStart.Format("2006-01-02"),
			"week_end":   weekEnd.Format("2006-01-02"),
			"completed":  count,
		}}, throughput...)
	}

	// Work in Progress (WIP) limits analysis
	wipLimits := pic.analyzeWIPLimits(projectID)

	// Burndown data (if iterations exist)
	burndownData := pic.getBurndownData(projectID)

	metrics := map[string]interface{}{
		"project_id":   projectID,
		"generated_at": now,

		"velocity": velocityMetrics,

		"cycle_time": map[string]interface{}{
			"average_hours": avgCycleTime,
			"average_days":  avgCycleTime / 24,
		},

		"lead_time": map[string]interface{}{
			"average_hours": avgLeadTime,
			"average_days":  avgLeadTime / 24,
		},

		"throughput":   throughput,
		"wip_analysis": wipLimits,
		"burndown":     burndownData,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Velocity metrics retrieved successfully",
		Data:      metrics,
		Timestamp: time.Now(),
	})
}

// GetBurndownChart provides burndown chart data
// @Summary Get burndown chart
// @Description Get burndown chart data for current iteration
// @Tags project-insights
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id query string false "Iteration ID (defaults to current)"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/insights/burndown [get]
func (pic *ProjectInsightsController) GetBurndownChart(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Query("iteration_id", "")

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Get iteration
	var iteration models.ProjectIteration
	if iterationID != "" {
		if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).First(&iteration); err != nil {
			return ctx.Response().Status(404).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Iteration not found",
				Timestamp: time.Now(),
			})
		}
	} else {
		// Get current iteration
		if err := facades.Orm().Query().Where("project_id = ? AND is_current = ?", projectID, true).First(&iteration); err != nil {
			return ctx.Response().Status(404).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "No current iteration found",
				Timestamp: time.Now(),
			})
		}
	}

	// Generate burndown data
	burndownData := pic.generateBurndownData(projectID, iteration)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Burndown chart data retrieved successfully",
		Data:      burndownData,
		Timestamp: time.Now(),
	})
}

// Helper functions

func (pic *ProjectInsightsController) calculateHealthScore(
	progress, overdueTasks, totalTasks, overdueMilestones, totalMilestones float64) float64 {

	score := 100.0

	// Deduct for low progress
	if progress < 50 {
		score -= (50 - progress) * 0.5
	}

	// Deduct for overdue tasks
	if totalTasks > 0 {
		overdueRatio := overdueTasks / totalTasks
		score -= overdueRatio * 30
	}

	// Deduct for overdue milestones
	if totalMilestones > 0 {
		overdueRatio := overdueMilestones / totalMilestones
		score -= overdueRatio * 20
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (pic *ProjectInsightsController) calculateDaysActive(startDate, endDate time.Time) int {
	return int(endDate.Sub(startDate).Hours() / 24)
}

func (pic *ProjectInsightsController) calculateVelocity(projectID string, days int) float64 {
	startDate := time.Now().AddDate(0, 0, -days)

	count, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND updated_at >= ?", projectID, "done", startDate).Count()

	return float64(count) / float64(days)
}

func (pic *ProjectInsightsController) analyzeWIPLimits(projectID string) map[string]interface{} {
	inProgressCount, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "in_progress").Count()

	// Simple WIP analysis - in a real system you'd have configurable limits
	recommendedWIP := int64(5) // Example limit

	return map[string]interface{}{
		"current_wip":     inProgressCount,
		"recommended_wip": recommendedWIP,
		"is_over_limit":   inProgressCount > recommendedWIP,
		"utilization":     float64(inProgressCount) / float64(recommendedWIP) * 100,
	}
}

func (pic *ProjectInsightsController) getBurndownData(projectID string) map[string]interface{} {
	// Get current iteration
	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("project_id = ? AND is_current = ?", projectID, true).First(&iteration); err != nil {
		return map[string]interface{}{
			"available": false,
			"message":   "No current iteration",
		}
	}

	return pic.generateBurndownData(projectID, iteration)
}

func (pic *ProjectInsightsController) generateBurndownData(projectID string, iteration models.ProjectIteration) map[string]interface{} {
	if iteration.StartDate == nil || iteration.EndDate == nil {
		return map[string]interface{}{
			"available": false,
			"message":   "Iteration missing start or end date",
		}
	}

	// Calculate total tasks in iteration
	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND iteration_id = ?", projectID, iteration.ID).Count()

	// Generate daily burndown data
	var burndownPoints []map[string]interface{}
	current := *iteration.StartDate
	end := *iteration.EndDate

	for current.Before(end) || current.Equal(end) {
		// Count remaining tasks at end of this day
		nextDay := current.AddDate(0, 0, 1)
		remaining, _ := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND iteration_id = ? AND (status != ? OR updated_at > ?)",
				projectID, iteration.ID, "done", nextDay).Count()

		burndownPoints = append(burndownPoints, map[string]interface{}{
			"date":      current.Format("2006-01-02"),
			"remaining": remaining,
			"ideal":     pic.calculateIdealBurndown(totalTasks, *iteration.StartDate, *iteration.EndDate, current),
		})

		current = current.AddDate(0, 0, 1)
	}

	return map[string]interface{}{
		"available":       true,
		"iteration_id":    iteration.ID,
		"iteration_title": iteration.Title,
		"start_date":      iteration.StartDate,
		"end_date":        iteration.EndDate,
		"total_tasks":     totalTasks,
		"burndown_points": burndownPoints,
	}
}

func (pic *ProjectInsightsController) calculateIdealBurndown(totalTasks int64, startDate, endDate, currentDate time.Time) float64 {
	totalDays := endDate.Sub(startDate).Hours() / 24
	daysPassed := currentDate.Sub(startDate).Hours() / 24

	if daysPassed < 0 {
		return float64(totalTasks)
	}
	if daysPassed >= totalDays {
		return 0
	}

	return float64(totalTasks) * (totalDays - daysPassed) / totalDays
}
