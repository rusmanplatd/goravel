package services

import (
	"encoding/json"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectInsightService struct {
	auditService *AuditService
}

func NewProjectInsightService() *ProjectInsightService {
	return &ProjectInsightService{
		auditService: NewAuditService(),
	}
}

// GenerateInsights generates insights for a project
func (s *ProjectInsightService) GenerateInsights(projectID string, period string) error {
	currentTime := time.Now()

	// Generate different types of insights
	err := s.generateVelocityInsight(projectID, period, currentTime)
	if err != nil {
		return err
	}

	err = s.generateBurndownInsight(projectID, period, currentTime)
	if err != nil {
		return err
	}

	err = s.generateCompletionRateInsight(projectID, period, currentTime)
	if err != nil {
		return err
	}

	err = s.generateTaskDistributionInsight(projectID, period, currentTime)
	if err != nil {
		return err
	}

	return nil
}

// generateVelocityInsight generates velocity insights
func (s *ProjectInsightService) generateVelocityInsight(projectID string, period string, date time.Time) error {
	var startDate time.Time
	switch period {
	case "daily":
		startDate = date.AddDate(0, 0, -1)
	case "weekly":
		startDate = date.AddDate(0, 0, -7)
	case "monthly":
		startDate = date.AddDate(0, -1, 0)
	case "quarterly":
		startDate = date.AddDate(0, -3, 0)
	default:
		startDate = date.AddDate(0, 0, -7) // Default to weekly
	}

	// Count completed tasks in period
	var completedTasks int64
	completedTasks, err := facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND status = ? AND updated_at BETWEEN ? AND ?",
			projectID, "done", startDate, date).
		Count()
	if err != nil {
		return err
	}

	// Count total tasks in period
	var totalTasks int64
	totalTasks, err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND created_at BETWEEN ? AND ?",
			projectID, startDate, date).
		Count()
	if err != nil {
		return err
	}

	// Calculate velocity (tasks completed per day)
	days := int(date.Sub(startDate).Hours() / 24)
	if days == 0 {
		days = 1
	}
	velocity := float64(completedTasks) / float64(days)

	data := map[string]interface{}{
		"completed_tasks": completedTasks,
		"total_tasks":     totalTasks,
		"velocity":        velocity,
		"period_days":     days,
		"start_date":      startDate,
		"end_date":        date,
	}

	return s.createOrUpdateInsight(projectID, "velocity", period, date, data)
}

// generateBurndownInsight generates burndown chart data
func (s *ProjectInsightService) generateBurndownInsight(projectID string, period string, date time.Time) error {
	var totalTasks int64
	totalTasks, err := facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ?", projectID).
		Count()
	if err != nil {
		return err
	}

	var completedTasks int64
	completedTasks, err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "done").
		Count()
	if err != nil {
		return err
	}

	remainingTasks := totalTasks - completedTasks
	completionPercentage := float64(0)
	if totalTasks > 0 {
		completionPercentage = float64(completedTasks) / float64(totalTasks) * 100
	}

	data := map[string]interface{}{
		"total_tasks":           totalTasks,
		"completed_tasks":       completedTasks,
		"remaining_tasks":       remainingTasks,
		"completion_percentage": completionPercentage,
	}

	return s.createOrUpdateInsight(projectID, "burndown", period, date, data)
}

// generateCompletionRateInsight generates completion rate insights
func (s *ProjectInsightService) generateCompletionRateInsight(projectID string, period string, date time.Time) error {
	// Get task counts by status
	var statusCounts []struct {
		Status string
		Count  int64
	}

	err := facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ?", projectID).
		Select("status", "COUNT(*) as count").
		Group("status").
		Scan(&statusCounts)
	if err != nil {
		return err
	}

	statusMap := make(map[string]int64)
	var total int64
	for _, sc := range statusCounts {
		statusMap[sc.Status] = sc.Count
		total += sc.Count
	}

	// Calculate percentages
	percentages := make(map[string]float64)
	for status, count := range statusMap {
		if total > 0 {
			percentages[status] = float64(count) / float64(total) * 100
		} else {
			percentages[status] = 0
		}
	}

	data := map[string]interface{}{
		"status_counts":      statusMap,
		"status_percentages": percentages,
		"total_tasks":        total,
	}

	return s.createOrUpdateInsight(projectID, "completion_rate", period, date, data)
}

// generateTaskDistributionInsight generates task distribution insights
func (s *ProjectInsightService) generateTaskDistributionInsight(projectID string, period string, date time.Time) error {
	// Get task counts by assignee
	var assigneeCounts []struct {
		AssigneeID *string
		Count      int64
	}

	err := facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ?", projectID).
		Select("assignee_id", "COUNT(*) as count").
		Group("assignee_id").
		Scan(&assigneeCounts)
	if err != nil {
		return err
	}

	assigneeMap := make(map[string]int64)
	var unassigned int64
	var total int64

	for _, ac := range assigneeCounts {
		if ac.AssigneeID == nil {
			unassigned = ac.Count
			assigneeMap["unassigned"] = ac.Count
		} else {
			assigneeMap[*ac.AssigneeID] = ac.Count
		}
		total += ac.Count
	}

	// Get task counts by priority
	var priorityCounts []struct {
		Priority string
		Count    int64
	}

	err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ?", projectID).
		Select("priority", "COUNT(*) as count").
		Group("priority").
		Scan(&priorityCounts)
	if err != nil {
		return err
	}

	priorityMap := make(map[string]int64)
	for _, pc := range priorityCounts {
		priorityMap[pc.Priority] = pc.Count
	}

	data := map[string]interface{}{
		"assignee_distribution": assigneeMap,
		"priority_distribution": priorityMap,
		"unassigned_tasks":      unassigned,
		"total_tasks":           total,
	}

	return s.createOrUpdateInsight(projectID, "task_distribution", period, date, data)
}

// createOrUpdateInsight creates or updates an insight record
func (s *ProjectInsightService) createOrUpdateInsight(projectID, insightType, period string, date time.Time, data map[string]interface{}) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Try to find existing insight
	var existingInsight models.ProjectInsight
	err = facades.Orm().Query().
		Where("project_id = ? AND type = ? AND period = ? AND date = ?",
			projectID, insightType, period, date.Format("2006-01-02")).
		First(&existingInsight)

	if err != nil {
		// Create new insight
		insight := &models.ProjectInsight{
			Type:      insightType,
			Period:    period,
			Date:      date,
			Data:      string(dataJSON),
			ProjectID: projectID,
		}

		err = facades.Orm().Query().Create(insight)
		if err != nil {
			return err
		}
	} else {
		// Update existing insight
		existingInsight.Data = string(dataJSON)
		err = facades.Orm().Query().Save(&existingInsight)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetInsights retrieves insights for a project
func (s *ProjectInsightService) GetInsights(projectID string, filters map[string]interface{}) ([]models.ProjectInsight, error) {
	var insights []models.ProjectInsight
	query := facades.Orm().Query().Where("project_id = ?", projectID)

	// Apply filters
	if insightType, exists := filters["type"]; exists {
		query = query.Where("type = ?", insightType)
	}
	if period, exists := filters["period"]; exists {
		query = query.Where("period = ?", period)
	}
	if startDate, exists := filters["start_date"]; exists {
		query = query.Where("date >= ?", startDate)
	}
	if endDate, exists := filters["end_date"]; exists {
		query = query.Where("date <= ?", endDate)
	}

	err := query.OrderBy("date", "DESC").Find(&insights)
	if err != nil {
		return nil, err
	}

	return insights, nil
}

// GetLatestInsight gets the latest insight of a specific type
func (s *ProjectInsightService) GetLatestInsight(projectID, insightType, period string) (*models.ProjectInsight, error) {
	var insight models.ProjectInsight
	err := facades.Orm().Query().
		Where("project_id = ? AND type = ? AND period = ?", projectID, insightType, period).
		OrderBy("date", "DESC").
		First(&insight)
	if err != nil {
		return nil, err
	}
	return &insight, nil
}

// GetProjectSummary gets a summary of project metrics
func (s *ProjectInsightService) GetProjectSummary(projectID string) (map[string]interface{}, error) {
	// Get basic task counts
	var totalTasks, completedTasks, inProgressTasks, todoTasks int64

	totalTasks, err := facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ?", projectID).
		Count()
	if err != nil {
		return nil, err
	}

	completedTasks, err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "done").
		Count()
	if err != nil {
		return nil, err
	}

	inProgressTasks, err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "in_progress").
		Count()
	if err != nil {
		return nil, err
	}

	todoTasks, err = facades.Orm().Query().
		Model(&models.Task{}).
		Where("project_id = ? AND status = ?", projectID, "todo").
		Count()
	if err != nil {
		return nil, err
	}

	// Calculate completion percentage
	completionPercentage := float64(0)
	if totalTasks > 0 {
		completionPercentage = float64(completedTasks) / float64(totalTasks) * 100
	}

	// Get team size
	var teamSize int64
	teamSize, err = facades.Orm().Query().
		Table("user_projects").
		Where("project_id = ?", projectID).
		Count()
	if err != nil {
		return nil, err
	}

	summary := map[string]interface{}{
		"total_tasks":           totalTasks,
		"completed_tasks":       completedTasks,
		"in_progress_tasks":     inProgressTasks,
		"todo_tasks":            todoTasks,
		"completion_percentage": completionPercentage,
		"team_size":             teamSize,
	}

	return summary, nil
}
