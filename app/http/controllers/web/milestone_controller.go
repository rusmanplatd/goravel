package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type MilestoneController struct {
	taskService *services.TaskService
}

func NewMilestoneController() *MilestoneController {
	return &MilestoneController{
		taskService: services.NewTaskService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *MilestoneController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the milestone management dashboard
func (c *MilestoneController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get milestone statistics
	totalMilestones, _ := facades.Orm().Query().Table("milestones").Count()
	activeMilestones, _ := facades.Orm().Query().Table("milestones").
		Where("status IN ?", []string{"active", "in_progress"}).Count()
	completedMilestones, _ := facades.Orm().Query().Table("milestones").
		Where("status = ?", "completed").Count()

	// Get recent milestones
	var recentMilestones []models.Milestone
	facades.Orm().Query().Model(&models.Milestone{}).
		Limit(10).
		OrderBy("created_at", "DESC").
		Find(&recentMilestones)

	// Get upcoming milestones
	var upcomingMilestones []models.Milestone
	facades.Orm().Query().Model(&models.Milestone{}).
		Where("due_date > ?", "NOW()").
		Where("status != ?", "completed").
		Limit(5).
		OrderBy("due_date", "ASC").
		Find(&upcomingMilestones)

	return ctx.Response().View().Make("milestones/index.tmpl", map[string]interface{}{
		"title":                "Milestones",
		"user":                 user,
		"total_milestones":     totalMilestones,
		"active_milestones":    activeMilestones,
		"completed_milestones": completedMilestones,
		"recent_milestones":    recentMilestones,
		"upcoming_milestones":  upcomingMilestones,
	})
}
