package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type TaskController struct {
	taskService *services.TaskService
}

func NewTaskController() *TaskController {
	return &TaskController{
		taskService: services.NewTaskService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *TaskController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the task management dashboard
func (c *TaskController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get task statistics
	totalTasks, _ := facades.Orm().Query().Table("tasks").Count()
	activeTasks, _ := facades.Orm().Query().Table("tasks").
		Where("status IN ?", []string{"todo", "in_progress"}).Count()
	completedTasks, _ := facades.Orm().Query().Table("tasks").
		Where("status = ?", "done").Count()

	// Get recent tasks
	var recentTasks []models.Task
	facades.Orm().Query().Model(&models.Task{}).
		Limit(10).
		OrderBy("created_at", "DESC").
		Find(&recentTasks)

	// Get task boards
	taskBoards, err := c.taskService.ListTaskBoards(map[string]interface{}{
		"is_active": true,
	})
	if err != nil {
		facades.Log().Error("Failed to fetch task boards", map[string]interface{}{
			"error": err.Error(),
		})
		taskBoards = []models.TaskBoard{}
	}

	return ctx.Response().View().Make("tasks/index.tmpl", map[string]interface{}{
		"title":           "Task Management",
		"user":            user,
		"total_tasks":     totalTasks,
		"active_tasks":    activeTasks,
		"completed_tasks": completedTasks,
		"recent_tasks":    recentTasks,
		"task_boards":     taskBoards,
	})
}

// Boards displays the task boards page
func (c *TaskController) Boards(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get all task boards
	taskBoards, err := c.taskService.ListTaskBoards(map[string]interface{}{
		"is_active": true,
	})
	if err != nil {
		facades.Log().Error("Failed to fetch task boards", map[string]interface{}{
			"error": err.Error(),
		})
		taskBoards = []models.TaskBoard{}
	}

	return ctx.Response().View().Make("tasks/boards.tmpl", map[string]interface{}{
		"title":       "Task Boards",
		"user":        user,
		"task_boards": taskBoards,
	})
}
