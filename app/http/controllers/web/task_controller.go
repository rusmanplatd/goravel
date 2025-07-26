package web

import (
	"goravel/app/models"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type TaskController struct {
	//Dependent services
}

func NewTaskController() *TaskController {
	return &TaskController{}
}

// Index displays the tasks page
func (r *TaskController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get user's tasks from database
	var tasks []models.Task
	err := facades.Orm().Query().Where("assignee_id", user.(*models.User).ID).Find(&tasks)
	if err != nil {
		facades.Log().Error("Failed to fetch tasks", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.(*models.User).ID,
		})
		return ctx.Response().View().Make("error.tmpl", map[string]interface{}{
			"error": "Failed to load tasks",
		})
	}

	// Calculate task statistics
	var stats = map[string]int{
		"total":       len(tasks),
		"pending":     0,
		"in_progress": 0,
		"completed":   0,
	}

	for _, task := range tasks {
		switch task.Status {
		case "todo":
			stats["pending"]++
		case "in_progress":
			stats["in_progress"]++
		case "done":
			stats["completed"]++
		}
	}

	data := map[string]interface{}{
		"title": "Tasks",
		"user":  user,
		"tasks": tasks,
		"stats": stats,
	}

	return ctx.Response().View().Make("tasks/index.tmpl", data)
}

// Show displays a specific task
func (r *TaskController) Show(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	taskId := ctx.Request().Route("id")

	// Get specific task data
	data := map[string]interface{}{
		"title": "Task Details",
		"user":  user,
		"task": map[string]interface{}{
			"id":          taskId,
			"title":       "Implement user authentication",
			"description": "Add OAuth2 and multi-factor authentication support. This includes implementing JWT tokens, refresh tokens, and secure password hashing.",
			"status":      "in_progress",
			"priority":    "high",
			"assignee":    "John Doe",
			"due_date":    "2024-01-20",
			"created_at":  "2024-01-10",
			"project":     "Project Alpha",
			"labels":      []string{"backend", "security", "authentication"},
			"progress":    65,
			"comments": []map[string]interface{}{
				{
					"id":      1,
					"author":  "John Doe",
					"content": "Started working on OAuth2 implementation. Basic structure is in place.",
					"time":    "2 hours ago",
				},
				{
					"id":      2,
					"author":  "Jane Smith",
					"content": "Looks good! Make sure to include proper error handling.",
					"time":    "1 hour ago",
				},
			},
		},
	}

	return ctx.Response().View().Make("tasks/show.tmpl", data)
}

// Create displays the form to create a new task
func (r *TaskController) Create(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "Create Task",
		"user":  user,
	}

	return ctx.Response().View().Make("tasks/create.tmpl", data)
}

// Store handles the creation of a new task
func (r *TaskController) Store(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Validate and store the task
	// For now, just redirect with success message
	ctx.Request().Session().Flash("success", "Task created successfully!")
	return ctx.Response().Redirect(302, "/tasks")
}
