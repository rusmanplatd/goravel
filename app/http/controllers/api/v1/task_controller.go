package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
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

// Index returns all tasks for a project
// @Summary Get all tasks
// @Description Retrieve a list of all tasks in a project with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags tasks
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[title] query string false "Filter by title (partial match)"
// @Param filter[description] query string false "Filter by description (partial match)"
// @Param filter[status] query string false "Filter by task status"
// @Param filter[priority] query string false "Filter by priority level"
// @Param filter[type] query string false "Filter by task type"
// @Param filter[assignee_id] query string false "Filter by assignee ID"
// @Param filter[milestone_id] query string false "Filter by milestone ID"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[is_archived] query bool false "Filter by archived status"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): assignee,creator,project,organization,milestone,labels,comments,activities"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.Task}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/tasks [get]
func (tc *TaskController) Index(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("id")
	projectID := ctx.Request().Route("project_id")

	var tasks []models.Task

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.Task{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("title"),
			querybuilder.Partial("description"),
			querybuilder.Exact("status"),
			querybuilder.Exact("priority"),
			querybuilder.Exact("type"),
			querybuilder.Exact("assignee_id"),
			querybuilder.Exact("milestone_id"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_archived"),
			querybuilder.Exact("organization_id"),
			querybuilder.Exact("project_id"),
		).
		AllowedSorts("title", "status", "priority", "type", "due_date", "created_at", "updated_at").
		AllowedIncludes("assignee", "creator", "project", "organization", "milestone", "labels", "comments", "activities").
		DefaultSort("-created_at")

	// Apply path constraints to the base query
	query := qb.Build().
		Where("organization_id = ?", organizationID).
		Where("project_id = ?", projectID)

	// Create a new query builder with the constrained query
	constrainedQB := querybuilder.For(query).WithRequest(ctx)

	// Use AutoPaginate for unified pagination support
	result, err := constrainedQB.AutoPaginate(&tasks)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tasks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Tasks retrieved successfully", result)
}

// Show returns a specific task
// @Summary Get a specific task by ID
// @Description Retrieve a specific task by its ID
// @Tags tasks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param id path string true "Task ID"
// @Success 200 {object} responses.APIResponse{data=models.Task}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/tasks/{task_id} [get]
func (tc *TaskController) Show(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	taskID := ctx.Request().Route("task_id")

	task, err := tc.taskService.GetTask(taskID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found",
			Timestamp: time.Now(),
		})
	}

	// Verify task belongs to project and organization
	if task.ProjectID != projectID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found in this project",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// Store creates a new task
// @Summary Create a new task
// @Description Create a new task in a project
// @Tags tasks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param task body requests.TaskRequest true "Task data"
// @Success 201 {object} responses.APIResponse{data=models.Task}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/tasks [post]
func (tc *TaskController) Store(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var req requests.TaskRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID (you'll need to implement this based on your auth system)
	userID := tc.getCurrentUserID(ctx)

	// Prepare data
	data := map[string]interface{}{
		"title":           req.Title,
		"description":     req.Description,
		"status":          req.Status,
		"priority":        req.Priority,
		"type":            req.Type,
		"color":           req.Color,
		"icon":            req.Icon,
		"assignee_id":     req.AssigneeID,
		"reviewer_id":     req.ReviewerID,
		"milestone_id":    req.MilestoneID,
		"parent_task_id":  req.ParentTaskID,
		"start_date":      req.StartDate,
		"due_date":        req.DueDate,
		"estimated_hours": req.EstimatedHours,
		"progress":        req.Progress,
		"position":        req.Position,
		"settings":        req.Settings,
		"project_id":      projectID,
		"created_by":      userID,
	}

	task, err := tc.taskService.CreateTask(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create task: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task created successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// Update updates a specific task
// @Summary Update a task
// @Description Update an existing task
// @Tags tasks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param id path string true "Task ID"
// @Param task body requests.TaskRequest true "Task data"
// @Success 200 {object} responses.APIResponse{data=models.Task}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/tasks/{task_id} [put]
func (tc *TaskController) Update(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	taskID := ctx.Request().Route("task_id")

	var req requests.TaskRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if task exists and belongs to project
	existingTask, err := tc.taskService.GetTask(taskID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found",
			Timestamp: time.Now(),
		})
	}

	if existingTask.ProjectID != projectID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found in this project",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"title":           req.Title,
		"description":     req.Description,
		"status":          req.Status,
		"priority":        req.Priority,
		"type":            req.Type,
		"color":           req.Color,
		"icon":            req.Icon,
		"assignee_id":     req.AssigneeID,
		"reviewer_id":     req.ReviewerID,
		"milestone_id":    req.MilestoneID,
		"parent_task_id":  req.ParentTaskID,
		"start_date":      req.StartDate,
		"due_date":        req.DueDate,
		"estimated_hours": req.EstimatedHours,
		"progress":        req.Progress,
		"position":        req.Position,
		"settings":        req.Settings,
	}

	task, err := tc.taskService.UpdateTask(taskID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update task: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task updated successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// Delete deletes a specific task
// @Summary Delete a task
// @Description Delete an existing task
// @Tags tasks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param id path string true "Task ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/tasks/{task_id} [delete]
func (tc *TaskController) Delete(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	taskID := ctx.Request().Route("task_id")

	// Check if task exists and belongs to project
	existingTask, err := tc.taskService.GetTask(taskID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found",
			Timestamp: time.Now(),
		})
	}

	if existingTask.ProjectID != projectID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task not found in this project",
			Timestamp: time.Now(),
		})
	}

	err = tc.taskService.DeleteTask(taskID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete task: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task deleted successfully",
		Timestamp: time.Now(),
	})
}

// Labels returns all labels for a project
// @Summary Get all task labels
// @Description Retrieve a list of all task labels in a project
// @Tags task-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse{data=[]models.TaskLabel}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/task-labels [get]
func (tc *TaskController) Labels(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	filters := map[string]interface{}{
		"project_id": projectID,
		"is_active":  true,
	}

	labels, err := tc.taskService.ListTaskLabels(filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve task labels",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      labels,
		Timestamp: time.Now(),
	})
}

// CreateLabel creates a new task label
// @Summary Create a new task label
// @Description Create a new task label in a project
// @Tags task-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param label body requests.TaskLabelRequest true "Label data"
// @Success 201 {object} responses.APIResponse{data=models.TaskLabel}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/task-labels [post]
func (tc *TaskController) CreateLabel(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var req requests.TaskLabelRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID (you'll need to implement this based on your auth system)
	userID := tc.getCurrentUserID(ctx)

	// Prepare data
	data := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"color":       req.Color,
		"icon":        req.Icon,
		"project_id":  projectID,
		"created_by":  userID,
	}

	label, err := tc.taskService.CreateTaskLabel(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create task label: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task label created successfully",
		Data:      label,
		Timestamp: time.Now(),
	})
}

// Milestones returns all milestones for a project
// @Summary Get all milestones
// @Description Retrieve a list of all milestones in a project
// @Tags milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse{data=[]models.Milestone}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/milestones [get]
func (tc *TaskController) Milestones(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	filters := map[string]interface{}{
		"project_id": projectID,
	}

	milestones, err := tc.taskService.ListMilestones(filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve milestones",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      milestones,
		Timestamp: time.Now(),
	})
}

// CreateMilestone creates a new milestone
// @Summary Create a new milestone
// @Description Create a new milestone in a project
// @Tags milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone body requests.MilestoneRequest true "Milestone data"
// @Success 201 {object} responses.APIResponse{data=models.Milestone}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/milestones [post]
func (tc *TaskController) CreateMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var req requests.MilestoneRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID (you'll need to implement this based on your auth system)
	userID := tc.getCurrentUserID(ctx)

	// Prepare data
	data := map[string]interface{}{
		"title":       req.Title,
		"description": req.Description,
		"status":      req.Status,
		"color":       req.Color,
		"icon":        req.Icon,
		"due_date":    req.DueDate,
		"progress":    req.Progress,
		"project_id":  projectID,
		"created_by":  userID,
	}

	milestone, err := tc.taskService.CreateMilestone(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Milestone created successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}

// Boards returns all task boards for a project
// @Summary Get all task boards
// @Description Retrieve a list of all task boards in a project
// @Tags task-boards
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse{data=[]models.TaskBoard}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/task-boards [get]
func (tc *TaskController) Boards(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	filters := map[string]interface{}{
		"project_id": projectID,
		"is_active":  true,
	}

	boards, err := tc.taskService.ListTaskBoards(filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve task boards",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      boards,
		Timestamp: time.Now(),
	})
}

// CreateBoard creates a new task board
// @Summary Create a new task board
// @Description Create a new task board in a project
// @Tags task-boards
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param board body requests.TaskBoardRequest true "Board data"
// @Success 201 {object} responses.APIResponse{data=models.TaskBoard}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/projects/{project_id}/task-boards [post]
func (tc *TaskController) CreateBoard(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var req requests.TaskBoardRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get current user ID (you'll need to implement this based on your auth system)
	userID := tc.getCurrentUserID(ctx)

	// Prepare data
	data := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"type":        req.Type,
		"color":       req.Color,
		"icon":        req.Icon,
		"is_default":  req.IsDefault,
		"settings":    req.Settings,
		"project_id":  projectID,
		"created_by":  userID,
	}

	board, err := tc.taskService.CreateTaskBoard(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create task board: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task board created successfully",
		Data:      board,
		Timestamp: time.Now(),
	})
}

// Helper methods

// getCurrentUser gets the current authenticated user from context
func (tc *TaskController) getCurrentUser(ctx http.Context) *models.User {
	// Get user from context (set by auth middleware)
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	// Type assertion
	if userModel, ok := user.(*models.User); ok {
		return userModel
	}

	return nil
}

// getCurrentUserID gets the current authenticated user ID from context
func (tc *TaskController) getCurrentUserID(ctx http.Context) string {
	// Get user ID from context (set by auth middleware)
	userID := ctx.Value("user_id")
	if userID == nil {
		return ""
	}

	// Type assertion
	if userIDStr, ok := userID.(string); ok {
		return userIDStr
	}

	return ""
}
