package v1

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectBulkOperationsController struct {
	filterService *services.ProjectFilterService
}

func NewProjectBulkOperationsController() *ProjectBulkOperationsController {
	return &ProjectBulkOperationsController{
		filterService: services.NewProjectFilterService(),
	}
}

// BulkUpdateTasks performs bulk updates on multiple tasks
// @Summary Bulk update tasks
// @Description Update multiple tasks at once with various operations
// @Tags project-bulk
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param bulk_update body object true "Bulk update operations"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/tasks/bulk [patch]
func (pboc *ProjectBulkOperationsController) BulkUpdateTasks(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request struct {
		TaskIDs    []string        `json:"task_ids,omitempty"`
		Filter     string          `json:"filter,omitempty"`
		Operations []BulkOperation `json:"operations" validate:"required,min=1"`
		DryRun     bool            `json:"dry_run,omitempty"`
		BatchSize  int             `json:"batch_size,omitempty"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Set default batch size
	if request.BatchSize == 0 {
		request.BatchSize = 100
	}

	// Get target tasks
	var targetTasks []models.Task
	var err error

	if len(request.TaskIDs) > 0 {
		// Use specific task IDs
		taskIDs := make([]interface{}, len(request.TaskIDs))
		for i, id := range request.TaskIDs {
			taskIDs[i] = id
		}
		err = facades.Orm().Query().Where("project_id = ?", projectID).
			WhereIn("id", taskIDs).Find(&targetTasks)
	} else if request.Filter != "" {
		// Use filter to select tasks
		query := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID)
		query, err = pboc.filterService.ApplyFilters(query, request.Filter, "task")
		if err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid filter: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		err = query.Find(&targetTasks)
	} else {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Either task_ids or filter must be provided",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tasks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(targetTasks) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No tasks found matching the criteria",
			Timestamp: time.Now(),
		})
	}

	// Validate operations
	for _, op := range request.Operations {
		if err := pboc.validateBulkOperation(op, projectID); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid operation: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// If dry run, return what would be changed
	if request.DryRun {
		preview := pboc.previewBulkOperations(targetTasks, request.Operations)
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:  "success",
			Message: "Bulk operation preview generated",
			Data: map[string]interface{}{
				"affected_tasks": len(targetTasks),
				"operations":     len(request.Operations),
				"preview":        preview,
				"dry_run":        true,
			},
			Timestamp: time.Now(),
		})
	}

	// Execute bulk operations
	results := pboc.executeBulkOperations(targetTasks, request.Operations, userID, request.BatchSize)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Bulk operations completed successfully",
		Data:      results,
		Timestamp: time.Now(),
	})
}

// BulkDeleteTasks deletes multiple tasks
// @Summary Bulk delete tasks
// @Description Delete multiple tasks at once
// @Tags project-bulk
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param bulk_delete body object true "Bulk delete request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/tasks/bulk/delete [delete]
func (pboc *ProjectBulkOperationsController) BulkDeleteTasks(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request struct {
		TaskIDs   []string `json:"task_ids,omitempty"`
		Filter    string   `json:"filter,omitempty"`
		Permanent bool     `json:"permanent,omitempty"`
		DryRun    bool     `json:"dry_run,omitempty"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Get target tasks
	var targetTasks []models.Task
	var err error

	if len(request.TaskIDs) > 0 {
		taskIDs := make([]interface{}, len(request.TaskIDs))
		for i, id := range request.TaskIDs {
			taskIDs[i] = id
		}
		err = facades.Orm().Query().Where("project_id = ?", projectID).
			WhereIn("id", taskIDs).Find(&targetTasks)
	} else if request.Filter != "" {
		query := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID)
		query, err = pboc.filterService.ApplyFilters(query, request.Filter, "task")
		if err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid filter: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		err = query.Find(&targetTasks)
	} else {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Either task_ids or filter must be provided",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tasks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(targetTasks) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No tasks found matching the criteria",
			Timestamp: time.Now(),
		})
	}

	// If dry run, return what would be deleted
	if request.DryRun {
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:  "success",
			Message: "Bulk delete preview generated",
			Data: map[string]interface{}{
				"tasks_to_delete": len(targetTasks),
				"permanent":       request.Permanent,
				"task_titles":     pboc.extractTaskTitles(targetTasks),
				"dry_run":         true,
			},
			Timestamp: time.Now(),
		})
	}

	// Execute bulk delete
	deletedCount := 0
	for _, task := range targetTasks {
		if request.Permanent {
			// Permanent delete (if supported by your model)
			_, err = facades.Orm().Query().Where("id = ?", task.ID).Delete(&task)
		} else {
			// Soft delete
			_, err = facades.Orm().Query().Delete(&task)
		}
		if err == nil {
			deletedCount++
		}
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Bulk delete completed successfully",
		Data: map[string]interface{}{
			"deleted_count":   deletedCount,
			"requested_count": len(targetTasks),
			"permanent":       request.Permanent,
		},
		Timestamp: time.Now(),
	})
}

// BulkCreateTasks creates multiple tasks from templates or CSV
// @Summary Bulk create tasks
// @Description Create multiple tasks at once from various sources
// @Tags project-bulk
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param bulk_create body object true "Bulk create request"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/tasks/bulk/create [post]
func (pboc *ProjectBulkOperationsController) BulkCreateTasks(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request struct {
		Source   string                 `json:"source" validate:"required"` // "manual", "csv", "template"
		Tasks    []BulkTaskCreate       `json:"tasks,omitempty"`
		CSVData  string                 `json:"csv_data,omitempty"`
		Template map[string]interface{} `json:"template,omitempty"`
		Count    int                    `json:"count,omitempty"`
		DryRun   bool                   `json:"dry_run,omitempty"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var tasksToCreate []models.Task
	var err error

	switch request.Source {
	case "manual":
		tasksToCreate, err = pboc.prepareBulkTasksFromManual(request.Tasks, projectID, userID)
	case "csv":
		tasksToCreate, err = pboc.prepareBulkTasksFromCSV(request.CSVData, projectID, userID)
	case "template":
		tasksToCreate, err = pboc.prepareBulkTasksFromTemplate(request.Template, request.Count, projectID, userID)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid source. Must be 'manual', 'csv', or 'template'",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to prepare tasks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(tasksToCreate) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No tasks to create",
			Timestamp: time.Now(),
		})
	}

	// If dry run, return what would be created
	if request.DryRun {
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:  "success",
			Message: "Bulk create preview generated",
			Data: map[string]interface{}{
				"tasks_to_create": len(tasksToCreate),
				"preview":         pboc.previewTaskCreation(tasksToCreate),
				"dry_run":         true,
			},
			Timestamp: time.Now(),
		})
	}

	// Execute bulk create
	createdTasks := []models.Task{}
	createdCount := 0

	for _, task := range tasksToCreate {
		if err := facades.Orm().Query().Create(&task); err == nil {
			createdTasks = append(createdTasks, task)
			createdCount++
		}
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:  "success",
		Message: "Bulk create completed successfully",
		Data: map[string]interface{}{
			"created_count":   createdCount,
			"requested_count": len(tasksToCreate),
			"created_tasks":   createdTasks,
		},
		Timestamp: time.Now(),
	})
}

// BulkOperation represents a single bulk operation
type BulkOperation struct {
	Type   string      `json:"type" validate:"required"` // "update", "assign", "label", "status", "priority", "milestone", "iteration"
	Field  string      `json:"field,omitempty"`          // Field to update
	Value  interface{} `json:"value"`                    // New value
	Action string      `json:"action,omitempty"`         // "set", "add", "remove" for certain operations
}

// BulkTaskCreate represents a task to be created in bulk
type BulkTaskCreate struct {
	Title       string                 `json:"title" validate:"required"`
	Description string                 `json:"description,omitempty"`
	Priority    string                 `json:"priority,omitempty"`
	Status      string                 `json:"status,omitempty"`
	AssigneeID  *string                `json:"assignee_id,omitempty"`
	Labels      []string               `json:"labels,omitempty"`
	DueDate     *time.Time             `json:"due_date,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// validateBulkOperation validates a bulk operation
func (pboc *ProjectBulkOperationsController) validateBulkOperation(op BulkOperation, projectID string) error {
	validTypes := []string{"update", "assign", "label", "status", "priority", "milestone", "iteration"}

	// Check if operation type is valid
	isValidType := false
	for _, validType := range validTypes {
		if op.Type == validType {
			isValidType = true
			break
		}
	}

	if !isValidType {
		return fmt.Errorf("invalid operation type: %s", op.Type)
	}

	// Validate specific operations
	switch op.Type {
	case "assign":
		if op.Value != nil {
			// Validate user exists
			var user models.User
			if err := facades.Orm().Query().Where("id = ?", op.Value).First(&user); err != nil {
				return fmt.Errorf("assignee not found: %v", op.Value)
			}
		}
	case "status":
		if op.Value != nil {
			// Validate status exists for project
			var status models.ProjectStatus
			if err := facades.Orm().Query().Where("project_id = ? AND name = ?", projectID, op.Value).First(&status); err != nil {
				return fmt.Errorf("status not found: %v", op.Value)
			}
		}
	case "milestone":
		if op.Value != nil {
			// Validate milestone exists for project
			var milestone models.Milestone
			if err := facades.Orm().Query().Where("project_id = ? AND id = ?", projectID, op.Value).First(&milestone); err != nil {
				return fmt.Errorf("milestone not found: %v", op.Value)
			}
		}
	case "iteration":
		if op.Value != nil {
			// Validate iteration exists for project
			var iteration models.ProjectIteration
			if err := facades.Orm().Query().Where("project_id = ? AND id = ?", projectID, op.Value).First(&iteration); err != nil {
				return fmt.Errorf("iteration not found: %v", op.Value)
			}
		}
	}

	return nil
}

// previewBulkOperations generates a preview of what would change
func (pboc *ProjectBulkOperationsController) previewBulkOperations(tasks []models.Task, operations []BulkOperation) map[string]interface{} {
	preview := map[string]interface{}{
		"affected_tasks": len(tasks),
		"operations":     []map[string]interface{}{},
	}

	for _, op := range operations {
		opPreview := map[string]interface{}{
			"type":           op.Type,
			"field":          op.Field,
			"value":          op.Value,
			"action":         op.Action,
			"affected_count": len(tasks),
		}

		// Add specific preview information based on operation type
		switch op.Type {
		case "assign":
			if op.Value != nil {
				var user models.User
				if err := facades.Orm().Query().Where("id = ?", op.Value).First(&user); err == nil {
					opPreview["assignee_name"] = user.Name
				}
			}
		case "status":
			opPreview["status_name"] = op.Value
		}

		preview["operations"] = append(preview["operations"].([]map[string]interface{}), opPreview)
	}

	return preview
}

// executeBulkOperations executes the bulk operations
func (pboc *ProjectBulkOperationsController) executeBulkOperations(tasks []models.Task, operations []BulkOperation, userID string, batchSize int) map[string]interface{} {
	results := map[string]interface{}{
		"total_tasks":       len(tasks),
		"successful_tasks":  0,
		"failed_tasks":      0,
		"operation_results": []map[string]interface{}{},
	}

	// Process tasks in batches
	for i := 0; i < len(tasks); i += batchSize {
		end := i + batchSize
		if end > len(tasks) {
			end = len(tasks)
		}

		batch := tasks[i:end]
		pboc.processBatch(batch, operations, userID, results)
	}

	return results
}

// processBatch processes a batch of tasks
func (pboc *ProjectBulkOperationsController) processBatch(tasks []models.Task, operations []BulkOperation, userID string, results map[string]interface{}) {
	for _, task := range tasks {
		taskSuccess := true

		for _, op := range operations {
			if err := pboc.applyOperation(&task, op, userID); err != nil {
				taskSuccess = false
				break
			}
		}

		// Save the task
		if taskSuccess {
			if err := facades.Orm().Query().Save(&task); err != nil {
				taskSuccess = false
			}
		}

		if taskSuccess {
			results["successful_tasks"] = results["successful_tasks"].(int) + 1
		} else {
			results["failed_tasks"] = results["failed_tasks"].(int) + 1
		}
	}
}

// applyOperation applies a single operation to a task
func (pboc *ProjectBulkOperationsController) applyOperation(task *models.Task, op BulkOperation, userID string) error {
	switch op.Type {
	case "update":
		if op.Field != "" && op.Value != nil {
			// Use reflection or switch to update the field
			switch op.Field {
			case "title":
				if str, ok := op.Value.(string); ok {
					task.Title = str
				}
			case "description":
				if str, ok := op.Value.(string); ok {
					task.Description = str
				}
			case "priority":
				if str, ok := op.Value.(string); ok {
					task.Priority = str
				}
			}
		}
	case "assign":
		if op.Value == nil {
			task.AssigneeID = nil
		} else if str, ok := op.Value.(string); ok {
			task.AssigneeID = &str
		}
	case "status":
		if str, ok := op.Value.(string); ok {
			task.Status = str
		}
	case "milestone":
		if op.Value == nil {
			task.MilestoneID = nil
		} else if str, ok := op.Value.(string); ok {
			task.MilestoneID = &str
		}
	}

	return nil
}

// Helper functions for bulk create operations
func (pboc *ProjectBulkOperationsController) prepareBulkTasksFromManual(taskData []BulkTaskCreate, projectID, userID string) ([]models.Task, error) {
	var tasks []models.Task

	for _, data := range taskData {
		task := models.Task{
			Title:       data.Title,
			Description: data.Description,
			Priority:    data.Priority,
			Status:      data.Status,
			ProjectID:   projectID,
			AssigneeID:  data.AssigneeID,
			DueDate:     data.DueDate,
		}

		if task.Status == "" {
			task.Status = "todo"
		}
		if task.Priority == "" {
			task.Priority = "medium"
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (pboc *ProjectBulkOperationsController) prepareBulkTasksFromCSV(csvData, projectID, userID string) ([]models.Task, error) {
	var tasks []models.Task

	lines := strings.Split(csvData, "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("CSV must have at least a header and one data row")
	}

	// Parse header
	headers := strings.Split(lines[0], ",")

	// Parse data rows
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		values := strings.Split(line, ",")
		if len(values) != len(headers) {
			continue // Skip malformed rows
		}

		task := models.Task{
			ProjectID: projectID,
			Status:    "todo",
			Priority:  "medium",
		}

		// Map CSV columns to task fields
		for j, header := range headers {
			value := strings.TrimSpace(values[j])
			switch strings.ToLower(header) {
			case "title":
				task.Title = value
			case "description":
				task.Description = value
			case "priority":
				task.Priority = value
			case "status":
				task.Status = value
			}
		}

		if task.Title != "" {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

func (pboc *ProjectBulkOperationsController) prepareBulkTasksFromTemplate(template map[string]interface{}, count int, projectID, userID string) ([]models.Task, error) {
	var tasks []models.Task

	if count <= 0 {
		count = 1
	}
	if count > 100 {
		count = 100 // Limit to prevent abuse
	}

	for i := 0; i < count; i++ {
		task := models.Task{
			ProjectID: projectID,
			Status:    "todo",
			Priority:  "medium",
		}

		// Apply template values
		if title, ok := template["title"].(string); ok {
			task.Title = title + " " + strconv.Itoa(i+1)
		}
		if desc, ok := template["description"].(string); ok {
			task.Description = desc
		}
		if priority, ok := template["priority"].(string); ok {
			task.Priority = priority
		}
		if status, ok := template["status"].(string); ok {
			task.Status = status
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (pboc *ProjectBulkOperationsController) extractTaskTitles(tasks []models.Task) []string {
	titles := make([]string, len(tasks))
	for i, task := range tasks {
		titles[i] = task.Title
	}
	return titles
}

func (pboc *ProjectBulkOperationsController) previewTaskCreation(tasks []models.Task) []map[string]interface{} {
	preview := make([]map[string]interface{}, len(tasks))
	for i, task := range tasks {
		preview[i] = map[string]interface{}{
			"title":       task.Title,
			"description": task.Description,
			"priority":    task.Priority,
			"status":      task.Status,
		}
	}
	return preview
}
