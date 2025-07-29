package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectLabelsController struct{}

func NewProjectLabelsController() *ProjectLabelsController {
	return &ProjectLabelsController{}
}

// ListLabels lists all labels for a project
// @Summary List project labels
// @Description Get all labels for a project with filtering and sorting
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {array} models.TaskLabel
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels [get]
func (plc *ProjectLabelsController) ListLabels(ctx http.Context) http.Response {
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

	var labels []models.TaskLabel

	query := querybuilder.For(&models.TaskLabel{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Exact("color"),
			querybuilder.Exact("is_active"),
		).
		AllowedSorts("name", "color", "created_at", "updated_at").
		DefaultSort("name").
		Build().
		Where("project_id = ?", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&labels)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project labels: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project labels retrieved successfully", result)
}

// CreateLabel creates a new project label
// @Summary Create project label
// @Description Create a new label for a project
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectLabelRequest true "Label data"
// @Success 201 {object} models.TaskLabel
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels [post]
func (plc *ProjectLabelsController) CreateLabel(ctx http.Context) http.Response {
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

	var request requests.ProjectLabelRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if label with same name already exists in project
	var existingLabel models.TaskLabel
	if err := facades.Orm().Query().
		Where("project_id = ? AND name = ?", projectID, request.Name).
		First(&existingLabel); err == nil {
		return ctx.Response().Status(409).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Label with this name already exists in the project",
			Timestamp: time.Now(),
		})
	}

	// Create new label
	label := models.TaskLabel{
		ProjectID:   projectID,
		Name:        request.Name,
		Color:       request.Color,
		Description: request.Description,
		IsActive:    true,
	}

	if err := facades.Orm().Query().Create(&label); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project label: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project label created successfully",
		Data:      label,
		Timestamp: time.Now(),
	})
}

// GetLabel retrieves a specific project label
// @Summary Get project label
// @Description Get a specific project label by ID
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param label_id path string true "Label ID"
// @Success 200 {object} models.TaskLabel
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels/{label_id} [get]
func (plc *ProjectLabelsController) GetLabel(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	labelID := ctx.Request().Route("label_id")

	var label models.TaskLabel
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", labelID, projectID).
		First(&label); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project label not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project label retrieved successfully",
		Data:      label,
		Timestamp: time.Now(),
	})
}

// UpdateLabel updates a project label
// @Summary Update project label
// @Description Update an existing project label
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param label_id path string true "Label ID"
// @Param request body requests.ProjectLabelRequest true "Label data"
// @Success 200 {object} models.TaskLabel
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels/{label_id} [patch]
func (plc *ProjectLabelsController) UpdateLabel(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	labelID := ctx.Request().Route("label_id")

	var label models.TaskLabel
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", labelID, projectID).
		First(&label); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project label not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectLabelRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if another label with same name exists (excluding current label)
	if request.Name != label.Name {
		var existingLabel models.TaskLabel
		if err := facades.Orm().Query().
			Where("project_id = ? AND name = ? AND id != ?", projectID, request.Name, labelID).
			First(&existingLabel); err == nil {
			return ctx.Response().Status(409).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Label with this name already exists in the project",
				Timestamp: time.Now(),
			})
		}
	}

	// Update fields
	if request.Name != "" {
		label.Name = request.Name
	}
	if request.Color != "" {
		label.Color = request.Color
	}
	if request.Description != "" {
		label.Description = request.Description
	}

	if err := facades.Orm().Query().Save(&label); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project label: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project label updated successfully",
		Data:      label,
		Timestamp: time.Now(),
	})
}

// DeleteLabel deletes a project label
// @Summary Delete project label
// @Description Delete a project label and remove it from all tasks
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param label_id path string true "Label ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels/{label_id} [delete]
func (plc *ProjectLabelsController) DeleteLabel(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	labelID := ctx.Request().Route("label_id")

	var label models.TaskLabel
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", labelID, projectID).
		First(&label); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project label not found",
			Timestamp: time.Now(),
		})
	}

	// Remove label from all tasks (assuming many-to-many relationship)
	facades.Orm().Query().Model(&label).Association("Tasks").Clear()

	// Delete the label
	if _, err := facades.Orm().Query().Delete(&label); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project label: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// GetLabelUsage gets usage statistics for a project label
// @Summary Get project label usage
// @Description Get usage statistics for a specific project label
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param label_id path string true "Label ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels/{label_id}/usage [get]
func (plc *ProjectLabelsController) GetLabelUsage(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	labelID := ctx.Request().Route("label_id")

	var label models.TaskLabel
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", labelID, projectID).
		First(&label); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project label not found",
			Timestamp: time.Now(),
		})
	}

	// Get total tasks with this label (using subquery approach)
	var totalTasks int64
	facades.Orm().Query().Raw("SELECT COUNT(*) FROM tasks WHERE project_id = ? AND id IN (SELECT task_id FROM task_labels WHERE label_id = ?)", projectID, labelID).Scan(&totalTasks)

	// Get tasks by status
	var statusCounts []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	facades.Orm().Query().Raw("SELECT status, COUNT(*) as count FROM tasks WHERE project_id = ? AND id IN (SELECT task_id FROM task_labels WHERE label_id = ?) GROUP BY status", projectID, labelID).Scan(&statusCounts)

	usage := map[string]interface{}{
		"label_id":      labelID,
		"label_name":    label.Name,
		"total_tasks":   totalTasks,
		"status_counts": statusCounts,
		"project_id":    projectID,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project label usage retrieved successfully",
		Data:      usage,
		Timestamp: time.Now(),
	})
}

// BulkDeleteLabels deletes multiple project labels
// @Summary Bulk delete project labels
// @Description Delete multiple project labels at once
// @Tags project-labels
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.BulkItemsRequest true "Bulk delete data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/labels/bulk-delete [delete]
func (plc *ProjectLabelsController) BulkDeleteLabels(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.BulkItemsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.ItemIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No label IDs specified for deletion",
			Timestamp: time.Now(),
		})
	}

	// Delete labels
	if _, err := facades.Orm().Query().
		Where("project_id = ? AND id IN ?", projectID, request.ItemIDs).
		Delete(&models.TaskLabel{}); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project labels: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Project labels deleted successfully",
		Data: map[string]interface{}{
			"deleted_count": len(request.ItemIDs),
			"label_ids":     request.ItemIDs,
		},
		Timestamp: time.Now(),
	})
}
