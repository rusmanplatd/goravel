package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectStatusesController struct{}

func NewProjectStatusesController() *ProjectStatusesController {
	return &ProjectStatusesController{}
}

// ListStatuses lists all statuses for a project
// @Summary List project statuses
// @Description Get all custom statuses for a project (GitHub Projects v2 style)
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param include_inactive query bool false "Include inactive statuses"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectStatus}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses [get]
func (psc *ProjectStatusesController) ListStatuses(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	includeInactive := ctx.Request().QueryBool("include_inactive", false)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	query := facades.Orm().Query().Where("project_id = ?", projectID)
	if !includeInactive {
		query = query.Where("is_active = ?", true)
	}

	var statuses []models.ProjectStatus
	if err := query.Order("position ASC, created_at ASC").Find(&statuses); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project statuses: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project statuses retrieved successfully",
		Data:      statuses,
		Timestamp: time.Now(),
	})
}

// CreateStatus creates a new custom status for a project
// @Summary Create project status
// @Description Create a new custom status for a project (GitHub Projects v2 style)
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param status body requests.ProjectStatusRequest true "Status data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectStatus}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses [post]
func (psc *ProjectStatusesController) CreateStatus(ctx http.Context) http.Response {
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

	var request requests.ProjectStatusRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check for duplicate name
	var existingStatus models.ProjectStatus
	if err := facades.Orm().Query().Where("project_id = ? AND name = ?", projectID, request.Name).First(&existingStatus); err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Status with this name already exists",
			Timestamp: time.Now(),
		})
	}

	// Get next position if not provided
	position := request.Position
	if position == 0 {
		var maxPosition int
		facades.Orm().Query().Model(&models.ProjectStatus{}).Where("project_id = ?", projectID).Select("COALESCE(MAX(position), 0)").Scan(&maxPosition)
		position = maxPosition + 1
	}

	status := models.ProjectStatus{
		Name:        request.Name,
		Description: request.Description,
		Color:       request.Color,
		Icon:        request.Icon,
		Type:        request.Type,
		Position:    position,
		IsActive:    true,
		IsDefault:   request.IsDefault,
		ProjectID:   projectID,
	}

	if err := facades.Orm().Query().Create(&status); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project status: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project status created successfully",
		Data:      status,
		Timestamp: time.Now(),
	})
}

// GetStatus retrieves a specific project status
// @Summary Get project status
// @Description Get details of a specific project status
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param status_id path string true "Status ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectStatus}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses/{status_id} [get]
func (psc *ProjectStatusesController) GetStatus(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	statusID := ctx.Request().Route("status_id")

	var status models.ProjectStatus
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", statusID, projectID).First(&status); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project status not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project status retrieved successfully",
		Data:      status,
		Timestamp: time.Now(),
	})
}

// UpdateStatus updates a project status
// @Summary Update project status
// @Description Update an existing project status
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param status_id path string true "Status ID"
// @Param status body requests.ProjectStatusRequest true "Status data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectStatus}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses/{status_id} [patch]
func (psc *ProjectStatusesController) UpdateStatus(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	statusID := ctx.Request().Route("status_id")

	var status models.ProjectStatus
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", statusID, projectID).First(&status); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project status not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectStatusRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check for duplicate name (excluding current status)
	var existingStatus models.ProjectStatus
	if err := facades.Orm().Query().Where("project_id = ? AND name = ? AND id != ?", projectID, request.Name, statusID).First(&existingStatus); err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Status with this name already exists",
			Timestamp: time.Now(),
		})
	}

	// Update fields
	status.Name = request.Name
	status.Description = request.Description
	status.Color = request.Color
	status.Icon = request.Icon
	status.Type = request.Type
	if request.Position > 0 {
		status.Position = request.Position
	}
	status.IsDefault = request.IsDefault

	if err := facades.Orm().Query().Save(&status); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project status: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project status updated successfully",
		Data:      status,
		Timestamp: time.Now(),
	})
}

// DeleteStatus deletes a project status
// @Summary Delete project status
// @Description Delete a project status (will move items to default status)
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param status_id path string true "Status ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses/{status_id} [delete]
func (psc *ProjectStatusesController) DeleteStatus(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	statusID := ctx.Request().Route("status_id")

	var status models.ProjectStatus
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", statusID, projectID).First(&status); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project status not found",
			Timestamp: time.Now(),
		})
	}

	// Find default status to move items to
	var defaultStatus models.ProjectStatus
	if err := facades.Orm().Query().Where("project_id = ? AND is_default = ? AND id != ?", projectID, true, statusID).First(&defaultStatus); err != nil {
		// If no default status, find the first active status
		if err := facades.Orm().Query().Where("project_id = ? AND is_active = ? AND id != ?", projectID, true, statusID).Order("position ASC").First(&defaultStatus); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Cannot delete status: no alternative status available",
				Timestamp: time.Now(),
			})
		}
	}

	// Move all tasks using this status to the default status
	_, err := facades.Orm().Query().Model(&models.Task{}).Where("status_id = ?", statusID).Update("status_id", defaultStatus.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to move items to default status: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Delete the status
	_, err = facades.Orm().Query().Delete(&status)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project status: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project status deleted successfully",
		Data:      map[string]interface{}{"moved_to_status": defaultStatus},
		Timestamp: time.Now(),
	})
}

// ReorderStatuses reorders project statuses
// @Summary Reorder project statuses
// @Description Reorder project statuses by updating positions
// @Tags project-statuses
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param order body map[string][]string true "Status order data"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/statuses/reorder [post]
func (psc *ProjectStatusesController) ReorderStatuses(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request struct {
		StatusIDs []string `json:"status_ids" validate:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update positions
	for i, statusID := range request.StatusIDs {
		_, err := facades.Orm().Query().Model(&models.ProjectStatus{}).
			Where("id = ? AND project_id = ?", statusID, projectID).
			Update("position", i+1)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to reorder statuses: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project statuses reordered successfully",
		Timestamp: time.Now(),
	})
}
