package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectStatusController struct{}

func NewProjectStatusController() *ProjectStatusController {
	return &ProjectStatusController{}
}

// GetProjectStats returns project statistics similar to GitHub Projects
// @Summary Get project statistics
// @Description Get comprehensive statistics for a project including item counts, progress, etc.
// @Tags project-status
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/stats [get]
func (psc *ProjectStatusController) GetProjectStats(ctx http.Context) http.Response {
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

	// Get task statistics
	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID).Count()
	todoTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status = ?", projectID, "todo").Count()
	inProgressTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status = ?", projectID, "in_progress").Count()
	doneTasks, _ := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ? AND status IN ?", projectID, []string{"done", "completed"}).Count()

	// Calculate progress percentage
	progressPercentage := float64(0)
	if totalTasks > 0 {
		progressPercentage = (float64(doneTasks) / float64(totalTasks)) * 100
	}

	stats := map[string]interface{}{
		"project": map[string]interface{}{
			"id":         project.ID,
			"name":       project.Name,
			"status":     project.Status,
			"priority":   project.Priority,
			"is_active":  project.IsActive,
			"created_at": project.CreatedAt,
			"updated_at": project.UpdatedAt,
		},
		"items": map[string]interface{}{
			"total":       totalTasks,
			"todo":        todoTasks,
			"in_progress": inProgressTasks,
			"done":        doneTasks,
		},
		"progress": map[string]interface{}{
			"percentage": progressPercentage,
			"completed":  doneTasks,
			"remaining":  totalTasks - doneTasks,
		},
		"activity": map[string]interface{}{
			"last_updated": project.UpdatedAt,
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project statistics retrieved successfully",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// UpdateProjectStatus updates the project status
// @Summary Update project status
// @Description Update project status (planning, active, on-hold, completed, cancelled)
// @Tags project-status
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/status [patch]
func (psc *ProjectStatusController) UpdateProjectStatus(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var request struct {
		Status string `json:"status" validate:"required,oneof=planning active on-hold completed cancelled"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	project.Status = request.Status

	// Auto-update is_active based on status
	if request.Status == "completed" || request.Status == "cancelled" {
		project.IsActive = false
	} else {
		project.IsActive = true
	}

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project status: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project status updated successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// ArchiveProject archives a project (similar to GitHub Projects archive)
// @Summary Archive project
// @Description Archive a project (sets status to completed and is_active to false)
// @Tags project-status
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/archive [post]
func (psc *ProjectStatusController) ArchiveProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	project.Status = "completed"
	project.IsActive = false

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to archive project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project archived successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// RestoreProject restores an archived project
// @Summary Restore project
// @Description Restore an archived project (sets status to active and is_active to true)
// @Tags project-status
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/restore [post]
func (psc *ProjectStatusController) RestoreProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	project.Status = "active"
	project.IsActive = true

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to restore project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project restored successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}
