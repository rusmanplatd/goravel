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

type ProjectMilestonesController struct{}

func NewProjectMilestonesController() *ProjectMilestonesController {
	return &ProjectMilestonesController{}
}

// ListMilestones lists all milestones for a project
// @Summary List project milestones
// @Description Get all milestones for a project with filtering and sorting
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Success 200 {array} models.Milestone
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones [get]
func (pmc *ProjectMilestonesController) ListMilestones(ctx http.Context) http.Response {
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

	var milestones []models.Milestone

	query := querybuilder.For(&models.Milestone{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("title"),
			querybuilder.Exact("status"),
			querybuilder.Exact("is_active"),
		).
		AllowedSorts("title", "due_date", "progress", "created_at", "updated_at").
		DefaultSort("due_date").
		Build().
		Where("project_id = ?", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&milestones)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project milestones: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project milestones retrieved successfully", result)
}

// CreateMilestone creates a new project milestone
// @Summary Create project milestone
// @Description Create a new milestone for a project
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectMilestoneRequest true "Milestone data"
// @Success 201 {object} models.Milestone
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones [post]
func (pmc *ProjectMilestonesController) CreateMilestone(ctx http.Context) http.Response {
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

	var request requests.ProjectMilestoneRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if milestone with same title already exists in project
	var existingMilestone models.Milestone
	if err := facades.Orm().Query().
		Where("project_id = ? AND title = ?", projectID, request.Title).
		First(&existingMilestone); err == nil {
		return ctx.Response().Status(409).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Milestone with this title already exists in the project",
			Timestamp: time.Now(),
		})
	}

	// Create new milestone
	milestone := models.Milestone{
		ProjectID:   projectID,
		Title:       request.Title,
		Description: request.Description,
		Status:      "open",
		Progress:    0,
	}

	// Set optional fields
	if request.DueDate != nil {
		milestone.DueDate = request.DueDate
	}

	if err := facades.Orm().Query().Create(&milestone); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone created successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}

// GetMilestone retrieves a specific project milestone
// @Summary Get project milestone
// @Description Get a specific project milestone by ID
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Success 200 {object} models.Milestone
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id} [get]
func (pmc *ProjectMilestonesController) GetMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone retrieved successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}

// UpdateMilestone updates a project milestone
// @Summary Update project milestone
// @Description Update an existing project milestone
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Param request body requests.ProjectMilestoneRequest true "Milestone data"
// @Success 200 {object} models.Milestone
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id} [patch]
func (pmc *ProjectMilestonesController) UpdateMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectMilestoneRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if another milestone with same title exists (excluding current milestone)
	if request.Title != "" && request.Title != milestone.Title {
		var existingMilestone models.Milestone
		if err := facades.Orm().Query().
			Where("project_id = ? AND title = ? AND id != ?", projectID, request.Title, milestoneID).
			First(&existingMilestone); err == nil {
			return ctx.Response().Status(409).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Milestone with this title already exists in the project",
				Timestamp: time.Now(),
			})
		}
	}

	// Update fields
	if request.Title != "" {
		milestone.Title = request.Title
	}
	if request.Description != "" {
		milestone.Description = request.Description
	}
	if request.DueDate != nil {
		milestone.DueDate = request.DueDate
	}
	// StartDate is not available in Milestone model

	if err := facades.Orm().Query().Save(&milestone); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone updated successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}

// DeleteMilestone deletes a project milestone
// @Summary Delete project milestone
// @Description Delete a project milestone and unassign it from all tasks
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id} [delete]
func (pmc *ProjectMilestonesController) DeleteMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	// Unassign milestone from all tasks
	facades.Orm().Query().Model(&models.Task{}).
		Where("milestone_id = ?", milestoneID).
		Update("milestone_id", nil)

	// Delete the milestone
	if _, err := facades.Orm().Query().Delete(&milestone); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// GetMilestoneProgress gets progress statistics for a project milestone
// @Summary Get project milestone progress
// @Description Get progress statistics for a specific project milestone
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id}/progress [get]
func (pmc *ProjectMilestonesController) GetMilestoneProgress(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	// Get total tasks in milestone
	totalTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("milestone_id = ? AND project_id = ?", milestoneID, projectID).
		Count()

	// Get completed tasks
	completedTasks, _ := facades.Orm().Query().Model(&models.Task{}).
		Where("milestone_id = ? AND project_id = ? AND status = ?", milestoneID, projectID, "done").
		Count()

	// Get tasks by status
	var statusCounts []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	facades.Orm().Query().Model(&models.Task{}).
		Select("status, COUNT(*) as count").
		Where("milestone_id = ? AND project_id = ?", milestoneID, projectID).
		Group("status").
		Scan(&statusCounts)

	// Calculate progress percentage
	var progressPercentage float64
	if totalTasks > 0 {
		progressPercentage = float64(completedTasks) / float64(totalTasks) * 100
	}

	// Update milestone progress
	milestone.Progress = progressPercentage
	facades.Orm().Query().Save(&milestone)

	// Check if milestone should be closed
	if progressPercentage == 100 && milestone.Status == "open" {
		milestone.Status = "closed"
		facades.Orm().Query().Save(&milestone)
	}

	progress := map[string]interface{}{
		"milestone_id":        milestoneID,
		"milestone_title":     milestone.Title,
		"total_tasks":         totalTasks,
		"completed_tasks":     completedTasks,
		"progress_percentage": progressPercentage,
		"status_counts":       statusCounts,
		"milestone_status":    milestone.Status,
		"due_date":            milestone.DueDate,
		"project_id":          projectID,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone progress retrieved successfully",
		Data:      progress,
		Timestamp: time.Now(),
	})
}

// CloseMilestone closes a project milestone
// @Summary Close project milestone
// @Description Close a project milestone
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Success 200 {object} models.Milestone
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id}/close [post]
func (pmc *ProjectMilestonesController) CloseMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	milestone.Status = "closed"
	if err := facades.Orm().Query().Save(&milestone); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to close project milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone closed successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}

// ReopenMilestone reopens a project milestone
// @Summary Reopen project milestone
// @Description Reopen a closed project milestone
// @Tags project-milestones
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param milestone_id path string true "Milestone ID"
// @Success 200 {object} models.Milestone
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/milestones/{milestone_id}/reopen [post]
func (pmc *ProjectMilestonesController) ReopenMilestone(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	milestoneID := ctx.Request().Route("milestone_id")

	var milestone models.Milestone
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", milestoneID, projectID).
		First(&milestone); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project milestone not found",
			Timestamp: time.Now(),
		})
	}

	milestone.Status = "open"
	if err := facades.Orm().Query().Save(&milestone); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to reopen project milestone: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project milestone reopened successfully",
		Data:      milestone,
		Timestamp: time.Now(),
	})
}
