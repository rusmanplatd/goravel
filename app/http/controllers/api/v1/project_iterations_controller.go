package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectIterationsController struct{}

func NewProjectIterationsController() *ProjectIterationsController {
	return &ProjectIterationsController{}
}

// ListIterations lists all iterations for a project
// @Summary List project iterations
// @Description Get all iterations/sprints for a project (GitHub Projects v2 style)
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param status query string false "Filter by status (planning, active, completed)"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectIteration}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations [get]
func (pic *ProjectIterationsController) ListIterations(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	status := ctx.Request().Query("status", "")

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
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var iterations []models.ProjectIteration
	if err := query.Order("start_date DESC, created_at DESC").Find(&iterations); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project iterations: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iterations retrieved successfully",
		Data:      iterations,
		Timestamp: time.Now(),
	})
}

// CreateIteration creates a new iteration for a project
// @Summary Create project iteration
// @Description Create a new iteration/sprint for a project (GitHub Projects v2 style)
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration body requests.ProjectIterationRequest true "Iteration data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectIteration}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations [post]
func (pic *ProjectIterationsController) CreateIteration(ctx http.Context) http.Response {
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

	var request requests.ProjectIterationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Calculate duration if not provided
	duration := request.Duration
	if duration == 0 && request.StartDate != nil && request.EndDate != nil {
		duration = int(request.EndDate.Sub(*request.StartDate).Hours() / 24)
	}

	// If marking as current, unset other current iterations
	if request.IsCurrent {
		_, err := facades.Orm().Query().Model(&models.ProjectIteration{}).
			Where("project_id = ?", projectID).
			Update("is_current", false)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to update current iterations: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	iteration := models.ProjectIteration{
		Title:       request.Title,
		Description: request.Description,
		StartDate:   request.StartDate,
		EndDate:     request.EndDate,
		Duration:    duration,
		Status:      "planning",
		IsCurrent:   request.IsCurrent,
		ProjectID:   projectID,
	}

	if err := facades.Orm().Query().Create(&iteration); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration created successfully",
		Data:      iteration,
		Timestamp: time.Now(),
	})
}

// GetIteration retrieves a specific project iteration
// @Summary Get project iteration
// @Description Get details of a specific project iteration
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id path string true "Iteration ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectIteration}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations/{iteration_id} [get]
func (pic *ProjectIterationsController) GetIteration(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Route("iteration_id")

	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).With("Tasks").First(&iteration); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project iteration not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration retrieved successfully",
		Data:      iteration,
		Timestamp: time.Now(),
	})
}

// UpdateIteration updates a project iteration
// @Summary Update project iteration
// @Description Update an existing project iteration
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id path string true "Iteration ID"
// @Param iteration body requests.ProjectIterationRequest true "Iteration data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectIteration}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations/{iteration_id} [patch]
func (pic *ProjectIterationsController) UpdateIteration(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Route("iteration_id")

	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).First(&iteration); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project iteration not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectIterationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// If marking as current, unset other current iterations
	if request.IsCurrent && !iteration.IsCurrent {
		_, err := facades.Orm().Query().Model(&models.ProjectIteration{}).
			Where("project_id = ? AND id != ?", projectID, iterationID).
			Update("is_current", false)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to update current iterations: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Update fields
	iteration.Title = request.Title
	iteration.Description = request.Description
	iteration.StartDate = request.StartDate
	iteration.EndDate = request.EndDate
	iteration.IsCurrent = request.IsCurrent

	// Calculate duration if dates are provided
	if request.Duration > 0 {
		iteration.Duration = request.Duration
	} else if request.StartDate != nil && request.EndDate != nil {
		iteration.Duration = int(request.EndDate.Sub(*request.StartDate).Hours() / 24)
	}

	if err := facades.Orm().Query().Save(&iteration); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration updated successfully",
		Data:      iteration,
		Timestamp: time.Now(),
	})
}

// DeleteIteration deletes a project iteration
// @Summary Delete project iteration
// @Description Delete a project iteration (will unassign tasks from iteration)
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id path string true "Iteration ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations/{iteration_id} [delete]
func (pic *ProjectIterationsController) DeleteIteration(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Route("iteration_id")

	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).First(&iteration); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project iteration not found",
			Timestamp: time.Now(),
		})
	}

	// Unassign all tasks from this iteration
	_, err := facades.Orm().Query().Model(&models.Task{}).Where("iteration_id = ?", iterationID).Update("iteration_id", nil)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to unassign tasks from iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Delete the iteration
	_, err = facades.Orm().Query().Delete(&iteration)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration deleted successfully",
		Timestamp: time.Now(),
	})
}

// StartIteration starts an iteration (sets status to active)
// @Summary Start project iteration
// @Description Start a project iteration (GitHub Projects v2 style)
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id path string true "Iteration ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectIteration}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations/{iteration_id}/start [post]
func (pic *ProjectIterationsController) StartIteration(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Route("iteration_id")

	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).First(&iteration); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project iteration not found",
			Timestamp: time.Now(),
		})
	}

	iteration.Status = "active"
	iteration.IsCurrent = true

	// Unset other current iterations
	_, err := facades.Orm().Query().Model(&models.ProjectIteration{}).
		Where("project_id = ? AND id != ?", projectID, iterationID).
		Update("is_current", false)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update current iterations: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if err := facades.Orm().Query().Save(&iteration); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start project iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration started successfully",
		Data:      iteration,
		Timestamp: time.Now(),
	})
}

// CompleteIteration completes an iteration (sets status to completed)
// @Summary Complete project iteration
// @Description Complete a project iteration (GitHub Projects v2 style)
// @Tags project-iterations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param iteration_id path string true "Iteration ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectIteration}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/iterations/{iteration_id}/complete [post]
func (pic *ProjectIterationsController) CompleteIteration(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	iterationID := ctx.Request().Route("iteration_id")

	var iteration models.ProjectIteration
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", iterationID, projectID).First(&iteration); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project iteration not found",
			Timestamp: time.Now(),
		})
	}

	iteration.Status = "completed"
	iteration.IsCurrent = false

	if err := facades.Orm().Query().Save(&iteration); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to complete project iteration: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project iteration completed successfully",
		Data:      iteration,
		Timestamp: time.Now(),
	})
}
