package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectWorkflowsController struct{}

func NewProjectWorkflowsController() *ProjectWorkflowsController {
	return &ProjectWorkflowsController{}
}

// ListWorkflows lists all workflows for a project
// @Summary List project workflows
// @Description Get all workflows for a project with filtering and sorting
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param is_enabled query bool false "Filter by enabled status"
// @Param trigger query string false "Filter by trigger type"
// @Success 200 {array} models.ProjectWorkflow
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows [get]
func (pwc *ProjectWorkflowsController) ListWorkflows(ctx http.Context) http.Response {
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

	var workflows []models.ProjectWorkflow

	query := querybuilder.For(&models.ProjectWorkflow{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("is_enabled"),
			querybuilder.Exact("trigger"),
			querybuilder.Partial("name"),
		).
		AllowedSorts("name", "trigger", "is_enabled", "created_at", "updated_at").
		DefaultSort("name").
		Build().
		Where("project_id = ?", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&workflows)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project workflows: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project workflows retrieved successfully", result)
}

// CreateWorkflow creates a new project workflow
// @Summary Create project workflow
// @Description Create a new workflow for a project
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectWorkflowRequest true "Workflow data"
// @Success 201 {object} models.ProjectWorkflow
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows [post]
func (pwc *ProjectWorkflowsController) CreateWorkflow(ctx http.Context) http.Response {
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

	var request requests.ProjectWorkflowRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert conditions and actions to JSON
	conditionsJSON := "{}"
	if request.Conditions != nil {
		if conditionsBytes, err := json.Marshal(request.Conditions); err == nil {
			conditionsJSON = string(conditionsBytes)
		}
	}

	actionsJSON := "{}"
	if request.Actions != nil {
		if actionsBytes, err := json.Marshal(request.Actions); err == nil {
			actionsJSON = string(actionsBytes)
		}
	}

	workflow := models.ProjectWorkflow{
		ProjectID:   projectID,
		Name:        request.Name,
		Description: request.Description,
		Trigger:     request.Trigger,
		Conditions:  conditionsJSON,
		Actions:     actionsJSON,
		IsActive:    request.IsEnabled,
	}

	if err := facades.Orm().Query().Create(&workflow); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project workflow: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project workflow created successfully",
		Data:      workflow,
		Timestamp: time.Now(),
	})
}

// GetWorkflow retrieves a specific project workflow
// @Summary Get project workflow
// @Description Get a specific project workflow by ID
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} models.ProjectWorkflow
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows/{workflow_id} [get]
func (pwc *ProjectWorkflowsController) GetWorkflow(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	workflowID := ctx.Request().Route("workflow_id")

	var workflow models.ProjectWorkflow
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", workflowID, projectID).First(&workflow); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project workflow not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project workflow retrieved successfully",
		Data:      workflow,
		Timestamp: time.Now(),
	})
}

// UpdateWorkflow updates a project workflow
// @Summary Update project workflow
// @Description Update an existing project workflow
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param workflow_id path string true "Workflow ID"
// @Param request body requests.ProjectWorkflowRequest true "Workflow data"
// @Success 200 {object} models.ProjectWorkflow
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows/{workflow_id} [patch]
func (pwc *ProjectWorkflowsController) UpdateWorkflow(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	workflowID := ctx.Request().Route("workflow_id")

	var workflow models.ProjectWorkflow
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", workflowID, projectID).First(&workflow); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project workflow not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectWorkflowRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields
	if request.Name != "" {
		workflow.Name = request.Name
	}
	if request.Description != "" {
		workflow.Description = request.Description
	}
	if request.Trigger != "" {
		workflow.Trigger = request.Trigger
	}

	// Update conditions if provided
	if request.Conditions != nil {
		if conditionsBytes, err := json.Marshal(request.Conditions); err == nil {
			workflow.Conditions = string(conditionsBytes)
		}
	}

	// Update actions if provided
	if request.Actions != nil {
		if actionsBytes, err := json.Marshal(request.Actions); err == nil {
			workflow.Actions = string(actionsBytes)
		}
	}

	workflow.IsActive = request.IsEnabled

	if err := facades.Orm().Query().Save(&workflow); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project workflow: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project workflow updated successfully",
		Data:      workflow,
		Timestamp: time.Now(),
	})
}

// DeleteWorkflow deletes a project workflow
// @Summary Delete project workflow
// @Description Delete a project workflow
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param workflow_id path string true "Workflow ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows/{workflow_id} [delete]
func (pwc *ProjectWorkflowsController) DeleteWorkflow(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	workflowID := ctx.Request().Route("workflow_id")

	var workflow models.ProjectWorkflow
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", workflowID, projectID).First(&workflow); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project workflow not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&workflow); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project workflow: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// EnableWorkflow enables a project workflow
// @Summary Enable project workflow
// @Description Enable a project workflow
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} models.ProjectWorkflow
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows/{workflow_id}/enable [post]
func (pwc *ProjectWorkflowsController) EnableWorkflow(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	workflowID := ctx.Request().Route("workflow_id")

	var workflow models.ProjectWorkflow
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", workflowID, projectID).First(&workflow); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project workflow not found",
			Timestamp: time.Now(),
		})
	}

	workflow.IsActive = true
	if err := facades.Orm().Query().Save(&workflow); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to enable project workflow: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project workflow enabled successfully",
		Data:      workflow,
		Timestamp: time.Now(),
	})
}

// DisableWorkflow disables a project workflow
// @Summary Disable project workflow
// @Description Disable a project workflow
// @Tags project-workflows
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param workflow_id path string true "Workflow ID"
// @Success 200 {object} models.ProjectWorkflow
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/workflows/{workflow_id}/disable [post]
func (pwc *ProjectWorkflowsController) DisableWorkflow(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	workflowID := ctx.Request().Route("workflow_id")

	var workflow models.ProjectWorkflow
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", workflowID, projectID).First(&workflow); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project workflow not found",
			Timestamp: time.Now(),
		})
	}

	workflow.IsActive = false
	if err := facades.Orm().Query().Save(&workflow); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to disable project workflow: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project workflow disabled successfully",
		Data:      workflow,
		Timestamp: time.Now(),
	})
}
