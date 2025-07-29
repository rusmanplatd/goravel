package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectAutomationsController struct{}

func NewProjectAutomationsController() *ProjectAutomationsController {
	return &ProjectAutomationsController{}
}

// ListAutomations lists all automations for a project
// @Summary List project automations
// @Description Get all automations for a project (GitHub Actions-style)
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param enabled query bool false "Filter by enabled status"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectAutomation}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations [get]
func (pac *ProjectAutomationsController) ListAutomations(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	enabled := ctx.Request().Query("enabled", "")

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
	if enabled == "true" {
		query = query.Where("is_enabled = ?", true)
	} else if enabled == "false" {
		query = query.Where("is_enabled = ?", false)
	}

	var automations []models.ProjectAutomation
	if err := query.Order("created_at DESC").Find(&automations); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project automations: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automations retrieved successfully",
		Data:      automations,
		Timestamp: time.Now(),
	})
}

// CreateAutomation creates a new automation for a project
// @Summary Create project automation
// @Description Create a new automation for a project (GitHub Actions-style)
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation body requests.ProjectAutomationRequest true "Automation data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectAutomation}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations [post]
func (pac *ProjectAutomationsController) CreateAutomation(ctx http.Context) http.Response {
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

	var request requests.ProjectAutomationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert conditions and actions to JSON
	conditionsJSON, err := json.Marshal(request.Conditions)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid conditions format: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	actionsJSON, err := json.Marshal(request.Actions)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid actions format: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	automation := models.ProjectAutomation{
		Name:         request.Name,
		Description:  request.Description,
		TriggerEvent: request.TriggerEvent,
		Conditions:   string(conditionsJSON),
		Actions:      string(actionsJSON),
		IsEnabled:    request.IsEnabled,
		RunsCount:    0,
		ProjectID:    projectID,
	}

	if err := facades.Orm().Query().Create(&automation); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project automation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automation created successfully",
		Data:      automation,
		Timestamp: time.Now(),
	})
}

// GetAutomation retrieves a specific project automation
// @Summary Get project automation
// @Description Get details of a specific project automation
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation_id path string true "Automation ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectAutomation}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations/{automation_id} [get]
func (pac *ProjectAutomationsController) GetAutomation(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	automationID := ctx.Request().Route("automation_id")

	var automation models.ProjectAutomation
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", automationID, projectID).First(&automation); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project automation not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automation retrieved successfully",
		Data:      automation,
		Timestamp: time.Now(),
	})
}

// UpdateAutomation updates a project automation
// @Summary Update project automation
// @Description Update an existing project automation
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation_id path string true "Automation ID"
// @Param automation body requests.ProjectAutomationRequest true "Automation data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectAutomation}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations/{automation_id} [patch]
func (pac *ProjectAutomationsController) UpdateAutomation(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	automationID := ctx.Request().Route("automation_id")

	var automation models.ProjectAutomation
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", automationID, projectID).First(&automation); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project automation not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectAutomationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert conditions and actions to JSON
	conditionsJSON, err := json.Marshal(request.Conditions)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid conditions format: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	actionsJSON, err := json.Marshal(request.Actions)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid actions format: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields
	automation.Name = request.Name
	automation.Description = request.Description
	automation.TriggerEvent = request.TriggerEvent
	automation.Conditions = string(conditionsJSON)
	automation.Actions = string(actionsJSON)
	automation.IsEnabled = request.IsEnabled

	if err := facades.Orm().Query().Save(&automation); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project automation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automation updated successfully",
		Data:      automation,
		Timestamp: time.Now(),
	})
}

// DeleteAutomation deletes a project automation
// @Summary Delete project automation
// @Description Delete a project automation
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation_id path string true "Automation ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations/{automation_id} [delete]
func (pac *ProjectAutomationsController) DeleteAutomation(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	automationID := ctx.Request().Route("automation_id")

	var automation models.ProjectAutomation
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", automationID, projectID).First(&automation); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project automation not found",
			Timestamp: time.Now(),
		})
	}

	// Delete the automation
	_, err := facades.Orm().Query().Delete(&automation)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project automation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automation deleted successfully",
		Timestamp: time.Now(),
	})
}

// ToggleAutomation enables or disables a project automation
// @Summary Toggle project automation
// @Description Enable or disable a project automation
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation_id path string true "Automation ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectAutomation}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations/{automation_id}/toggle [post]
func (pac *ProjectAutomationsController) ToggleAutomation(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	automationID := ctx.Request().Route("automation_id")

	var automation models.ProjectAutomation
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", automationID, projectID).First(&automation); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project automation not found",
			Timestamp: time.Now(),
		})
	}

	// Toggle enabled status
	automation.IsEnabled = !automation.IsEnabled

	if err := facades.Orm().Query().Save(&automation); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to toggle project automation: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	status := "disabled"
	if automation.IsEnabled {
		status = "enabled"
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project automation " + status + " successfully",
		Data:      automation,
		Timestamp: time.Now(),
	})
}

// TriggerAutomation manually triggers an automation for testing
// @Summary Trigger project automation
// @Description Manually trigger a project automation for testing
// @Tags project-automations
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param automation_id path string true "Automation ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/automations/{automation_id}/trigger [post]
func (pac *ProjectAutomationsController) TriggerAutomation(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	automationID := ctx.Request().Route("automation_id")

	var automation models.ProjectAutomation
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", automationID, projectID).First(&automation); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project automation not found",
			Timestamp: time.Now(),
		})
	}

	if !automation.IsEnabled {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Automation is disabled",
			Timestamp: time.Now(),
		})
	}

	// Update run statistics
	now := time.Now()
	automation.RunsCount++
	automation.LastRunAt = &now

	if err := facades.Orm().Query().Save(&automation); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update automation statistics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Here you would implement the actual automation logic
	// For now, we'll just return a success response
	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Project automation triggered successfully",
		Data: map[string]interface{}{
			"automation_id": automationID,
			"triggered_at":  now,
			"runs_count":    automation.RunsCount,
		},
		Timestamp: time.Now(),
	})
}
