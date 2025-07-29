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

type ProjectFieldsController struct{}

func NewProjectFieldsController() *ProjectFieldsController {
	return &ProjectFieldsController{}
}

// ListFields lists all custom fields in a project
func (pfc *ProjectFieldsController) ListFields(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var fields []models.ProjectCustomField
	if err := facades.Orm().Query().Where("project_id = ?", projectID).Find(&fields); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project fields: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project fields retrieved successfully",
		Data:      fields,
		Timestamp: time.Now(),
	})
}

// CreateField creates a new custom field
func (pfc *ProjectFieldsController) CreateField(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.ProjectFieldRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	field := models.ProjectCustomField{
		ProjectID:   projectID,
		Name:        request.Name,
		Type:        request.DataType,
		Description: request.Description,
		IsRequired:  false,
	}

	if err := facades.Orm().Query().Create(&field); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project field created successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// GetField retrieves a specific custom field
func (pfc *ProjectFieldsController) GetField(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	fieldID := ctx.Request().Route("field_id")

	var field models.ProjectCustomField
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", fieldID, projectID).First(&field); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project field not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project field retrieved successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// UpdateField updates a custom field
// @Summary Update project field
// @Description Update an existing custom field
// @Tags project-fields
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param field_id path string true "Field ID"
// @Param request body requests.ProjectFieldRequest true "Field data"
// @Success 200 {object} models.ProjectCustomField
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/fields/{field_id} [patch]
func (pfc *ProjectFieldsController) UpdateField(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	fieldID := ctx.Request().Route("field_id")

	var field models.ProjectCustomField
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", fieldID, projectID).First(&field); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project field not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectFieldRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields
	if request.Name != "" {
		field.Name = request.Name
	}
	if request.Description != "" {
		field.Description = request.Description
	}
	if request.DataType != "" {
		field.Type = request.DataType
	}

	// Update options if provided
	if len(request.Options) > 0 {
		optionsMap := map[string]interface{}{
			"options": request.Options,
		}
		if optionsJSON, err := json.Marshal(optionsMap); err == nil {
			field.Options = string(optionsJSON)
		}
	}

	if err := facades.Orm().Query().Save(&field); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project field updated successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// DeleteField deletes a custom field
func (pfc *ProjectFieldsController) DeleteField(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	fieldID := ctx.Request().Route("field_id")

	var field models.ProjectCustomField
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", fieldID, projectID).First(&field); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project field not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&field); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}
