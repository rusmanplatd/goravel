package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectCustomFieldController struct {
	fieldService *services.ProjectCustomFieldService
}

func NewProjectCustomFieldController() *ProjectCustomFieldController {
	return &ProjectCustomFieldController{
		fieldService: services.NewProjectCustomFieldService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *ProjectCustomFieldController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index returns all custom fields for a project
// @Summary Get all project custom fields
// @Description Retrieve a list of all custom fields for a project
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param type query string false "Filter by field type"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectCustomField}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields [get]
func (c *ProjectCustomFieldController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")

	filters := make(map[string]interface{})
	if fieldType := ctx.Request().Query("type", ""); fieldType != "" {
		filters["type"] = fieldType
	}
	if isActive := ctx.Request().Query("is_active", ""); isActive != "" {
		filters["is_active"] = isActive == "true"
	}

	fields, err := c.fieldService.ListFields(projectID, filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve custom fields: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom fields retrieved successfully",
		Data:      fields,
		Timestamp: time.Now(),
	})
}

// Show returns a specific custom field
// @Summary Get a specific custom field by ID
// @Description Retrieve a specific custom field by its ID
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "Field ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectCustomField}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields/{id} [get]
func (c *ProjectCustomFieldController) Show(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	field, err := c.fieldService.GetField(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Custom field not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom field retrieved successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// Store creates a new custom field
// @Summary Create a new custom field
// @Description Create a new custom field for a project
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param request body object true "Field data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectCustomField}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields [post]
func (c *ProjectCustomFieldController) Store(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")

	var requestData map[string]interface{}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Add project ID and user info
	requestData["project_id"] = projectID
	requestData["created_by"] = &user.ID

	field, err := c.fieldService.CreateField(requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create custom field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom field created successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// Update updates a custom field
// @Summary Update a custom field
// @Description Update an existing custom field
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "Field ID"
// @Param request body object true "Field data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectCustomField}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields/{id} [put]
func (c *ProjectCustomFieldController) Update(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	var requestData map[string]interface{}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	requestData["updated_by"] = &user.ID

	field, err := c.fieldService.UpdateField(id, requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update custom field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom field updated successfully",
		Data:      field,
		Timestamp: time.Now(),
	})
}

// Delete deletes a custom field
// @Summary Delete a custom field
// @Description Delete an existing custom field
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "Field ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields/{id} [delete]
func (c *ProjectCustomFieldController) Delete(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	err := c.fieldService.DeleteField(id, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete custom field: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom field deleted successfully",
		Timestamp: time.Now(),
	})
}

// Reorder updates the position of multiple fields
// @Summary Reorder custom fields
// @Description Update the position of multiple custom fields
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param request body object true "Field positions map"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/custom-fields/reorder [post]
func (c *ProjectCustomFieldController) Reorder(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	var requestData struct {
		FieldPositions map[string]int `json:"field_positions" binding:"required"`
	}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	err := c.fieldService.ReorderFields(requestData.FieldPositions, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to reorder custom fields: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Custom fields reordered successfully",
		Timestamp: time.Now(),
	})
}

// SetTaskFieldValue sets a custom field value for a task
// @Summary Set task field value
// @Description Set a custom field value for a task
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param task_id path string true "Task ID"
// @Param field_id path string true "Field ID"
// @Param request body object true "Field value"
// @Success 200 {object} responses.APIResponse{data=models.TaskFieldValue}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/tasks/{task_id}/fields/{field_id} [post]
func (c *ProjectCustomFieldController) SetTaskFieldValue(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	taskID := ctx.Request().Route("task_id")
	fieldID := ctx.Request().Route("field_id")

	var requestData struct {
		Value interface{} `json:"value" binding:"required"`
	}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	fieldValue, err := c.fieldService.SetFieldValue(taskID, fieldID, requestData.Value, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to set field value: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Field value set successfully",
		Data:      fieldValue,
		Timestamp: time.Now(),
	})
}

// GetTaskFieldValues gets all custom field values for a task
// @Summary Get task field values
// @Description Get all custom field values for a task
// @Tags project-custom-fields
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param task_id path string true "Task ID"
// @Success 200 {object} responses.APIResponse{data=[]models.TaskFieldValue}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/tasks/{task_id}/fields [get]
func (c *ProjectCustomFieldController) GetTaskFieldValues(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	taskID := ctx.Request().Route("task_id")

	fieldValues, err := c.fieldService.GetTaskFieldValues(taskID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to get field values: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Field values retrieved successfully",
		Data:      fieldValues,
		Timestamp: time.Now(),
	})
}
