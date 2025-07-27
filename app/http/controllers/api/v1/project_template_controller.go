package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectTemplateController struct {
	templateService *services.ProjectTemplateService
}

func NewProjectTemplateController() *ProjectTemplateController {
	return &ProjectTemplateController{
		templateService: services.NewProjectTemplateService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *ProjectTemplateController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index returns all project templates
// @Summary Get all project templates
// @Description Retrieve a list of all project templates with filtering
// @Tags project-templates
// @Accept json
// @Produce json
// @Param category query string false "Filter by template category"
// @Param is_public query bool false "Filter by public status"
// @Param is_featured query bool false "Filter by featured status"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectTemplate}
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates [get]
func (c *ProjectTemplateController) Index(ctx http.Context) http.Response {
	filters := make(map[string]interface{})

	if category := ctx.Request().Query("category", ""); category != "" {
		filters["category"] = category
	}
	if isPublic := ctx.Request().Query("is_public", ""); isPublic != "" {
		filters["is_public"] = isPublic == "true"
	}
	if isFeatured := ctx.Request().Query("is_featured", ""); isFeatured != "" {
		filters["is_featured"] = isFeatured == "true"
	}

	templates, err := c.templateService.ListTemplates(filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve templates: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Templates retrieved successfully",
		Data:      templates,
		Timestamp: time.Now(),
	})
}

// Show returns a specific template
// @Summary Get a specific template by ID
// @Description Retrieve a specific project template by its ID
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectTemplate}
// @Failure 404 {object} responses.ErrorResponse
// @Router /templates/{id} [get]
func (c *ProjectTemplateController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	template, err := c.templateService.GetTemplate(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Template not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Template retrieved successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Store creates a new template
// @Summary Create a new project template
// @Description Create a new project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param request body object true "Template data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectTemplate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates [post]
func (c *ProjectTemplateController) Store(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	var requestData map[string]interface{}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	requestData["created_by"] = &user.ID

	template, err := c.templateService.CreateTemplate(requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Template created successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Update updates a template
// @Summary Update a project template
// @Description Update an existing project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param request body object true "Template data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectTemplate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/{id} [put]
func (c *ProjectTemplateController) Update(ctx http.Context) http.Response {
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

	template, err := c.templateService.UpdateTemplate(id, requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Template updated successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Delete deletes a template
// @Summary Delete a project template
// @Description Delete an existing project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/{id} [delete]
func (c *ProjectTemplateController) Delete(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	err := c.templateService.DeleteTemplate(id, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Template deleted successfully",
		Timestamp: time.Now(),
	})
}

// UseTemplate creates a project from a template
// @Summary Create project from template
// @Description Create a new project using an existing template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param request body object true "Project data"
// @Success 201 {object} responses.APIResponse{data=models.Project}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/{id}/use [post]
func (c *ProjectTemplateController) UseTemplate(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	templateID := ctx.Request().Route("id")

	var requestData map[string]interface{}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	requestData["created_by"] = &user.ID

	project, err := c.templateService.UseTemplate(templateID, requestData, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project from template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project created from template successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// Featured returns featured templates
// @Summary Get featured templates
// @Description Retrieve a list of featured project templates
// @Tags project-templates
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectTemplate}
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/featured [get]
func (c *ProjectTemplateController) Featured(ctx http.Context) http.Response {
	templates, err := c.templateService.GetFeaturedTemplates()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve featured templates: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Featured templates retrieved successfully",
		Data:      templates,
		Timestamp: time.Now(),
	})
}

// Category returns templates by category
// @Summary Get templates by category
// @Description Retrieve templates filtered by category
// @Tags project-templates
// @Accept json
// @Produce json
// @Param category path string true "Template category"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectTemplate}
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/category/{category} [get]
func (c *ProjectTemplateController) Category(ctx http.Context) http.Response {
	category := ctx.Request().Route("category")

	templates, err := c.templateService.GetTemplatesByCategory(category)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve templates by category: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Templates retrieved successfully",
		Data:      templates,
		Timestamp: time.Now(),
	})
}
