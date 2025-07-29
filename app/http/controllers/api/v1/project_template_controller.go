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

type ProjectTemplateController struct{}

func NewProjectTemplateController() *ProjectTemplateController {
	return &ProjectTemplateController{}
}

// Index lists all project templates
// @Summary List project templates
// @Description Get all project templates with filtering and sorting
// @Tags project-templates
// @Accept json
// @Produce json
// @Param category query string false "Filter by category (development, marketing, design, general)"
// @Param is_public query bool false "Filter by public status"
// @Param is_featured query bool false "Filter by featured status"
// @Success 200 {array} models.ProjectTemplate
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates [get]
func (ptc *ProjectTemplateController) Index(ctx http.Context) http.Response {
	var templates []models.ProjectTemplate

	query := querybuilder.For(&models.ProjectTemplate{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("category"),
			querybuilder.Exact("is_public"),
			querybuilder.Exact("is_featured"),
			querybuilder.Partial("name"),
		).
		AllowedSorts("name", "category", "usage_count", "created_at", "updated_at").
		DefaultSort("-is_featured", "-usage_count", "name").
		Build()

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&templates)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project templates: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project templates retrieved successfully", result)
}

// Store creates a new project template
// @Summary Create project template
// @Description Create a new project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param request body requests.ProjectTemplateRequest true "Template data"
// @Success 201 {object} models.ProjectTemplate
// @Failure 400 {object} responses.ErrorResponse
// @Router /templates [post]
func (ptc *ProjectTemplateController) Store(ctx http.Context) http.Response {
	var request requests.ProjectTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Convert configuration to JSON
	configJSON := "{}"
	if request.Configuration != nil {
		if configBytes, err := json.Marshal(request.Configuration); err == nil {
			configJSON = string(configBytes)
		}
	}

	template := models.ProjectTemplate{
		Name:          request.Name,
		Description:   request.Description,
		Category:      request.Category,
		Icon:          request.Icon,
		Color:         request.Color,
		IsPublic:      request.IsPublic,
		IsFeatured:    false, // Only admins can set featured
		Configuration: configJSON,
		UsageCount:    0,
	}

	// Set organization ID if provided (for organization-specific templates)
	if request.OrganizationID != nil {
		template.OrganizationID = request.OrganizationID
	}

	if err := facades.Orm().Query().Create(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project template created successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Show retrieves a specific project template
// @Summary Get project template
// @Description Get a specific project template by ID
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} models.ProjectTemplate
// @Failure 404 {object} responses.ErrorResponse
// @Router /templates/{id} [get]
func (ptc *ProjectTemplateController) Show(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	var template models.ProjectTemplate
	if err := facades.Orm().Query().Where("id = ?", templateID).First(&template); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project template not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project template retrieved successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Update updates a project template
// @Summary Update project template
// @Description Update an existing project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param request body requests.ProjectTemplateRequest true "Template data"
// @Success 200 {object} models.ProjectTemplate
// @Failure 404 {object} responses.ErrorResponse
// @Router /templates/{id} [put]
func (ptc *ProjectTemplateController) Update(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	var template models.ProjectTemplate
	if err := facades.Orm().Query().Where("id = ?", templateID).First(&template); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project template not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields
	if request.Name != "" {
		template.Name = request.Name
	}
	if request.Description != "" {
		template.Description = request.Description
	}
	if request.Category != "" {
		template.Category = request.Category
	}
	if request.Icon != "" {
		template.Icon = request.Icon
	}
	if request.Color != "" {
		template.Color = request.Color
	}
	template.IsPublic = request.IsPublic

	// Update configuration if provided
	if request.Configuration != nil {
		if configBytes, err := json.Marshal(request.Configuration); err == nil {
			template.Configuration = string(configBytes)
		}
	}

	if err := facades.Orm().Query().Save(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project template updated successfully",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Destroy deletes a project template
// @Summary Delete project template
// @Description Delete a project template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /templates/{id} [delete]
func (ptc *ProjectTemplateController) Destroy(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	var template models.ProjectTemplate
	if err := facades.Orm().Query().Where("id = ?", templateID).First(&template); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project template not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// UseTemplate creates a new project from a template
// @Summary Use project template
// @Description Create a new project from an existing template
// @Tags project-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param request body requests.UseTemplateRequest true "Project creation data"
// @Success 201 {object} models.Project
// @Failure 404 {object} responses.ErrorResponse
// @Router /templates/{id}/use [post]
func (ptc *ProjectTemplateController) UseTemplate(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	var template models.ProjectTemplate
	if err := facades.Orm().Query().Where("id = ?", templateID).First(&template); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project template not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.UseTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Start transaction
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to start transaction: " + err.Error(),
			Timestamp: time.Now(),
		})
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create project from template
	project := models.Project{
		Name:           request.Name,
		Description:    request.Description,
		Status:         "planning",
		Priority:       "medium",
		Color:          template.Color,
		Icon:           template.Icon,
		IsActive:       true,
		OrganizationID: request.OrganizationID,
	}

	if err := tx.Create(&project); err != nil {
		tx.Rollback()
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project from template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Parse template configuration
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(template.Configuration), &config); err == nil {
		// Create default views from template
		if defaultViews, ok := config["default_views"].([]interface{}); ok {
			for i, viewData := range defaultViews {
				if viewMap, ok := viewData.(map[string]interface{}); ok {
					view := models.ProjectView{
						ProjectID:   project.ID,
						Name:        viewMap["name"].(string),
						Type:        viewMap["type"].(string),
						Description: "Created from template",
						Layout:      "{}",
						IsDefault:   i == 0, // First view is default
						IsPublic:    true,
						Position:    i + 1,
					}
					tx.Create(&view)
				}
			}
		}

		// Create custom fields from template
		if customFields, ok := config["custom_fields"].([]interface{}); ok {
			for i, fieldData := range customFields {
				if fieldMap, ok := fieldData.(map[string]interface{}); ok {
					field := models.ProjectCustomField{
						ProjectID:   project.ID,
						Name:        fieldMap["name"].(string),
						Type:        fieldMap["type"].(string),
						Description: "Created from template",
						Options:     "{}",
						IsRequired:  false,
						IsActive:    true,
						Position:    i + 1,
					}
					tx.Create(&field)
				}
			}
		}
	}

	// Increment template usage count
	template.UsageCount++
	tx.Save(&template)

	// Commit transaction
	if err := tx.Commit(); err != nil {
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

// Featured lists featured project templates
// @Summary List featured templates
// @Description Get all featured project templates
// @Tags project-templates
// @Accept json
// @Produce json
// @Success 200 {array} models.ProjectTemplate
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/featured [get]
func (ptc *ProjectTemplateController) Featured(ctx http.Context) http.Response {
	var templates []models.ProjectTemplate

	if err := facades.Orm().Query().Where("is_featured = ? AND is_public = ?", true, true).
		Order("usage_count DESC, name ASC").
		Find(&templates); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve featured templates: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Featured templates retrieved successfully",
		Data:      templates,
		Timestamp: time.Now(),
	})
}

// Categories lists templates by category
// @Summary List templates by category
// @Description Get all templates in a specific category
// @Tags project-templates
// @Accept json
// @Produce json
// @Param category path string true "Category name"
// @Success 200 {array} models.ProjectTemplate
// @Failure 500 {object} responses.ErrorResponse
// @Router /templates/category/{category} [get]
func (ptc *ProjectTemplateController) Categories(ctx http.Context) http.Response {
	category := ctx.Request().Route("category")

	var templates []models.ProjectTemplate

	if err := facades.Orm().Query().Where("category = ? AND is_public = ?", category, true).
		Order("is_featured DESC, usage_count DESC, name ASC").
		Find(&templates); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve templates by category: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Templates retrieved successfully",
		Data:      templates,
		Timestamp: time.Now(),
	})
}
