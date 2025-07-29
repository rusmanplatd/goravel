package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
	"goravel/app/services"
)

type ProjectsController struct {
	organizationService *services.OrganizationService
}

func NewProjectsController() *ProjectsController {
	return &ProjectsController{
		organizationService: services.NewOrganizationService(),
	}
}

// ListOrgProjects lists all projects for an organization with GitHub Projects v2 style filtering
func (pc *ProjectsController) ListOrgProjects(ctx http.Context) http.Response {
	orgID := ctx.Request().Route("org_id")
	state := ctx.Request().Query("state", "open")        // GitHub Projects style: open, closed, all
	visibility := ctx.Request().Query("visibility", "")  // private, public
	archived := ctx.Request().Query("archived", "false") // Include archived projects

	var projects []models.Project

	query := querybuilder.For(&models.Project{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("status"),
			querybuilder.Exact("state"),
			querybuilder.Exact("visibility"),
			querybuilder.Exact("priority"),
			querybuilder.Partial("name"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_archived"),
			querybuilder.Exact("owner_id"),
			querybuilder.Exact("template_id"),
		).
		AllowedSorts("name", "state", "visibility", "priority", "created_at", "updated_at", "closed_at", "archived_at").
		DefaultSort("-created_at").
		AllowedIncludes("organization", "owner", "template", "teams", "users", "tasks", "views", "custom_fields").
		Build().
		Where("organization_id = ?", orgID)

	// Apply state filter (GitHub Projects style)
	if state == "closed" {
		query = query.Where("state = ?", "closed")
	} else if state == "open" {
		query = query.Where("state = ?", "open")
	}
	// "all" shows both open and closed

	// Apply visibility filter
	if visibility != "" {
		query = query.Where("visibility = ?", visibility)
	}

	// Apply archived filter
	if archived == "false" {
		query = query.Where("is_archived = ?", false)
	} else if archived == "true" {
		query = query.Where("is_archived = ?", true)
	}
	// "all" shows both archived and non-archived

	// Use pagination
	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&projects)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve projects: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Projects retrieved successfully", result)
}

// CreateOrgProject creates a new project with GitHub Projects v2 features
func (pc *ProjectsController) CreateOrgProject(ctx http.Context) http.Response {
	orgID := ctx.Request().Route("org_id")
	userID := ctx.Value("user_id").(string)

	var request requests.ModernProjectRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	project := models.Project{
		Name:           request.Name,
		Description:    request.Description,
		Readme:         request.Readme,
		Status:         "planning",
		State:          "open",    // GitHub Projects style default
		Visibility:     "private", // GitHub Projects style default
		Priority:       "medium",
		OrganizationID: orgID,
		OwnerID:        &userID, // Set current user as owner
		IsActive:       true,
		IsArchived:     false,
		IsTemplate:     false,
	}

	// Apply optional fields
	if request.Status != "" {
		project.Status = request.Status
	}
	if request.State != "" {
		project.State = request.State
	}
	if request.Priority != "" {
		project.Priority = request.Priority
	}
	if request.Visibility != "" {
		project.Visibility = request.Visibility
	}
	if request.OwnerID != nil {
		project.OwnerID = request.OwnerID
	}
	if request.TemplateID != nil {
		project.TemplateID = request.TemplateID
	}
	if request.Color != "" {
		project.Color = request.Color
	}
	if request.Icon != "" {
		project.Icon = request.Icon
	}

	if err := facades.Orm().Query().Create(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project created successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// ListUserProjects lists all projects for the authenticated user
func (pc *ProjectsController) ListUserProjects(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	state := ctx.Request().Query("state", "open")
	visibility := ctx.Request().Query("visibility", "")

	var projects []models.Project

	query := querybuilder.For(&models.Project{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("status"),
			querybuilder.Exact("state"),
			querybuilder.Exact("visibility"),
			querybuilder.Exact("priority"),
			querybuilder.Partial("name"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_archived"),
		).
		AllowedSorts("name", "state", "visibility", "priority", "created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("owner_id = ? OR id IN (SELECT project_id FROM user_projects WHERE user_id = ?)", userID, userID)

	// Apply state filter
	if state == "closed" {
		query = query.Where("state = ?", "closed")
	} else if state == "open" {
		query = query.Where("state = ?", "open")
	}

	// Apply visibility filter
	if visibility != "" {
		query = query.Where("visibility = ?", visibility)
	}

	// Exclude archived by default
	query = query.Where("is_archived = ?", false)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&projects)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve projects: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Projects retrieved successfully", result)
}

// CreateUserProject creates a new project for the authenticated user
func (pc *ProjectsController) CreateUserProject(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	var request requests.ModernProjectRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	project := models.Project{
		Name:        request.Name,
		Description: request.Description,
		Readme:      request.Readme,
		Status:      "planning",
		State:       "open",
		Visibility:  "private",
		Priority:    "medium",
		OwnerID:     &userID,
		IsActive:    true,
		IsArchived:  false,
		IsTemplate:  false,
	}

	// Apply optional fields
	if request.Status != "" {
		project.Status = request.Status
	}
	if request.State != "" {
		project.State = request.State
	}
	if request.Priority != "" {
		project.Priority = request.Priority
	}
	if request.Visibility != "" {
		project.Visibility = request.Visibility
	}
	if request.TemplateID != nil {
		project.TemplateID = request.TemplateID
	}
	if request.Color != "" {
		project.Color = request.Color
	}
	if request.Icon != "" {
		project.Icon = request.Icon
	}

	if err := facades.Orm().Query().Create(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project created successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// GetProject retrieves a specific project
func (pc *ProjectsController) GetProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().
		With("Organization", "Owner", "Template", "Views", "CustomFields").
		Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project retrieved successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// UpdateProject updates a specific project with GitHub Projects v2 features
func (pc *ProjectsController) UpdateProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ModernProjectUpdateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		project.Name = request.Name
	}
	if request.Description != "" {
		project.Description = request.Description
	}
	if request.Readme != "" {
		project.Readme = request.Readme
	}
	if request.Status != "" {
		project.Status = request.Status
	}
	if request.State != "" {
		project.State = request.State
		// Set closed_at timestamp when closing
		if request.State == "closed" && project.ClosedAt == nil {
			now := time.Now()
			project.ClosedAt = &now
		} else if request.State == "open" {
			project.ClosedAt = nil
		}
	}
	if request.Priority != "" {
		project.Priority = request.Priority
	}
	if request.Visibility != "" {
		project.Visibility = request.Visibility
	}
	if request.OwnerID != nil {
		project.OwnerID = request.OwnerID
	}
	if request.Color != "" {
		project.Color = request.Color
	}
	if request.Icon != "" {
		project.Icon = request.Icon
	}

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project updated successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// CloseProject closes a project (GitHub Projects v2 style)
func (pc *ProjectsController) CloseProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if project.State == "closed" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project is already closed",
			Timestamp: time.Now(),
		})
	}

	project.State = "closed"
	now := time.Now()
	project.ClosedAt = &now

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to close project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project closed successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// ReopenProject reopens a closed project (GitHub Projects v2 style)
func (pc *ProjectsController) ReopenProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if project.State == "open" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project is already open",
			Timestamp: time.Now(),
		})
	}

	project.State = "open"
	project.ClosedAt = nil

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to reopen project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project reopened successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// ArchiveProject archives a project (GitHub Projects v2 style)
func (pc *ProjectsController) ArchiveProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if project.IsArchived {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project is already archived",
			Timestamp: time.Now(),
		})
	}

	project.IsArchived = true
	now := time.Now()
	project.ArchivedAt = &now

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

// UnarchiveProject unarchives a project (GitHub Projects v2 style)
func (pc *ProjectsController) UnarchiveProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if !project.IsArchived {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project is not archived",
			Timestamp: time.Now(),
		})
	}

	project.IsArchived = false
	project.ArchivedAt = nil

	if err := facades.Orm().Query().Save(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to unarchive project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project unarchived successfully",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// DuplicateProject creates a copy of an existing project (GitHub Projects v2 style)
func (pc *ProjectsController) DuplicateProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var originalProject models.Project
	if err := facades.Orm().Query().
		With("Views", "CustomFields").
		Where("id = ?", projectID).First(&originalProject); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	var request struct {
		Name          string `json:"name" validate:"required,min=2,max=255"`
		IncludeViews  bool   `json:"include_views"`
		IncludeFields bool   `json:"include_fields"`
		IncludeTasks  bool   `json:"include_tasks"`
	}
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create new project
	newProject := models.Project{
		Name:           request.Name,
		Description:    originalProject.Description,
		Readme:         originalProject.Readme,
		Status:         "planning", // Reset to planning
		State:          "open",     // Reset to open
		Visibility:     originalProject.Visibility,
		Priority:       originalProject.Priority,
		Color:          originalProject.Color,
		Icon:           originalProject.Icon,
		OrganizationID: originalProject.OrganizationID,
		OwnerID:        &userID, // Set current user as owner
		IsActive:       true,
		IsArchived:     false,
		IsTemplate:     false,
		Settings:       originalProject.Settings,
	}

	if err := facades.Orm().Query().Create(&newProject); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to duplicate project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Duplicate views if requested
	if request.IncludeViews {
		for _, view := range originalProject.Views {
			newView := models.ProjectView{
				Name:        view.Name,
				Description: view.Description,
				Type:        view.Type,
				Layout:      view.Layout,
				Filters:     view.Filters,
				Sorting:     view.Sorting,
				Grouping:    view.Grouping,
				IsDefault:   view.IsDefault,
				IsPublic:    view.IsPublic,
				Position:    view.Position,
				ProjectID:   newProject.ID,
			}
			facades.Orm().Query().Create(&newView)
		}
	}

	// Duplicate custom fields if requested
	if request.IncludeFields {
		for _, field := range originalProject.CustomFields {
			newField := models.ProjectCustomField{
				Name:        field.Name,
				Description: field.Description,
				Type:        field.Type,
				Options:     field.Options,
				IsRequired:  field.IsRequired,
				Position:    field.Position,
				IsActive:    field.IsActive,
				ProjectID:   newProject.ID,
			}
			facades.Orm().Query().Create(&newField)
		}
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project duplicated successfully",
		Data:      newProject,
		Timestamp: time.Now(),
	})
}

// DeleteProject deletes a project
func (pc *ProjectsController) DeleteProject(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&project); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}
