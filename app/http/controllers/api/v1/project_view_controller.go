package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectViewController struct {
	viewService *services.ProjectViewService
}

func NewProjectViewController() *ProjectViewController {
	return &ProjectViewController{
		viewService: services.NewProjectViewService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *ProjectViewController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index returns all views for a project
// @Summary Get all project views
// @Description Retrieve a list of all views for a project
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param type query string false "Filter by view type"
// @Param is_public query bool false "Filter by public status"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectView}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views [get]
func (c *ProjectViewController) Index(ctx http.Context) http.Response {
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
	if viewType := ctx.Request().Query("type", ""); viewType != "" {
		filters["type"] = viewType
	}
	if isPublic := ctx.Request().Query("is_public", ""); isPublic != "" {
		filters["is_public"] = isPublic == "true"
	}

	views, err := c.viewService.ListViews(projectID, filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve views: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Views retrieved successfully",
		Data:      views,
		Timestamp: time.Now(),
	})
}

// Show returns a specific project view
// @Summary Get a specific project view by ID
// @Description Retrieve a specific project view by its ID
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "View ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectView}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views/{id} [get]
func (c *ProjectViewController) Show(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	view, err := c.viewService.GetView(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View retrieved successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// Store creates a new project view
// @Summary Create a new project view
// @Description Create a new view for a project
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param request body object true "View data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectView}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views [post]
func (c *ProjectViewController) Store(ctx http.Context) http.Response {
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

	view, err := c.viewService.CreateView(requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View created successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// Update updates a project view
// @Summary Update a project view
// @Description Update an existing project view
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "View ID"
// @Param request body object true "View data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectView}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views/{id} [put]
func (c *ProjectViewController) Update(ctx http.Context) http.Response {
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

	view, err := c.viewService.UpdateView(id, requestData)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View updated successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// Delete deletes a project view
// @Summary Delete a project view
// @Description Delete an existing project view
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "View ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views/{id} [delete]
func (c *ProjectViewController) Delete(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	err := c.viewService.DeleteView(id, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View deleted successfully",
		Timestamp: time.Now(),
	})
}

// SetDefault sets a view as the default for a project
// @Summary Set default project view
// @Description Set a view as the default for a project
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "View ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views/{id}/set-default [post]
func (c *ProjectViewController) SetDefault(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	err := c.viewService.SetDefaultView(id, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to set default view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Default view set successfully",
		Timestamp: time.Now(),
	})
}

// Duplicate creates a copy of an existing view
// @Summary Duplicate a project view
// @Description Create a copy of an existing project view
// @Tags project-views
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param id path string true "View ID"
// @Param request body object true "Duplicate data with new name"
// @Success 201 {object} responses.APIResponse{data=models.ProjectView}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/views/{id}/duplicate [post]
func (c *ProjectViewController) Duplicate(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	id := ctx.Request().Route("id")

	var requestData struct {
		Name string `json:"name" binding:"required"`
	}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	view, err := c.viewService.DuplicateView(id, requestData.Name, &user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to duplicate view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View duplicated successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}
