package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectViewsController struct{}

func NewProjectViewsController() *ProjectViewsController {
	return &ProjectViewsController{}
}

// ListViews lists all views for a project
func (pvc *ProjectViewsController) ListViews(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	viewType := ctx.Request().Query("type", "")

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

	// Filter by view type
	if viewType != "" {
		query = query.Where("type = ?", viewType)
	}

	var views []models.ProjectView
	if err := query.Order("position ASC, created_at ASC").Find(&views); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve views: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Views retrieved successfully",
		Data:      views,
		Timestamp: time.Now(),
	})
}

// CreateView creates a new view for a project
func (pvc *ProjectViewsController) CreateView(ctx http.Context) http.Response {
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

	var request ProjectViewRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if view name already exists for this project
	var existingView models.ProjectView
	if err := facades.Orm().Query().Where("project_id = ? AND name = ?", projectID, request.Name).First(&existingView); err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View with this name already exists",
			Timestamp: time.Now(),
		})
	}

	// Get next position
	var maxPosition int
	facades.Orm().Query().Model(&models.ProjectView{}).Where("project_id = ?", projectID).
		Select("COALESCE(MAX(position), 0)").Scan(&maxPosition)

	// If this is set as default, unset other default views
	if request.IsDefault {
		facades.Orm().Query().Model(&models.ProjectView{}).
			Where("project_id = ? AND is_default = ?", projectID, true).
			Update("is_default", false)
	}

	// Convert configuration to JSON strings
	layoutJSON := "{}"
	if request.Layout != nil {
		if layoutBytes, err := json.Marshal(request.Layout); err == nil {
			layoutJSON = string(layoutBytes)
		}
	}

	filtersJSON := "{}"
	if request.Filters != nil {
		if filtersBytes, err := json.Marshal(request.Filters); err == nil {
			filtersJSON = string(filtersBytes)
		}
	}

	sortingJSON := "{}"
	if request.Sorting != nil {
		if sortingBytes, err := json.Marshal(request.Sorting); err == nil {
			sortingJSON = string(sortingBytes)
		}
	}

	groupingJSON := "{}"
	if request.Grouping != nil {
		if groupingBytes, err := json.Marshal(request.Grouping); err == nil {
			groupingJSON = string(groupingBytes)
		}
	}

	view := models.ProjectView{
		Name:        request.Name,
		Description: request.Description,
		Type:        request.Type,
		Layout:      layoutJSON,
		Filters:     filtersJSON,
		Sorting:     sortingJSON,
		Grouping:    groupingJSON,
		IsDefault:   request.IsDefault,
		IsPublic:    request.IsPublic,
		Position:    maxPosition + 1,
		ProjectID:   projectID,
	}

	if err := facades.Orm().Query().Create(&view); err != nil {
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

// GetView retrieves a specific view
func (pvc *ProjectViewsController) GetView(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	viewID := ctx.Request().Route("view_id")

	var view models.ProjectView
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", viewID, projectID).First(&view); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "View retrieved successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// UpdateView updates a view
func (pvc *ProjectViewsController) UpdateView(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	viewID := ctx.Request().Route("view_id")

	var view models.ProjectView
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", viewID, projectID).First(&view); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View not found",
			Timestamp: time.Now(),
		})
	}

	var request ProjectViewRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if view name already exists for this project (excluding current view)
	var existingView models.ProjectView
	if err := facades.Orm().Query().Where("project_id = ? AND name = ? AND id != ?", projectID, request.Name, viewID).First(&existingView); err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View with this name already exists",
			Timestamp: time.Now(),
		})
	}

	// If this is set as default, unset other default views
	if request.IsDefault && !view.IsDefault {
		facades.Orm().Query().Model(&models.ProjectView{}).
			Where("project_id = ? AND is_default = ? AND id != ?", projectID, true, viewID).
			Update("is_default", false)
	}

	// Update fields
	view.Name = request.Name
	view.Description = request.Description
	view.Type = request.Type
	view.IsDefault = request.IsDefault
	view.IsPublic = request.IsPublic

	// Convert configuration to JSON strings
	if request.Layout != nil {
		if layoutBytes, err := json.Marshal(request.Layout); err == nil {
			view.Layout = string(layoutBytes)
		}
	}

	if request.Filters != nil {
		if filtersBytes, err := json.Marshal(request.Filters); err == nil {
			view.Filters = string(filtersBytes)
		}
	}

	if request.Sorting != nil {
		if sortingBytes, err := json.Marshal(request.Sorting); err == nil {
			view.Sorting = string(sortingBytes)
		}
	}

	if request.Grouping != nil {
		if groupingBytes, err := json.Marshal(request.Grouping); err == nil {
			view.Grouping = string(groupingBytes)
		}
	}

	if err := facades.Orm().Query().Save(&view); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "View updated successfully",
		Data:      view,
		Timestamp: time.Now(),
	})
}

// DeleteView deletes a view
func (pvc *ProjectViewsController) DeleteView(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	viewID := ctx.Request().Route("view_id")

	var view models.ProjectView
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", viewID, projectID).First(&view); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View not found",
			Timestamp: time.Now(),
		})
	}

	// Prevent deletion of default view
	if view.IsDefault {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Cannot delete the default view",
			Timestamp: time.Now(),
		})
	}

	// Delete the view
	_, err := facades.Orm().Query().Delete(&view)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "View deleted successfully",
		Timestamp: time.Now(),
	})
}

// DuplicateView duplicates an existing view
func (pvc *ProjectViewsController) DuplicateView(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	viewID := ctx.Request().Route("view_id")

	var originalView models.ProjectView
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", viewID, projectID).First(&originalView); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View not found",
			Timestamp: time.Now(),
		})
	}

	var request struct {
		Name string `json:"name" validate:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if view name already exists
	var existingView models.ProjectView
	if err := facades.Orm().Query().Where("project_id = ? AND name = ?", projectID, request.Name).First(&existingView); err == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "View with this name already exists",
			Timestamp: time.Now(),
		})
	}

	// Get next position
	var maxPosition int
	facades.Orm().Query().Model(&models.ProjectView{}).Where("project_id = ?", projectID).
		Select("COALESCE(MAX(position), 0)").Scan(&maxPosition)

	// Create duplicate
	duplicateView := models.ProjectView{
		Name:        request.Name,
		Description: originalView.Description,
		Type:        originalView.Type,
		Layout:      originalView.Layout,
		Filters:     originalView.Filters,
		Sorting:     originalView.Sorting,
		Grouping:    originalView.Grouping,
		IsDefault:   false, // Duplicates are never default
		IsPublic:    false, // Duplicates are private by default
		Position:    maxPosition + 1,
		ProjectID:   projectID,
	}

	if err := facades.Orm().Query().Create(&duplicateView); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to duplicate view: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "View duplicated successfully",
		Data:      duplicateView,
		Timestamp: time.Now(),
	})
}

// ReorderViews reorders views
func (pvc *ProjectViewsController) ReorderViews(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request struct {
		ViewIDs []string `json:"view_ids" validate:"required,min=1"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify all views exist and belong to the project
	var views []models.ProjectView
	viewIDs := make([]interface{}, len(request.ViewIDs))
	for i, id := range request.ViewIDs {
		viewIDs[i] = id
	}
	if err := facades.Orm().Query().Where("project_id = ?", projectID).WhereIn("id", viewIDs).Find(&views); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve views: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(views) != len(request.ViewIDs) {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Some views not found or invalid",
			Timestamp: time.Now(),
		})
	}

	// Update positions
	for i, viewID := range request.ViewIDs {
		facades.Orm().Query().Model(&models.ProjectView{}).
			Where("id = ? AND project_id = ?", viewID, projectID).
			Update("position", i+1)
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Views reordered successfully",
		Timestamp: time.Now(),
	})
}

// ProjectViewRequest represents the request structure for creating/updating views
type ProjectViewRequest struct {
	Name        string      `json:"name" validate:"required"`
	Description string      `json:"description,omitempty"`
	Type        string      `json:"type" validate:"required"` // table, board, timeline, roadmap, calendar
	Layout      interface{} `json:"layout,omitempty"`
	Filters     interface{} `json:"filters,omitempty"`
	Sorting     interface{} `json:"sorting,omitempty"`
	Grouping    interface{} `json:"grouping,omitempty"`
	IsDefault   bool        `json:"is_default,omitempty"`
	IsPublic    bool        `json:"is_public,omitempty"`
}
