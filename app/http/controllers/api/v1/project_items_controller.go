package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectItemsController struct{}

func NewProjectItemsController() *ProjectItemsController {
	return &ProjectItemsController{}
}

// ListItems lists all items in a project
// @Summary List project items
// @Description Get all items (issues, pull requests, draft issues) in a project
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Success 200 {array} models.Task
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items [get]
func (pic *ProjectItemsController) ListItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var items []models.Task

	query := querybuilder.For(&models.Task{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("status"),
			querybuilder.Exact("priority"),
			querybuilder.Exact("type"),
			querybuilder.Partial("title"),
		).
		AllowedSorts("title", "status", "priority", "created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("project_id = ?", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&items)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project items retrieved successfully", result)
}

// AddItem adds a new item to a project
// @Summary Add project item
// @Description Add a new item (issue, pull request, or draft issue) to a project
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectItemRequest true "Item data"
// @Success 201 {object} models.Task
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items [post]
func (pic *ProjectItemsController) AddItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.ProjectItemRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create a new task item
	task := models.Task{
		ProjectID: projectID,
		Type:      request.ContentType,
		Status:    "todo",
		Priority:  "medium",
		IsActive:  true,
	}

	if request.Title != "" {
		task.Title = request.Title
	}
	if request.Body != "" {
		task.Description = request.Body
	}

	if err := facades.Orm().Query().Create(&task); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add item to project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Item added to project successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// GetItem retrieves a specific project item
// @Summary Get project item
// @Description Get a specific item in a project
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Item ID"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/{item_id} [get]
func (pic *ProjectItemsController) GetItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var task models.Task
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&task); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project item not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project item retrieved successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// UpdateItem updates a specific project item
// @Summary Update project item
// @Description Update a specific item in a project
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Item ID"
// @Param request body requests.ProjectItemUpdateRequest true "Item update data"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/{item_id} [patch]
func (pic *ProjectItemsController) UpdateItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var task models.Task
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&task); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project item not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectItemUpdateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields that are provided
	if request.Status != "" {
		task.Status = request.Status
	}
	if request.Priority != "" {
		task.Priority = request.Priority
	}

	if err := facades.Orm().Query().Save(&task); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project item updated successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// RemoveItem removes an item from a project
// @Summary Remove project item
// @Description Remove an item from a project
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Item ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/{item_id} [delete]
func (pic *ProjectItemsController) RemoveItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var task models.Task
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&task); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project item not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&task); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove project item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// ArchiveItem archives a project item
// @Summary Archive project item
// @Description Archive a project item
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Item ID"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/{item_id}/archive [post]
func (pic *ProjectItemsController) ArchiveItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var task models.Task
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&task); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project item not found",
			Timestamp: time.Now(),
		})
	}

	task.IsArchived = true
	if err := facades.Orm().Query().Save(&task); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to archive project item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project item archived successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// RestoreItem restores an archived project item
// @Summary Restore project item
// @Description Restore an archived project item
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Item ID"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/{item_id}/restore [post]
func (pic *ProjectItemsController) RestoreItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var task models.Task
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&task); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project item not found",
			Timestamp: time.Now(),
		})
	}

	task.IsArchived = false
	if err := facades.Orm().Query().Save(&task); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to restore project item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project item restored successfully",
		Data:      task,
		Timestamp: time.Now(),
	})
}

// BulkUpdateItems updates multiple project items at once
// @Summary Bulk update project items
// @Description Update multiple project items with the same changes
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.BulkUpdateItemsRequest true "Bulk update data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/bulk-update [patch]
func (pic *ProjectItemsController) BulkUpdateItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.BulkUpdateItemsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.ItemIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No items specified for bulk update",
			Timestamp: time.Now(),
		})
	}

	// Build update map
	updates := make(map[string]interface{})
	if request.Status != "" {
		updates["status"] = request.Status
	}
	if request.Priority != "" {
		updates["priority"] = request.Priority
	}
	if request.AssigneeID != nil {
		updates["assignee_id"] = request.AssigneeID
	}

	if len(updates) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No updates specified",
			Timestamp: time.Now(),
		})
	}

	// Perform bulk update
	var updatedCount int64 = 0
	for key, value := range updates {
		if _, err := facades.Orm().Query().Model(&models.Task{}).
			Where("project_id = ? AND id IN ?", projectID, request.ItemIDs).
			Update(key, value); err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to bulk update items: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Count affected items
	updatedCount = int64(len(request.ItemIDs))

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Items updated successfully",
		Data: map[string]interface{}{
			"updated_count": updatedCount,
			"item_ids":      request.ItemIDs,
			"updates":       updates,
		},
		Timestamp: time.Now(),
	})
}

// BulkArchiveItems archives multiple project items at once
// @Summary Bulk archive project items
// @Description Archive multiple project items
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.BulkItemsRequest true "Bulk archive data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/bulk-archive [post]
func (pic *ProjectItemsController) BulkArchiveItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.BulkItemsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.ItemIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No items specified for bulk archive",
			Timestamp: time.Now(),
		})
	}

	// Perform bulk archive
	if _, err := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND id IN ?", projectID, request.ItemIDs).
		Update("is_archived", true); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to bulk archive items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Items archived successfully",
		Data: map[string]interface{}{
			"archived_count": len(request.ItemIDs),
			"item_ids":       request.ItemIDs,
		},
		Timestamp: time.Now(),
	})
}

// BulkDeleteItems deletes multiple project items at once
// @Summary Bulk delete project items
// @Description Delete multiple project items permanently
// @Tags project-items
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.BulkItemsRequest true "Bulk delete data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/items/bulk-delete [delete]
func (pic *ProjectItemsController) BulkDeleteItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request requests.BulkItemsRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.ItemIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No items specified for bulk delete",
			Timestamp: time.Now(),
		})
	}

	// Perform bulk delete
	if _, err := facades.Orm().Query().Where("project_id = ? AND id IN ?", projectID, request.ItemIDs).Delete(&models.Task{}); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to bulk delete items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Items deleted successfully",
		Data: map[string]interface{}{
			"deleted_count": len(request.ItemIDs),
			"item_ids":      request.ItemIDs,
		},
		Timestamp: time.Now(),
	})
}
