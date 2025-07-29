package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectRoadmapController struct{}

func NewProjectRoadmapController() *ProjectRoadmapController {
	return &ProjectRoadmapController{}
}

// ListRoadmapItems lists all roadmap items for a project
// @Summary List project roadmap items
// @Description Get all roadmap items for a project with hierarchical structure (GitHub Projects v2 style)
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param type query string false "Filter by type (milestone, epic, feature, release)"
// @Param status query string false "Filter by status (planned, in_progress, completed, cancelled)"
// @Param parent_id query string false "Filter by parent item ID"
// @Param include_children query bool false "Include child items in response"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectRoadmapItem}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap [get]
func (prc *ProjectRoadmapController) ListRoadmapItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemType := ctx.Request().Query("type", "")
	status := ctx.Request().Query("status", "")
	parentID := ctx.Request().Query("parent_id", "")
	includeChildren := ctx.Request().QueryBool("include_children", false)

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

	// Apply filters
	if itemType != "" {
		query = query.Where("type = ?", itemType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if parentID != "" {
		query = query.Where("parent_id = ?", parentID)
	} else if !includeChildren {
		// Only show top-level items if not filtering by parent and not including children
		query = query.Where("parent_id IS NULL")
	}

	// Include relationships if requested
	if includeChildren {
		query = query.With("Children").With("Tasks")
	} else {
		query = query.With("Tasks")
	}

	var roadmapItems []models.ProjectRoadmapItem
	if err := query.Order("position ASC, target_date ASC, created_at ASC").Find(&roadmapItems); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve roadmap items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap items retrieved successfully",
		Data:      roadmapItems,
		Timestamp: time.Now(),
	})
}

// CreateRoadmapItem creates a new roadmap item for a project
// @Summary Create project roadmap item
// @Description Create a new roadmap item for a project (GitHub Projects v2 style)
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param roadmap_item body requests.ProjectRoadmapItemRequest true "Roadmap item data"
// @Success 201 {object} responses.APIResponse{data=models.ProjectRoadmapItem}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap [post]
func (prc *ProjectRoadmapController) CreateRoadmapItem(ctx http.Context) http.Response {
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

	var request requests.ProjectRoadmapItemRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify parent item exists if specified
	if request.ParentID != nil {
		var parentItem models.ProjectRoadmapItem
		if err := facades.Orm().Query().Where("id = ? AND project_id = ?", *request.ParentID, projectID).First(&parentItem); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Parent roadmap item not found",
				Timestamp: time.Now(),
			})
		}
	}

	// Get next position if not provided
	var maxPosition int
	query := facades.Orm().Query().Model(&models.ProjectRoadmapItem{}).Where("project_id = ?", projectID)
	if request.ParentID != nil {
		query = query.Where("parent_id = ?", *request.ParentID)
	} else {
		query = query.Where("parent_id IS NULL")
	}
	query.Select("COALESCE(MAX(position), 0)").Scan(&maxPosition)

	roadmapItem := models.ProjectRoadmapItem{
		Title:       request.Title,
		Description: request.Description,
		Type:        request.Type,
		Status:      "planned",
		StartDate:   request.StartDate,
		TargetDate:  request.TargetDate,
		Progress:    0.0,
		Color:       request.Color,
		Position:    maxPosition + 1,
		ProjectID:   projectID,
		ParentID:    request.ParentID,
	}

	// Set status if provided
	if request.Status != "" {
		roadmapItem.Status = request.Status
	}

	if err := facades.Orm().Query().Create(&roadmapItem); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create roadmap item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Link tasks if provided
	if len(request.TaskIDs) > 0 {
		for _, taskID := range request.TaskIDs {
			// Verify task exists and belongs to project
			var task models.Task
			if err := facades.Orm().Query().Where("id = ? AND project_id = ?", taskID, projectID).First(&task); err != nil {
				continue // Skip invalid tasks
			}

			// Create relationship
			err := facades.Orm().Query().Table("roadmap_item_tasks").Create(map[string]interface{}{
				"roadmap_item_id": roadmapItem.ID,
				"task_id":         taskID,
				"added_at":        time.Now(),
				"added_by":        ctx.Value("user_id").(string),
			})
			if err != nil {
				// Log error but continue
				continue
			}
		}
	}

	// Reload with relationships
	facades.Orm().Query().Where("id = ?", roadmapItem.ID).With("Tasks").First(&roadmapItem)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap item created successfully",
		Data:      roadmapItem,
		Timestamp: time.Now(),
	})
}

// GetRoadmapItem retrieves a specific roadmap item
// @Summary Get project roadmap item
// @Description Get details of a specific project roadmap item
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Roadmap Item ID"
// @Success 200 {object} responses.APIResponse{data=models.ProjectRoadmapItem}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/{item_id} [get]
func (prc *ProjectRoadmapController) GetRoadmapItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var roadmapItem models.ProjectRoadmapItem
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).
		With("Children").With("Tasks").With("Parent").First(&roadmapItem); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Roadmap item not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap item retrieved successfully",
		Data:      roadmapItem,
		Timestamp: time.Now(),
	})
}

// UpdateRoadmapItem updates a roadmap item
// @Summary Update project roadmap item
// @Description Update an existing project roadmap item
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Roadmap Item ID"
// @Param roadmap_item body requests.ProjectRoadmapItemRequest true "Roadmap item data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectRoadmapItem}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/{item_id} [patch]
func (prc *ProjectRoadmapController) UpdateRoadmapItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var roadmapItem models.ProjectRoadmapItem
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&roadmapItem); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Roadmap item not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectRoadmapItemRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Verify parent item exists if specified and different from current
	if request.ParentID != nil && (roadmapItem.ParentID == nil || *request.ParentID != *roadmapItem.ParentID) {
		// Prevent circular references
		if *request.ParentID == itemID {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Cannot set item as its own parent",
				Timestamp: time.Now(),
			})
		}

		var parentItem models.ProjectRoadmapItem
		if err := facades.Orm().Query().Where("id = ? AND project_id = ?", *request.ParentID, projectID).First(&parentItem); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Parent roadmap item not found",
				Timestamp: time.Now(),
			})
		}
	}

	// Update fields
	roadmapItem.Title = request.Title
	roadmapItem.Description = request.Description
	roadmapItem.Type = request.Type
	roadmapItem.StartDate = request.StartDate
	roadmapItem.TargetDate = request.TargetDate
	roadmapItem.Color = request.Color
	roadmapItem.ParentID = request.ParentID

	if request.Status != "" {
		roadmapItem.Status = request.Status
		// Set completion date if completed
		if request.Status == "completed" && roadmapItem.CompletedAt == nil {
			now := time.Now()
			roadmapItem.CompletedAt = &now
			roadmapItem.Progress = 100.0
		} else if request.Status != "completed" {
			roadmapItem.CompletedAt = nil
		}
	}

	if err := facades.Orm().Query().Save(&roadmapItem); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update roadmap item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update task relationships if provided
	if len(request.TaskIDs) > 0 {
		// Remove existing relationships
		_, err := facades.Orm().Query().Table("roadmap_item_tasks").Where("roadmap_item_id = ?", itemID).Delete()
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to update task relationships: " + err.Error(),
				Timestamp: time.Now(),
			})
		}

		// Add new relationships
		for _, taskID := range request.TaskIDs {
			// Verify task exists and belongs to project
			var task models.Task
			if err := facades.Orm().Query().Where("id = ? AND project_id = ?", taskID, projectID).First(&task); err != nil {
				continue // Skip invalid tasks
			}

			// Create relationship
			err := facades.Orm().Query().Table("roadmap_item_tasks").Create(map[string]interface{}{
				"roadmap_item_id": itemID,
				"task_id":         taskID,
				"added_at":        time.Now(),
				"added_by":        ctx.Value("user_id").(string),
			})
			if err != nil {
				continue
			}
		}
	}

	// Reload with relationships
	facades.Orm().Query().Where("id = ?", itemID).With("Tasks").With("Children").First(&roadmapItem)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap item updated successfully",
		Data:      roadmapItem,
		Timestamp: time.Now(),
	})
}

// DeleteRoadmapItem deletes a roadmap item
// @Summary Delete project roadmap item
// @Description Delete a project roadmap item (will also delete child items)
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Roadmap Item ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/{item_id} [delete]
func (prc *ProjectRoadmapController) DeleteRoadmapItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var roadmapItem models.ProjectRoadmapItem
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&roadmapItem); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Roadmap item not found",
			Timestamp: time.Now(),
		})
	}

	// Delete task relationships first
	_, err := facades.Orm().Query().Table("roadmap_item_tasks").Where("roadmap_item_id = ?", itemID).Delete()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove task relationships: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update child items to have no parent (or delete them based on requirements)
	_, err = facades.Orm().Query().Model(&models.ProjectRoadmapItem{}).
		Where("parent_id = ?", itemID).
		Update("parent_id", nil)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update child items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Delete the roadmap item
	_, err = facades.Orm().Query().Delete(&roadmapItem)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete roadmap item: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap item deleted successfully",
		Timestamp: time.Now(),
	})
}

// UpdateRoadmapItemProgress updates the progress of a roadmap item
// @Summary Update roadmap item progress
// @Description Update the progress percentage of a roadmap item
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Roadmap Item ID"
// @Param progress body object{progress=number} true "Progress data"
// @Success 200 {object} responses.APIResponse{data=models.ProjectRoadmapItem}
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/{item_id}/progress [patch]
func (prc *ProjectRoadmapController) UpdateRoadmapItemProgress(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")

	var roadmapItem models.ProjectRoadmapItem
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&roadmapItem); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Roadmap item not found",
			Timestamp: time.Now(),
		})
	}

	var request struct {
		Progress float64 `json:"progress" validate:"required,min=0,max=100"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	roadmapItem.Progress = request.Progress

	// Auto-update status based on progress
	if request.Progress == 0 {
		roadmapItem.Status = "planned"
		roadmapItem.CompletedAt = nil
	} else if request.Progress == 100 {
		roadmapItem.Status = "completed"
		if roadmapItem.CompletedAt == nil {
			now := time.Now()
			roadmapItem.CompletedAt = &now
		}
	} else {
		roadmapItem.Status = "in_progress"
		roadmapItem.CompletedAt = nil
	}

	if err := facades.Orm().Query().Save(&roadmapItem); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update roadmap item progress: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Roadmap item progress updated successfully",
		Data:      roadmapItem,
		Timestamp: time.Now(),
	})
}

// LinkTasksToRoadmapItem links tasks to a roadmap item
// @Summary Link tasks to roadmap item
// @Description Link multiple tasks to a roadmap item
// @Tags project-roadmap
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param item_id path string true "Roadmap Item ID"
// @Param tasks body object{task_ids=[]string} true "Task IDs to link"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/{item_id}/tasks [post]
func (prc *ProjectRoadmapController) LinkTasksToRoadmapItem(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	itemID := ctx.Request().Route("item_id")
	userID := ctx.Value("user_id").(string)

	var roadmapItem models.ProjectRoadmapItem
	if err := facades.Orm().Query().Where("id = ? AND project_id = ?", itemID, projectID).First(&roadmapItem); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Roadmap item not found",
			Timestamp: time.Now(),
		})
	}

	var request struct {
		TaskIDs []string `json:"task_ids" validate:"required,min=1"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	linkedCount := 0
	for _, taskID := range request.TaskIDs {
		// Verify task exists and belongs to project
		var task models.Task
		if err := facades.Orm().Query().Where("id = ? AND project_id = ?", taskID, projectID).First(&task); err != nil {
			continue // Skip invalid tasks
		}

		// Check if relationship already exists
		existing, _ := facades.Orm().Query().Table("roadmap_item_tasks").
			Where("roadmap_item_id = ? AND task_id = ?", itemID, taskID).
			Count()
		if existing > 0 {
			continue // Skip existing relationships
		}

		// Create relationship
		err := facades.Orm().Query().Table("roadmap_item_tasks").Create(map[string]interface{}{
			"roadmap_item_id": itemID,
			"task_id":         taskID,
			"added_at":        time.Now(),
			"added_by":        userID,
		})
		if err == nil {
			linkedCount++
		}
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Tasks linked to roadmap item successfully",
		Data: map[string]interface{}{
			"linked_count":    linkedCount,
			"total_requested": len(request.TaskIDs),
		},
		Timestamp: time.Now(),
	})
}
