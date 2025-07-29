package v1

import (
	"strings"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectFiltersController struct {
	filterService *services.ProjectFilterService
}

func NewProjectFiltersController() *ProjectFiltersController {
	return &ProjectFiltersController{
		filterService: services.NewProjectFilterService(),
	}
}

// GetAvailableFilters returns available filters for a model type
// @Summary Get available filters
// @Description Get available filter fields, operators, and examples for a model
// @Tags project-filters
// @Accept json
// @Produce json
// @Param model query string true "Model type (project, task, roadmap)"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/filters [get]
func (pfc *ProjectFiltersController) GetAvailableFilters(ctx http.Context) http.Response {
	model := ctx.Request().Query("model", "project")

	// Validate model type
	validModels := []string{"project", "task", "roadmap"}
	isValid := false
	for _, validModel := range validModels {
		if model == validModel {
			isValid = true
			break
		}
	}

	if !isValid {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid model type. Must be one of: project, task, roadmap",
			Timestamp: time.Now(),
		})
	}

	filters := pfc.filterService.GetAvailableFilters(model)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Available filters retrieved successfully",
		Data:      filters,
		Timestamp: time.Now(),
	})
}

// ValidateFilterString validates a filter string
// @Summary Validate filter string
// @Description Validate GitHub Projects-style filter syntax
// @Tags project-filters
// @Accept json
// @Produce json
// @Param filter body object{filter_string=string} true "Filter string to validate"
// @Success 200 {object} responses.APIResponse
// @Failure 422 {object} responses.ErrorResponse
// @Router /projects/filters/validate [post]
func (pfc *ProjectFiltersController) ValidateFilterString(ctx http.Context) http.Response {
	var request struct {
		FilterString string `json:"filter_string" validate:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	err := pfc.filterService.ValidateFilterString(request.FilterString)
	if err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid filter syntax: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Filter string is valid",
		Data:      map[string]interface{}{"valid": true},
		Timestamp: time.Now(),
	})
}

// GetFilterSuggestions returns filter suggestions based on partial input
// @Summary Get filter suggestions
// @Description Get filter suggestions for autocomplete functionality
// @Tags project-filters
// @Accept json
// @Produce json
// @Param partial query string false "Partial filter input"
// @Param model query string false "Model type (project, task, roadmap)" default(project)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/filters/suggestions [get]
func (pfc *ProjectFiltersController) GetFilterSuggestions(ctx http.Context) http.Response {
	partial := ctx.Request().Query("partial", "")
	model := ctx.Request().Query("model", "project")

	// Validate model type
	validModels := []string{"project", "task", "roadmap"}
	isValid := false
	for _, validModel := range validModels {
		if model == validModel {
			isValid = true
			break
		}
	}

	if !isValid {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid model type. Must be one of: project, task, roadmap",
			Timestamp: time.Now(),
		})
	}

	suggestions := pfc.filterService.BuildFilterSuggestions(partial, model)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Filter suggestions retrieved successfully",
		Data:      suggestions,
		Timestamp: time.Now(),
	})
}

// SearchProjects searches projects with advanced filtering
// @Summary Search projects with filters
// @Description Search projects using GitHub Projects-style filter syntax
// @Tags project-filters
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param filter query string false "Filter string (GitHub Projects syntax)"
// @Param sort query string false "Sort field and direction" default("created_at:desc")
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(15)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/search [get]
func (pfc *ProjectFiltersController) SearchProjects(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	filterString := ctx.Request().Query("filter", "")
	sortString := ctx.Request().Query("sort", "created_at:desc")
	page := ctx.Request().QueryInt("page", 1)
	limit := ctx.Request().QueryInt("limit", 15)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Start with base query for project items (tasks, roadmap items, etc.)
	query := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID)

	// Apply filters
	if filterString != "" {
		var err error
		query, err = pfc.filterService.ApplyFilters(query, filterString, "task")
		if err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid filter: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Apply sorting
	if sortString != "" {
		query = pfc.applySorting(query, sortString)
	}

	// Apply pagination
	offset := (page - 1) * limit
	query = query.Offset(offset).Limit(limit)

	// Get results
	var tasks []models.Task
	if err := query.Find(&tasks); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to search tasks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get total count for pagination
	totalQuery := facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID)
	if filterString != "" {
		totalQuery, _ = pfc.filterService.ApplyFilters(totalQuery, filterString, "task")
	}
	total, _ := totalQuery.Count()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Search completed successfully",
		Data: map[string]interface{}{
			"items": tasks,
			"pagination": map[string]interface{}{
				"current_page": page,
				"per_page":     limit,
				"total":        total,
				"total_pages":  (total + int64(limit) - 1) / int64(limit),
			},
			"filter_applied": filterString,
			"sort_applied":   sortString,
		},
		Timestamp: time.Now(),
	})
}

// SearchRoadmapItems searches roadmap items with advanced filtering
// @Summary Search roadmap items with filters
// @Description Search roadmap items using GitHub Projects-style filter syntax
// @Tags project-filters
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param filter query string false "Filter string (GitHub Projects syntax)"
// @Param sort query string false "Sort field and direction" default("position:asc")
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(15)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/roadmap/search [get]
func (pfc *ProjectFiltersController) SearchRoadmapItems(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	filterString := ctx.Request().Query("filter", "")
	sortString := ctx.Request().Query("sort", "position:asc")
	page := ctx.Request().QueryInt("page", 1)
	limit := ctx.Request().QueryInt("limit", 15)

	// Verify project exists
	var project models.Project
	if err := facades.Orm().Query().Where("id = ?", projectID).First(&project); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Start with base query for roadmap items
	query := facades.Orm().Query().Model(&models.ProjectRoadmapItem{}).Where("project_id = ?", projectID)

	// Apply filters
	if filterString != "" {
		var err error
		query, err = pfc.filterService.ApplyFilters(query, filterString, "roadmap")
		if err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid filter: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Apply sorting
	if sortString != "" {
		query = pfc.applySorting(query, sortString)
	}

	// Apply pagination
	offset := (page - 1) * limit
	query = query.Offset(offset).Limit(limit)

	// Include relationships
	query = query.With("Tasks").With("Children")

	// Get results
	var roadmapItems []models.ProjectRoadmapItem
	if err := query.Find(&roadmapItems); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to search roadmap items: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get total count for pagination
	totalQuery := facades.Orm().Query().Model(&models.ProjectRoadmapItem{}).Where("project_id = ?", projectID)
	if filterString != "" {
		totalQuery, _ = pfc.filterService.ApplyFilters(totalQuery, filterString, "roadmap")
	}
	total, _ := totalQuery.Count()

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Roadmap search completed successfully",
		Data: map[string]interface{}{
			"items": roadmapItems,
			"pagination": map[string]interface{}{
				"current_page": page,
				"per_page":     limit,
				"total":        total,
				"total_pages":  (total + int64(limit) - 1) / int64(limit),
			},
			"filter_applied": filterString,
			"sort_applied":   sortString,
		},
		Timestamp: time.Now(),
	})
}

// applySorting applies sorting to a query based on sort string
func (pfc *ProjectFiltersController) applySorting(query orm.Query, sortString string) orm.Query {
	// Parse sort string (e.g., "created_at:desc", "name:asc")
	parts := strings.Split(sortString, ":")
	if len(parts) != 2 {
		query = query.Order("created_at DESC") // Default sort
		return query
	}

	field := strings.TrimSpace(parts[0])
	direction := strings.ToUpper(strings.TrimSpace(parts[1]))

	if direction != "ASC" && direction != "DESC" {
		direction = "DESC"
	}

	query = query.Order(field + " " + direction)
	return query
}
