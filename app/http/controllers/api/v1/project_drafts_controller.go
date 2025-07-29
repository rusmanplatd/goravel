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

type ProjectDraftsController struct{}

func NewProjectDraftsController() *ProjectDraftsController {
	return &ProjectDraftsController{}
}

// ListDrafts lists all draft issues in a project
// @Summary List project draft issues
// @Description Get all draft issues in a project (GitHub Projects v2 style)
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Success 200 {array} models.Task
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts [get]
func (pdc *ProjectDraftsController) ListDrafts(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var drafts []models.Task

	query := querybuilder.For(&models.Task{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("priority"),
			querybuilder.Partial("title"),
			querybuilder.Exact("assignee_id"),
		).
		AllowedSorts("title", "priority", "created_at", "updated_at").
		DefaultSort("-created_at").
		Build().
		Where("project_id = ? AND type = ?", projectID, "draft_issue")

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&drafts)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve draft issues: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Draft issues retrieved successfully", result)
}

// CreateDraft creates a new draft issue
// @Summary Create project draft issue
// @Description Create a new draft issue in a project (GitHub Projects v2 style)
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.DraftIssueRequest true "Draft issue data"
// @Success 201 {object} models.Task
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts [post]
func (pdc *ProjectDraftsController) CreateDraft(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request requests.DraftIssueRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create a new draft issue
	draft := models.Task{
		ProjectID:   projectID,
		Title:       request.Title,
		Description: request.Description,
		Type:        "draft_issue",
		Status:      "draft",
		Priority:    "medium",
		IsActive:    true,
		IsArchived:  false,
	}
	draft.CreatedBy = &userID
	draft.UpdatedBy = &userID

	// Apply optional fields
	if request.Priority != "" {
		draft.Priority = request.Priority
	}
	if request.AssigneeID != nil {
		draft.AssigneeID = request.AssigneeID
	}

	if err := facades.Orm().Query().Create(&draft); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create draft issue: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Draft issue created successfully",
		Data:      draft,
		Timestamp: time.Now(),
	})
}

// GetDraft retrieves a specific draft issue
// @Summary Get project draft issue
// @Description Get a specific draft issue in a project
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param draft_id path string true "Draft ID"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/{draft_id} [get]
func (pdc *ProjectDraftsController) GetDraft(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	draftID := ctx.Request().Route("draft_id")

	var draft models.Task
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ? AND type = ?", draftID, projectID, "draft_issue").
		First(&draft); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Draft issue not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Draft issue retrieved successfully",
		Data:      draft,
		Timestamp: time.Now(),
	})
}

// UpdateDraft updates a specific draft issue
// @Summary Update project draft issue
// @Description Update a specific draft issue in a project
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param draft_id path string true "Draft ID"
// @Param request body requests.DraftIssueRequest true "Draft issue update data"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/{draft_id} [patch]
func (pdc *ProjectDraftsController) UpdateDraft(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	draftID := ctx.Request().Route("draft_id")
	userID := ctx.Value("user_id").(string)

	var draft models.Task
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ? AND type = ?", draftID, projectID, "draft_issue").
		First(&draft); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Draft issue not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.DraftIssueRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Title != "" {
		draft.Title = request.Title
	}
	if request.Description != "" {
		draft.Description = request.Description
	}
	if request.Priority != "" {
		draft.Priority = request.Priority
	}
	if request.AssigneeID != nil {
		draft.AssigneeID = request.AssigneeID
	}

	draft.UpdatedBy = &userID

	if err := facades.Orm().Query().Save(&draft); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update draft issue: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Draft issue updated successfully",
		Data:      draft,
		Timestamp: time.Now(),
	})
}

// ConvertToIssue converts a draft issue to a regular issue
// @Summary Convert draft to issue
// @Description Convert a draft issue to a regular issue (GitHub Projects v2 style)
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param draft_id path string true "Draft ID"
// @Success 200 {object} models.Task
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/{draft_id}/convert [post]
func (pdc *ProjectDraftsController) ConvertToIssue(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	draftID := ctx.Request().Route("draft_id")
	userID := ctx.Value("user_id").(string)

	var draft models.Task
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ? AND type = ?", draftID, projectID, "draft_issue").
		First(&draft); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Draft issue not found",
			Timestamp: time.Now(),
		})
	}

	// Convert draft to regular issue
	draft.Type = "issue"
	draft.Status = "todo" // Default status for new issues
	draft.UpdatedBy = &userID

	if err := facades.Orm().Query().Save(&draft); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to convert draft to issue: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Draft issue converted to issue successfully",
		Data:      draft,
		Timestamp: time.Now(),
	})
}

// DeleteDraft deletes a draft issue
// @Summary Delete project draft issue
// @Description Delete a draft issue from a project
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param draft_id path string true "Draft ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/{draft_id} [delete]
func (pdc *ProjectDraftsController) DeleteDraft(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	draftID := ctx.Request().Route("draft_id")

	var draft models.Task
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ? AND type = ?", draftID, projectID, "draft_issue").
		First(&draft); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Draft issue not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&draft); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete draft issue: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// BulkConvertDrafts converts multiple draft issues to regular issues
// @Summary Bulk convert drafts to issues
// @Description Convert multiple draft issues to regular issues
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body object true "Draft IDs to convert"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/bulk-convert [post]
func (pdc *ProjectDraftsController) BulkConvertDrafts(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	var request struct {
		DraftIDs []string `json:"draft_ids" validate:"required,min=1"`
	}
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.DraftIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No draft IDs specified for bulk conversion",
			Timestamp: time.Now(),
		})
	}

	// Update multiple drafts to issues
	updates := map[string]interface{}{
		"type":       "issue",
		"status":     "todo",
		"updated_by": &userID,
	}

	if _, err := facades.Orm().Query().Model(&models.Task{}).
		Where("project_id = ? AND id IN ? AND type = ?", projectID, request.DraftIDs, "draft_issue").
		Update(updates); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to bulk convert drafts: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Draft issues converted successfully",
		Data: map[string]interface{}{
			"converted_count": len(request.DraftIDs),
			"draft_ids":       request.DraftIDs,
		},
		Timestamp: time.Now(),
	})
}

// BulkDeleteDrafts deletes multiple draft issues
// @Summary Bulk delete draft issues
// @Description Delete multiple draft issues from a project
// @Tags project-drafts
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body object true "Draft IDs to delete"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/drafts/bulk-delete [delete]
func (pdc *ProjectDraftsController) BulkDeleteDrafts(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")

	var request struct {
		DraftIDs []string `json:"draft_ids" validate:"required,min=1"`
	}
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	if len(request.DraftIDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No draft IDs specified for bulk deletion",
			Timestamp: time.Now(),
		})
	}

	// Delete multiple drafts
	if _, err := facades.Orm().Query().
		Where("project_id = ? AND id IN ? AND type = ?", projectID, request.DraftIDs, "draft_issue").
		Delete(&models.Task{}); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to bulk delete drafts: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Draft issues deleted successfully",
		Data: map[string]interface{}{
			"deleted_count": len(request.DraftIDs),
			"draft_ids":     request.DraftIDs,
		},
		Timestamp: time.Now(),
	})
}
