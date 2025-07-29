package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
	"goravel/app/services"
)

type TeamController struct {
	organizationService *services.OrganizationService
}

func NewTeamController() *TeamController {
	return &TeamController{
		organizationService: services.NewOrganizationService(),
	}
}

// Index returns all teams for an organization
// @Summary Get all teams
// @Description Retrieve a list of all teams in an organization with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[description] query string false "Filter by description (partial match)"
// @Param filter[type] query string false "Filter by team type"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[department_id] query string false "Filter by department ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): organization,department,users,projects"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.Team}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams [get]
func (tc *TeamController) Index(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")

	var teams []models.Team

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.Team{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("description"),
			querybuilder.Exact("type"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("department_id"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("name", "type", "created_at", "updated_at").
		AllowedIncludes("organization", "department", "users", "projects").
		DefaultSort("-created_at")

	// Apply organization constraint to the base query
	query := qb.Build().Where("organization_id = ?", organizationID)

	// Create a new query builder with the constrained query
	constrainedQB := querybuilder.For(query).WithRequest(ctx)

	// Use AutoPaginate for unified pagination support
	result, err := constrainedQB.AutoPaginate(&teams)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve teams: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Teams retrieved successfully", result)
}

// Show returns a specific team
// @Summary Get a specific team by ID
// @Description Retrieve a specific team by its ID
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Success 200 {object} responses.APIResponse{data=models.Team}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id} [get]
func (tc *TeamController) Show(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	team, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	// Verify team belongs to organization
	if team.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      team,
		Timestamp: time.Now(),
	})
}

// Store creates a new team
// @Summary Create a new team
// @Description Create a new team in an organization
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param team body requests.TeamRequest true "Team data"
// @Success 201 {object} responses.APIResponse{data=models.Team}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams [post]
func (tc *TeamController) Store(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")

	var req requests.TeamRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"name":            req.Name,
		"code":            req.Code,
		"description":     req.Description,
		"type":            req.Type,
		"color":           req.Color,
		"icon":            req.Icon,
		"is_active":       true, // Default to true
		"organization_id": organizationID,
		"department_id":   req.DepartmentID,
		"team_lead_id":    req.TeamLeadID,
		"max_size":        req.MaxSize,
	}

	team, err := tc.organizationService.CreateTeam(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create team: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Team created successfully",
		Data:      team,
		Timestamp: time.Now(),
	})
}

// Update updates a specific team
// @Summary Update a team
// @Description Update an existing team
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Param team body requests.TeamRequest true "Team data"
// @Success 200 {object} responses.APIResponse{data=models.Team}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id} [put]
func (tc *TeamController) Update(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.TeamRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if team exists and belongs to organization
	existingTeam, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	if existingTeam.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"name":          req.Name,
		"code":          req.Code,
		"description":   req.Description,
		"type":          req.Type,
		"color":         req.Color,
		"icon":          req.Icon,
		"department_id": req.DepartmentID,
		"team_lead_id":  req.TeamLeadID,
		"max_size":      req.MaxSize,
	}

	team, err := tc.organizationService.UpdateTeam(id, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update team: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Team updated successfully",
		Data:      team,
		Timestamp: time.Now(),
	})
}

// Delete deletes a specific team
// @Summary Delete a team
// @Description Delete an existing team
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id} [delete]
func (tc *TeamController) Delete(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	// Check if team exists and belongs to organization
	existingTeam, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	if existingTeam.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = tc.organizationService.DeleteTeam(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete team: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Team deleted successfully",
		Timestamp: time.Now(),
	})
}

// Users returns users in a team
// @Summary Get team users
// @Description Retrieve users in a specific team
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or email"
// @Param role query string false "Filter by role"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.User}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id}/users [get]
func (tc *TeamController) Users(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	role := ctx.Request().Input("role", "")

	// Check if team exists and belongs to organization
	existingTeam, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	if existingTeam.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Build filters
	filters := make(map[string]interface{})
	filters["team_id"] = id
	if search != "" {
		filters["search"] = search
	}
	if role != "" {
		filters["role"] = role
	}

	users, paginationInfo, err := tc.organizationService.GetTeamUsers(id, filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve team users",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   users,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringPtr(paginationInfo, "next_cursor"),
			PrevCursor: getStringPtr(paginationInfo, "prev_cursor"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// AddUser adds a user to a team
// @Summary Add user to team
// @Description Add a user to a specific team
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Param user body requests.TeamUserRequest true "User data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id}/users [post]
func (tc *TeamController) AddUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.TeamUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate request
	if err := req.Authorize(ctx); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if team exists and belongs to organization
	existingTeam, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	if existingTeam.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"role":       req.Role,
		"allocation": req.Allocation,
	}

	err = tc.organizationService.AddUserToTeam(id, req.UserID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add user to team: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User added to team successfully",
		Timestamp: time.Now(),
	})
}

// RemoveUser removes a user from a team
// @Summary Remove user from team
// @Description Remove a user from a specific team
// @Tags teams
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Team ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/teams/{id}/users/{user_id} [delete]
func (tc *TeamController) RemoveUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	// Check if team exists and belongs to organization
	existingTeam, err := tc.organizationService.GetTeam(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found",
			Timestamp: time.Now(),
		})
	}

	if existingTeam.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Team not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = tc.organizationService.RemoveUserFromTeam(id, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove user from team: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User removed from team successfully",
		Timestamp: time.Now(),
	})
}
