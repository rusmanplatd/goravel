package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/services"
)

type ProjectController struct {
	organizationService *services.OrganizationService
}

func NewProjectController() *ProjectController {
	return &ProjectController{
		organizationService: services.NewOrganizationService(),
	}
}

// Index returns all projects for an organization
// @Summary Get all projects
// @Description Retrieve a list of all projects in an organization with filtering and cursor-based pagination
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or description"
// @Param status query string false "Filter by project status"
// @Param priority query string false "Filter by project priority"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Project}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects [get]
func (pc *ProjectController) Index(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	status := ctx.Request().Input("status", "")
	priority := ctx.Request().Input("priority", "")
	isActive := ctx.Request().Input("is_active", "")

	// Build filters
	filters := make(map[string]interface{})
	filters["organization_id"] = organizationID
	if search != "" {
		filters["search"] = search
	}
	if status != "" {
		filters["status"] = status
	}
	if priority != "" {
		filters["priority"] = priority
	}
	if isActive != "" {
		filters["is_active"] = isActive == "true"
	}

	// Get projects
	projects, paginationInfo, err := pc.organizationService.ListProjects(filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve projects",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   projects,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Show returns a specific project
// @Summary Get a specific project by ID
// @Description Retrieve a specific project by its ID
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Success 200 {object} responses.APIResponse{data=models.Project}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id} [get]
func (pc *ProjectController) Show(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	project, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	// Verify project belongs to organization
	if project.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      project,
		Timestamp: time.Now(),
	})
}

// Store creates a new project
// @Summary Create a new project
// @Description Create a new project in an organization
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project body requests.ProjectRequest true "Project data"
// @Success 201 {object} responses.APIResponse{data=models.Project}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects [post]
func (pc *ProjectController) Store(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")

	var req requests.ProjectRequest
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
		"name":               req.Name,
		"code":               req.Code,
		"description":        req.Description,
		"status":             req.Status,
		"priority":           req.Priority,
		"color":              req.Color,
		"icon":               req.Icon,
		"is_active":          true, // Default to true
		"organization_id":    organizationID,
		"project_manager_id": req.ProjectManagerID,
		"start_date":         req.StartDate,
		"end_date":           req.EndDate,
		"budget":             req.Budget,
		"settings":           req.Settings,
	}

	project, err := pc.organizationService.CreateProject(data)
	if err != nil {
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

// Update updates a specific project
// @Summary Update a project
// @Description Update an existing project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param project body requests.ProjectRequest true "Project data"
// @Success 200 {object} responses.APIResponse{data=models.Project}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id} [put]
func (pc *ProjectController) Update(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.ProjectRequest
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

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"name":               req.Name,
		"code":               req.Code,
		"description":        req.Description,
		"status":             req.Status,
		"priority":           req.Priority,
		"color":              req.Color,
		"icon":               req.Icon,
		"project_manager_id": req.ProjectManagerID,
		"start_date":         req.StartDate,
		"end_date":           req.EndDate,
		"budget":             req.Budget,
		"settings":           req.Settings,
	}

	project, err := pc.organizationService.UpdateProject(id, data)
	if err != nil {
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

// Delete deletes a specific project
// @Summary Delete a project
// @Description Delete an existing project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id} [delete]
func (pc *ProjectController) Delete(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = pc.organizationService.DeleteProject(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project deleted successfully",
		Timestamp: time.Now(),
	})
}

// Users returns users in a project
// @Summary Get project users
// @Description Retrieve users in a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or email"
// @Param role query string false "Filter by role"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.User}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/users [get]
func (pc *ProjectController) Users(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	role := ctx.Request().Input("role", "")

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Build filters
	filters := make(map[string]interface{})
	filters["project_id"] = id
	if search != "" {
		filters["search"] = search
	}
	if role != "" {
		filters["role"] = role
	}

	users, paginationInfo, err := pc.organizationService.GetProjectUsers(id, filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project users",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   users,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// AddUser adds a user to a project
// @Summary Add user to project
// @Description Add a user to a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param user body requests.ProjectUserRequest true "User data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/users [post]
func (pc *ProjectController) AddUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.ProjectUserRequest
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

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"role":       req.Role,
		"allocation": req.Allocation,
	}

	err = pc.organizationService.AddUserToProject(id, req.UserID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add user to project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User added to project successfully",
		Timestamp: time.Now(),
	})
}

// RemoveUser removes a user from a project
// @Summary Remove user from project
// @Description Remove a user from a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/users/{user_id} [delete]
func (pc *ProjectController) RemoveUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = pc.organizationService.RemoveUserFromProject(id, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove user from project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User removed from project successfully",
		Timestamp: time.Now(),
	})
}

// Teams returns teams in a project
// @Summary Get project teams
// @Description Retrieve teams in a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or description"
// @Param role query string false "Filter by role"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Team}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/teams [get]
func (pc *ProjectController) Teams(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	role := ctx.Request().Input("role", "")

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Build filters
	filters := make(map[string]interface{})
	filters["project_id"] = id
	if search != "" {
		filters["search"] = search
	}
	if role != "" {
		filters["role"] = role
	}

	teams, paginationInfo, err := pc.organizationService.GetProjectTeams(id, filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project teams",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   teams,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// AddTeam adds a team to a project
// @Summary Add team to project
// @Description Add a team to a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param team body requests.TeamProjectRequest true "Team data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/teams [post]
func (pc *ProjectController) AddTeam(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.TeamProjectRequest
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

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"role":       req.Role,
		"allocation": req.Allocation,
	}

	err = pc.organizationService.AddTeamToProject(id, req.TeamID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add team to project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Team added to project successfully",
		Timestamp: time.Now(),
	})
}

// RemoveTeam removes a team from a project
// @Summary Remove team from project
// @Description Remove a team from a specific project
// @Tags projects
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Project ID"
// @Param team_id path string true "Team ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{id}/teams/{team_id} [delete]
func (pc *ProjectController) RemoveTeam(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	teamID := ctx.Request().Route("team_id")

	// Check if project exists and belongs to organization
	existingProject, err := pc.organizationService.GetProject(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found",
			Timestamp: time.Now(),
		})
	}

	if existingProject.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = pc.organizationService.RemoveTeamFromProject(id, teamID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove team from project: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Team removed from project successfully",
		Timestamp: time.Now(),
	})
}
