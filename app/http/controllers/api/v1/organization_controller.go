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

type OrganizationController struct {
	organizationService *services.OrganizationService
}

func NewOrganizationController() *OrganizationController {
	return &OrganizationController{
		organizationService: services.NewOrganizationService(),
	}
}

// Index returns all organizations
// @Summary Get all organizations
// @Description Retrieve a list of all organizations with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags organizations
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[domain] query string false "Filter by domain (partial match)"
// @Param filter[description] query string false "Filter by description (partial match)"
// @Param filter[type] query string false "Filter by organization type"
// @Param filter[industry] query string false "Filter by industry"
// @Param filter[size] query string false "Filter by organization size"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[is_verified] query bool false "Filter by verification status"
// @Param filter[parent_organization_id] query string false "Filter by parent organization"
// @Param filter[tenant_id] query string false "Filter by tenant ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): tenant,parent,children,users,departments,teams,projects"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.Organization}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations [get]
func (oc *OrganizationController) Index(ctx http.Context) http.Response {
	var organizations []models.Organization

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.Organization{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("domain"),
			querybuilder.Partial("description"),
			querybuilder.Exact("type"),
			querybuilder.Exact("industry"),
			querybuilder.Exact("size"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_verified"),
			querybuilder.Exact("parent_organization_id"),
			querybuilder.Exact("tenant_id"),
		).
		AllowedSorts("name", "domain", "type", "industry", "size", "created_at", "updated_at").
		AllowedIncludes("tenant", "parent", "children", "users", "departments", "teams", "projects").
		DefaultSort("-created_at")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&organizations)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve organizations: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Organizations retrieved successfully", result)
}

// Show returns a specific organization
// @Summary Get organization by ID
// @Description Retrieve a specific organization by its ID
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Success 200 {object} responses.APIResponse{data=models.Organization}
// @Failure 404 {object} responses.ErrorResponse
// @Router /organizations/{id} [get]
func (oc *OrganizationController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	organization, err := oc.organizationService.GetOrganization(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      organization,
		Timestamp: time.Now(),
	})
}

// Store creates a new organization
// @Summary Create organization
// @Description Create a new organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param organization body requests.OrganizationRequest true "Organization data"
// @Success 201 {object} responses.APIResponse{data=models.Organization}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations [post]
func (oc *OrganizationController) Store(ctx http.Context) http.Response {
	var req requests.OrganizationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Convert request to map
	data := map[string]interface{}{
		"name":                   req.Name,
		"slug":                   req.Slug,
		"domain":                 req.Domain,
		"description":            req.Description,
		"type":                   req.Type,
		"industry":               req.Industry,
		"size":                   req.Size,
		"website":                req.Website,
		"logo":                   req.Logo,
		"banner":                 req.Banner,
		"contact_email":          req.ContactEmail,
		"contact_phone":          req.ContactPhone,
		"address":                req.Address,
		"country_id":             req.CountryID,
		"province_id":            req.ProvinceID,
		"city_id":                req.CityID,
		"district_id":            req.DistrictID,
		"postal_code":            req.PostalCode,
		"tenant_id":              req.TenantID,
		"parent_organization_id": req.ParentOrganizationID,
		"settings":               req.Settings,
	}

	// Set optional fields
	if req.FoundedAt != nil {
		data["founded_at"] = req.FoundedAt
	}

	organization, err := oc.organizationService.CreateOrganization(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Organization created successfully",
		Data:      organization,
		Timestamp: time.Now(),
	})
}

// Update updates an existing organization
// @Summary Update organization
// @Description Update an existing organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param organization body requests.OrganizationRequest true "Updated organization data"
// @Success 200 {object} responses.APIResponse{data=models.Organization}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id} [put]
func (oc *OrganizationController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var req requests.OrganizationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Convert request to map
	data := map[string]interface{}{
		"name":                   req.Name,
		"slug":                   req.Slug,
		"domain":                 req.Domain,
		"description":            req.Description,
		"type":                   req.Type,
		"industry":               req.Industry,
		"size":                   req.Size,
		"website":                req.Website,
		"logo":                   req.Logo,
		"banner":                 req.Banner,
		"contact_email":          req.ContactEmail,
		"contact_phone":          req.ContactPhone,
		"address":                req.Address,
		"country_id":             req.CountryID,
		"province_id":            req.ProvinceID,
		"city_id":                req.CityID,
		"district_id":            req.DistrictID,
		"postal_code":            req.PostalCode,
		"tenant_id":              req.TenantID,
		"parent_organization_id": req.ParentOrganizationID,
		"settings":               req.Settings,
	}

	// Set optional fields
	if req.FoundedAt != nil {
		data["founded_at"] = req.FoundedAt
	}

	organization, err := oc.organizationService.UpdateOrganization(id, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Organization updated successfully",
		Data:      organization,
		Timestamp: time.Now(),
	})
}

// Delete deletes an organization
// @Summary Delete organization
// @Description Delete an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id} [delete]
func (oc *OrganizationController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	err := oc.organizationService.DeleteOrganization(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Organization deleted successfully",
		Timestamp: time.Now(),
	})
}

// Users returns users in an organization
// @Summary Get organization users
// @Description Retrieve users in an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param role query string false "Filter by user role"
// @Param status query string false "Filter by user status"
// @Param is_active query bool false "Filter by active status"
// @Param search query string false "Search by name or email"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.User}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/users [get]
func (oc *OrganizationController) Users(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	role := ctx.Request().Input("role", "")
	status := ctx.Request().Input("status", "")
	isActive := ctx.Request().Input("is_active", "")
	search := ctx.Request().Input("search", "")

	// Build filters
	filters := make(map[string]interface{})
	if role != "" {
		filters["role"] = role
	}
	if status != "" {
		filters["status"] = status
	}
	if isActive != "" {
		filters["is_active"] = isActive == "true"
	}
	if search != "" {
		filters["search"] = search
	}

	users, paginationInfo, err := oc.organizationService.GetOrganizationUsers(id, filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve organization users",
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

// AddUser adds a user to an organization
// @Summary Add user to organization
// @Description Add a user to an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param user body requests.OrganizationUserRequest true "User data"
// @Success 201 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/users [post]
func (oc *OrganizationController) AddUser(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var req requests.OrganizationUserRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Convert request to map
	data := map[string]interface{}{
		"role":          req.Role,
		"status":        req.Status,
		"title":         req.Title,
		"employee_id":   req.EmployeeID,
		"department_id": req.DepartmentID,
		"team_id":       req.TeamID,
		"manager_id":    req.ManagerID,
		"permissions":   req.Permissions,
	}

	// Set optional fields
	if req.HireDate != nil {
		data["hire_date"] = req.HireDate
	}
	if req.ExpiresAt != nil {
		data["expires_at"] = req.ExpiresAt
	}

	err := oc.organizationService.AddUserToOrganization(id, req.UserID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add user to organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "User added to organization successfully",
		Timestamp: time.Now(),
	})
}

// RemoveUser removes a user from an organization
// @Summary Remove user from organization
// @Description Remove a user from an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/users/{user_id} [delete]
func (oc *OrganizationController) RemoveUser(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	err := oc.organizationService.RemoveUserFromOrganization(id, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove user from organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User removed from organization successfully",
		Timestamp: time.Now(),
	})
}

// Hierarchy returns the organization hierarchy
// @Summary Get organization hierarchy
// @Description Retrieve the organization hierarchy (parents and subsidiaries)
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/hierarchy [get]
func (oc *OrganizationController) Hierarchy(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	hierarchy, err := oc.organizationService.GetOrganizationHierarchy(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve organization hierarchy",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      hierarchy,
		Timestamp: time.Now(),
	})
}

// Stats returns organization statistics
// @Summary Get organization statistics
// @Description Retrieve statistics for an organization
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/stats [get]
func (oc *OrganizationController) Stats(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	stats, err := oc.organizationService.GetOrganizationStats(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve organization statistics",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// Verify marks an organization as verified
// @Summary Verify organization
// @Description Mark an organization as verified
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{id}/verify [post]
func (oc *OrganizationController) Verify(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	err := oc.organizationService.VerifyOrganization(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to verify organization: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Organization verified successfully",
		Timestamp: time.Now(),
	})
}
