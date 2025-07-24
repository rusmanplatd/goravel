package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/services"
)

type DepartmentController struct {
	organizationService *services.OrganizationService
}

func NewDepartmentController() *DepartmentController {
	return &DepartmentController{
		organizationService: services.NewOrganizationService(),
	}
}

// Index returns all departments for an organization
// @Summary Get all departments
// @Description Retrieve a list of all departments in an organization with filtering and cursor-based pagination
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or description"
// @Param is_active query bool false "Filter by active status"
// @Param parent_department_id query string false "Filter by parent department"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Department}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments [get]
func (dc *DepartmentController) Index(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")
	parentDeptID := ctx.Request().Input("parent_department_id", "")

	// Build filters
	filters := make(map[string]interface{})
	filters["organization_id"] = organizationID
	if search != "" {
		filters["search"] = search
	}
	if isActive != "" {
		filters["is_active"] = isActive == "true"
	}
	if parentDeptID != "" {
		filters["parent_department_id"] = parentDeptID
	}

	// Get departments
	departments, paginationInfo, err := dc.organizationService.ListDepartments(filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve departments",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   departments,
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

// Show returns a specific department
// @Summary Get a specific department by ID
// @Description Retrieve a specific department by its ID
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Success 200 {object} responses.APIResponse{data=models.Department}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id} [get]
func (dc *DepartmentController) Show(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	department, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	// Verify department belongs to organization
	if department.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      department,
		Timestamp: time.Now(),
	})
}

// Store creates a new department
// @Summary Create a new department
// @Description Create a new department in an organization
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param department body requests.DepartmentRequest true "Department data"
// @Success 201 {object} responses.APIResponse{data=models.Department}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments [post]
func (dc *DepartmentController) Store(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")

	var req requests.DepartmentRequest
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
		"name":                 req.Name,
		"code":                 req.Code,
		"description":          req.Description,
		"color":                req.Color,
		"icon":                 req.Icon,
		"is_active":            req.IsActive,
		"organization_id":      organizationID,
		"parent_department_id": req.ParentDepartmentID,
		"manager_id":           req.ManagerID,
	}

	department, err := dc.organizationService.CreateDepartment(data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create department: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Department created successfully",
		Data:      department,
		Timestamp: time.Now(),
	})
}

// Update updates a specific department
// @Summary Update a department
// @Description Update an existing department
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Param department body requests.DepartmentRequest true "Department data"
// @Success 200 {object} responses.APIResponse{data=models.Department}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id} [put]
func (dc *DepartmentController) Update(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.DepartmentRequest
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

	// Check if department exists and belongs to organization
	existingDept, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	if existingDept.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"name":                 req.Name,
		"code":                 req.Code,
		"description":          req.Description,
		"color":                req.Color,
		"icon":                 req.Icon,
		"is_active":            req.IsActive,
		"parent_department_id": req.ParentDepartmentID,
		"manager_id":           req.ManagerID,
	}

	department, err := dc.organizationService.UpdateDepartment(id, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update department: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Department updated successfully",
		Data:      department,
		Timestamp: time.Now(),
	})
}

// Delete deletes a specific department
// @Summary Delete a department
// @Description Delete an existing department
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id} [delete]
func (dc *DepartmentController) Delete(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	// Check if department exists and belongs to organization
	existingDept, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	if existingDept.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = dc.organizationService.DeleteDepartment(id)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete department: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Department deleted successfully",
		Timestamp: time.Now(),
	})
}

// Users returns users in a department
// @Summary Get department users
// @Description Retrieve users in a specific department
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or email"
// @Param role query string false "Filter by role"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.User}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id}/users [get]
func (dc *DepartmentController) Users(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	role := ctx.Request().Input("role", "")

	// Check if department exists and belongs to organization
	existingDept, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	if existingDept.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Build filters
	filters := make(map[string]interface{})
	filters["department_id"] = id
	if search != "" {
		filters["search"] = search
	}
	if role != "" {
		filters["role"] = role
	}

	users, paginationInfo, err := dc.organizationService.GetDepartmentUsers(id, filters, cursor, limit)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve department users",
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

// AddUser adds a user to a department
// @Summary Add user to department
// @Description Add a user to a specific department
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Param user body requests.DepartmentUserRequest true "User data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id}/users [post]
func (dc *DepartmentController) AddUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")

	var req requests.DepartmentUserRequest
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

	// Check if department exists and belongs to organization
	existingDept, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	if existingDept.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	// Prepare data
	data := map[string]interface{}{
		"role": req.Role,
	}

	err = dc.organizationService.AddUserToDepartment(id, req.UserID, data)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add user to department: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User added to department successfully",
		Timestamp: time.Now(),
	})
}

// RemoveUser removes a user from a department
// @Summary Remove user from department
// @Description Remove a user from a specific department
// @Tags departments
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param id path string true "Department ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/departments/{id}/users/{user_id} [delete]
func (dc *DepartmentController) RemoveUser(ctx http.Context) http.Response {
	organizationID := ctx.Request().Route("organization_id")
	id := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	// Check if department exists and belongs to organization
	existingDept, err := dc.organizationService.GetDepartment(id)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found",
			Timestamp: time.Now(),
		})
	}

	if existingDept.OrganizationID != organizationID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Department not found in this organization",
			Timestamp: time.Now(),
		})
	}

	err = dc.organizationService.RemoveUserFromDepartment(id, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove user from department: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User removed from department successfully",
		Timestamp: time.Now(),
	})
}
