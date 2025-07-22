package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type RoleController struct{}

func NewRoleController() *RoleController {
	return &RoleController{}
}

// Index returns all roles for a tenant
// @Summary Get all roles
// @Description Retrieve a list of all roles with cursor-based pagination
// @Tags roles
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Role}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles [get]
func (rc *RoleController) Index(ctx http.Context) http.Response {
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Tenant context required",
			Timestamp: time.Now(),
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")

	// Build query
	query := facades.Orm().Query().Where("tenant_id = ?", tenantID)

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ?", "%"+search+"%")
	}

	// Apply active status filter
	if isActive != "" {
		if isActive == "true" {
			query = query.Where("is_active = ?", true)
		} else if isActive == "false" {
			query = query.Where("is_active = ?", false)
		}
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var roles []models.Role
	err = query.Find(&roles)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve roles",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(roles) > limit
	if hasMore {
		roles = roles[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(roles, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   roles,
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

// Show returns a specific role
// @Summary Get a specific role by ID
// @Description Retrieve a single role by its ID
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} http.Json{data=models.Role}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id} [get]
func (rc *RoleController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var role models.Role
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&role)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Role not found",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": role,
	})
}

// Store creates a new role
// @Summary Create a new role
// @Description Create a new role for a tenant
// @Tags roles
// @Accept json
// @Produce json
// @Param role body models.Role true "Role data"
// @Success 201 {object} http.Json{data=models.Role}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles [post]
func (rc *RoleController) Store(ctx http.Context) http.Response {
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Tenant context required",
		})
	}

	var role models.Role
	if err := ctx.Request().Bind(&role); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	// Set tenant ID
	role.TenantID = &[]string{tenantID.(string)}[0]

	err := facades.Orm().Query().Create(&role)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to create role",
		})
	}

	return ctx.Response().Status(201).Json(http.Json{
		"data":    role,
		"message": "Role created successfully",
	})
}

// Update updates an existing role
// @Summary Update a role by ID
// @Description Update an existing role by its ID
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param role body models.Role true "Role data"
// @Success 200 {object} http.Json{data=models.Role}
// @Failure 404 {object} http.Json{error=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id} [put]
func (rc *RoleController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var role models.Role
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&role)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Role not found",
		})
	}

	if err := ctx.Request().Bind(&role); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	err = facades.Orm().Query().Save(&role)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to update role",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data":    role,
		"message": "Role updated successfully",
	})
}

// Delete removes a role
// @Summary Delete a role by ID
// @Description Delete a role by its ID
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id} [delete]
func (rc *RoleController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var role models.Role
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&role)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Role not found",
		})
	}

	_, err = facades.Orm().Query().Delete(&role)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to delete role",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "Role deleted successfully",
	})
}

// Permissions returns all permissions for a role
// @Summary Get all permissions for a role
// @Description Retrieve all permissions associated with a specific role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} http.Json{data=[]models.Permission}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id}/permissions [get]
func (rc *RoleController) Permissions(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var permissions []models.Permission
	err := facades.Orm().Query().
		Where("id IN (SELECT permission_id FROM role_permissions rp JOIN roles r ON rp.role_id = r.id WHERE r.id = ? AND r.tenant_id = ?)", roleID, tenantID).
		Find(&permissions)

	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to retrieve role permissions",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": permissions,
	})
}

// AssignPermission assigns a permission to a role
// @Summary Assign a permission to a role
// @Description Assign a permission to a specific role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param permission_id body string true "Permission ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id}/permissions [post]
func (rc *RoleController) AssignPermission(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	permissionID := ctx.Request().Input("permission_id")
	tenantID := ctx.Value("tenant_id")

	if permissionID == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Permission ID is required",
		})
	}

	// Check if role exists and belongs to tenant
	var role models.Role
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Role not found",
		})
	}

	// Check if permission exists
	var permission models.Permission
	err = facades.Orm().Query().Where("id = ?", permissionID).First(&permission)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Permission not found",
		})
	}

	// Create role-permission relationship
	err = facades.Orm().Query().Create(&map[string]interface{}{
		"role_id":       role.ID,
		"permission_id": permission.ID,
	})
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to assign permission to role",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "Permission assigned to role successfully",
	})
}

// RevokePermission removes a permission from a role
// @Summary Revoke a permission from a role
// @Description Revoke a permission from a specific role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param permission_id path string true "Permission ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /roles/{id}/permissions/{permission_id} [delete]
func (rc *RoleController) RevokePermission(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	permissionID := ctx.Request().Route("permission_id")

	_, err := facades.Orm().Query().
		Table("role_permissions").
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&map[string]interface{}{})

	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to revoke permission from role",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "Permission revoked from role successfully",
	})
}
