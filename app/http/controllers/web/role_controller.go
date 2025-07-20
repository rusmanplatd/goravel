package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/models"
)

type RoleController struct{}

func NewRoleController() *RoleController {
	return &RoleController{}
}

// Index displays the roles list page for a tenant
func (c *RoleController) Index(ctx http.Context) http.Response {
	tenantID := ctx.Request().Input("tenant_id", "")
	if tenantID == "" {
		return ctx.Response().View().Make("roles/index.tmpl", map[string]interface{}{
			"title": "Roles",
			"error": "Tenant ID is required",
			"roles": []models.Role{},
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
		return ctx.Response().View().Make("roles/index.tmpl", map[string]interface{}{
			"title":    "Roles",
			"error":    "Invalid cursor format",
			"roles":    []models.Role{},
			"tenantID": tenantID,
		})
	}

	var roles []models.Role
	err = query.Find(&roles)
	if err != nil {
		return ctx.Response().View().Make("roles/index.tmpl", map[string]interface{}{
			"title":    "Roles",
			"error":    "Failed to retrieve roles",
			"roles":    []models.Role{},
			"tenantID": tenantID,
		})
	}

	// Check if there are more results
	hasMore := len(roles) > limit
	if hasMore {
		roles = roles[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(roles, limit, cursor, hasMore)

	// Get unique guards for filter
	var guards []string
	facades.Orm().Query().Where("tenant_id = ?", tenantID).
		Distinct("guard").
		Pluck("guard", &guards)

	return ctx.Response().View().Make("roles/index.tmpl", map[string]interface{}{
		"title":      "Roles",
		"roles":      roles,
		"pagination": paginationInfo,
		"tenantID":   tenantID,
		"filters": map[string]interface{}{
			"search": search,
			"guard":  "",
			"guards": guards,
		},
	})
}

// Show displays a specific role
func (c *RoleController) Show(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	if roleID == "" {
		return ctx.Response().Redirect(302, "/roles")
	}

	var role models.Role
	err := facades.Orm().Query().Where("id = ?", roleID).First(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/show.tmpl", map[string]interface{}{
			"title": "Role Not Found",
			"error": "Role not found",
		})
	}

	return ctx.Response().View().Make("roles/show.tmpl", map[string]interface{}{
		"title": "Role: " + role.Name,
		"role":  role,
	})
}

// Create displays the role creation form
func (c *RoleController) Create(ctx http.Context) http.Response {
	tenantID := ctx.Request().Input("tenant_id", "")
	return ctx.Response().View().Make("roles/create.tmpl", map[string]interface{}{
		"title":    "Create Role",
		"tenantID": tenantID,
	})
}

// Store handles role creation
func (c *RoleController) Store(ctx http.Context) http.Response {
	// Get form data
	name := ctx.Request().Input("name", "")
	description := ctx.Request().Input("description", "")
	tenantID := ctx.Request().Input("tenant_id", "")
	// isActive := ctx.Request().Input("is_active", "true") == "true"

	// Validate required fields
	if name == "" || tenantID == "" {
		return ctx.Response().View().Make("roles/create.tmpl", map[string]interface{}{
			"title":       "Create Role",
			"error":       "Name and Tenant ID are required",
			"name":        name,
			"description": description,
			"tenantID":    tenantID,
		})
	}

	// Create role
	role := models.Role{
		Name:        name,
		Description: description,
		TenantID:    &tenantID,
		// IsActive:    isActive,
	}

	err := facades.Orm().Query().Create(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/create.tmpl", map[string]interface{}{
			"title":       "Create Role",
			"error":       "Failed to create role",
			"name":        name,
			"description": description,
			"tenantID":    tenantID,
		})
	}

	return ctx.Response().Redirect(302, "/roles/"+role.ID)
}

// Edit displays the role edit form
func (c *RoleController) Edit(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	if roleID == "" {
		return ctx.Response().Redirect(302, "/roles")
	}

	var role models.Role
	err := facades.Orm().Query().Where("id = ?", roleID).First(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/edit.tmpl", map[string]interface{}{
			"title": "Role Not Found",
			"error": "Role not found",
		})
	}

	return ctx.Response().View().Make("roles/edit.tmpl", map[string]interface{}{
		"title": "Edit Role: " + role.Name,
		"role":  role,
	})
}

// Update handles role updates
func (c *RoleController) Update(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	if roleID == "" {
		return ctx.Response().Redirect(302, "/roles")
	}

	var role models.Role
	err := facades.Orm().Query().Where("id = ?", roleID).First(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/edit.tmpl", map[string]interface{}{
			"title": "Role Not Found",
			"error": "Role not found",
		})
	}

	// Get form data
	name := ctx.Request().Input("name", "")
	description := ctx.Request().Input("description", "")
	// isActive := ctx.Request().Input("is_active", "true") == "true"

	// Validate required fields
	if name == "" {
		return ctx.Response().View().Make("roles/edit.tmpl", map[string]interface{}{
			"title": "Edit Role",
			"error": "Name is required",
			"role":  role,
		})
	}

	// Update role
	role.Name = name
	role.Description = description
	// role.IsActive = isActive

	err = facades.Orm().Query().Save(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/edit.tmpl", map[string]interface{}{
			"title": "Edit Role",
			"error": "Failed to update role",
			"role":  role,
		})
	}

	return ctx.Response().Redirect(302, "/roles/"+role.ID)
}

// Delete handles role deletion
func (c *RoleController) Delete(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	if roleID == "" {
		return ctx.Response().Redirect(302, "/roles")
	}

	var role models.Role
	err := facades.Orm().Query().Where("id = ?", roleID).First(&role)
	if err != nil {
		return ctx.Response().Redirect(302, "/roles")
	}

	// Delete role
	_, err = facades.Orm().Query().Delete(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/show.tmpl", map[string]interface{}{
			"title": "Role: " + role.Name,
			"role":  role,
			"error": "Failed to delete role",
		})
	}

	return ctx.Response().Redirect(302, "/roles")
}

// Permissions displays permissions for a specific role
func (c *RoleController) Permissions(ctx http.Context) http.Response {
	roleID := ctx.Request().Route("id")
	if roleID == "" {
		return ctx.Response().Redirect(302, "/roles")
	}

	var role models.Role
	err := facades.Orm().Query().Where("id = ?", roleID).First(&role)
	if err != nil {
		return ctx.Response().View().Make("roles/permissions.tmpl", map[string]interface{}{
			"title": "Role Not Found",
			"error": "Role not found",
		})
	}

	// Get permissions for this role
	var permissions []models.Permission
	err = facades.Orm().Query().
		Where("id IN (SELECT permission_id FROM role_permissions WHERE role_id = ?)", roleID).
		Find(&permissions)

	if err != nil {
		return ctx.Response().View().Make("roles/permissions.tmpl", map[string]interface{}{
			"title":       "Permissions - " + role.Name,
			"role":        role,
			"error":       "Failed to retrieve permissions",
			"permissions": []models.Permission{},
		})
	}

	return ctx.Response().View().Make("roles/permissions.tmpl", map[string]interface{}{
		"title":       "Permissions - " + role.Name,
		"role":        role,
		"permissions": permissions,
	})
}
