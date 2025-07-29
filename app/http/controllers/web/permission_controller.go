package web

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type PermissionController struct{}

func NewPermissionController() *PermissionController {
	return &PermissionController{}
}

// Index displays the permissions list page for a organization
func (c *PermissionController) Index(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	if organizationId == "" {
		return ctx.Response().View().Make("permissions/index.tmpl", map[string]interface{}{
			"title":       "Permissions",
			"error":       "Organization ID is required",
			"permissions": []models.Permission{},
		})
	}

	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	guard := ctx.Request().Input("guard", "")

	// Build query
	query := facades.Orm().Query().Where("organization_id = ?", organizationId)

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ? OR description LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	// Apply guard filter
	if guard != "" {
		query = query.Where("guard = ?", guard)
	}

	// Apply cursor pagination
	if cursor != "" {
		query = query.Where("id > ?", cursor)
	}

	// Get permissions
	var permissions []models.Permission
	err := query.Limit(limit + 1).Order("id ASC").Find(&permissions)
	if err != nil {
		return ctx.Response().View().Make("permissions/index.tmpl", map[string]interface{}{
			"title":       "Permissions",
			"error":       "Failed to load permissions",
			"permissions": []models.Permission{},
		})
	}

	// Check if there are more results
	hasMore := len(permissions) > limit
	if hasMore {
		permissions = permissions[:limit]
	}

	// Get next cursor
	nextCursor := ""
	if hasMore && len(permissions) > 0 {
		nextCursor = permissions[len(permissions)-1].ID
	}

	// Get unique guards for filter
	var guards []string
	facades.Orm().Query().Where("organization_id = ?", organizationId).
		Distinct("guard").
		Pluck("guard", &guards)

	return ctx.Response().View().Make("permissions/index.tmpl", map[string]interface{}{
		"title":          "Permissions",
		"organizationId": organizationId,
		"permissions":    permissions,
		"pagination": map[string]interface{}{
			"cursor":     cursor,
			"nextCursor": nextCursor,
			"limit":      limit,
			"hasMore":    hasMore,
		},
		"filters": map[string]interface{}{
			"search": search,
			"guard":  guard,
			"guards": guards,
		},
	})
}

// Create displays the create permission page
func (c *PermissionController) Create(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	if organizationId == "" {
		return ctx.Response().Redirect(302, "/organizations")
	}

	return ctx.Response().View().Make("permissions/create.tmpl", map[string]interface{}{
		"title":          "Create Permission",
		"organizationId": organizationId,
	})
}

// Store creates a new permission
func (c *PermissionController) Store(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	if organizationId == "" {
		return ctx.Response().Redirect(302, "/organizations")
	}

	// Validate input
	name := ctx.Request().Input("name", "")
	description := ctx.Request().Input("description", "")
	guard := ctx.Request().Input("guard", "web")

	if name == "" {
		return ctx.Response().View().Make("permissions/create.tmpl", map[string]interface{}{
			"title":          "Create Permission",
			"organizationId": organizationId,
			"error":          "Name is required",
			"name":           name,
			"description":    description,
			"guard":          guard,
		})
	}

	// Check if permission already exists
	var existingPermission models.Permission
	err := facades.Orm().Query().Where("organization_id = ? AND name = ?", organizationId, name).First(&existingPermission)
	if err == nil {
		return ctx.Response().View().Make("permissions/create.tmpl", map[string]interface{}{
			"title":          "Create Permission",
			"organizationId": organizationId,
			"error":          "Permission with this name already exists",
			"name":           name,
			"description":    description,
			"guard":          guard,
		})
	}

	// Create permission
	permission := models.Permission{
		OrganizationID: &organizationId,
		Name:           name,
		Description:    description,
		Guard:          guard,
	}

	err = facades.Orm().Query().Create(&permission)
	if err != nil {
		return ctx.Response().View().Make("permissions/create.tmpl", map[string]interface{}{
			"title":          "Create Permission",
			"organizationId": organizationId,
			"error":          "Failed to create permission",
			"name":           name,
			"description":    description,
			"guard":          guard,
		})
	}

	return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
}

// Edit displays the edit permission page
func (c *PermissionController) Edit(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	permissionID := ctx.Request().Input("id", "")

	if organizationId == "" || permissionID == "" {
		return ctx.Response().Redirect(302, "/organizations")
	}

	// Get permission
	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", permissionID, organizationId).First(&permission)
	if err != nil {
		return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
	}

	return ctx.Response().View().Make("permissions/edit.tmpl", map[string]interface{}{
		"title":          "Edit Permission",
		"organizationId": organizationId,
		"permission":     permission,
	})
}

// Update updates an existing permission
func (c *PermissionController) Update(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	permissionID := ctx.Request().Input("id", "")

	if organizationId == "" || permissionID == "" {
		return ctx.Response().Redirect(302, "/organizations")
	}

	// Get permission
	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", permissionID, organizationId).First(&permission)
	if err != nil {
		return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
	}

	// Validate input
	name := ctx.Request().Input("name", "")
	description := ctx.Request().Input("description", "")
	guard := ctx.Request().Input("guard", "web")

	if name == "" {
		return ctx.Response().View().Make("permissions/edit.tmpl", map[string]interface{}{
			"title":          "Edit Permission",
			"organizationId": organizationId,
			"permission":     permission,
			"error":          "Name is required",
		})
	}

	// Check if name already exists (excluding current permission)
	var existingPermission models.Permission
	err = facades.Orm().Query().Where("organization_id = ? AND name = ? AND id != ?", organizationId, name, permissionID).First(&existingPermission)
	if err == nil {
		return ctx.Response().View().Make("permissions/edit.tmpl", map[string]interface{}{
			"title":          "Edit Permission",
			"organizationId": organizationId,
			"permission":     permission,
			"error":          "Permission with this name already exists",
		})
	}

	// Update permission
	permission.Name = name
	permission.Description = description
	permission.Guard = guard
	permission.UpdatedAt = time.Now()

	err = facades.Orm().Query().Save(&permission)
	if err != nil {
		return ctx.Response().View().Make("permissions/edit.tmpl", map[string]interface{}{
			"title":          "Edit Permission",
			"organizationId": organizationId,
			"permission":     permission,
			"error":          "Failed to update permission",
		})
	}

	return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
}

// Destroy deletes a permission
func (c *PermissionController) Destroy(ctx http.Context) http.Response {
	organizationId := ctx.Request().Input("organization_id", "")
	permissionID := ctx.Request().Input("id", "")

	if organizationId == "" || permissionID == "" {
		return ctx.Response().Redirect(302, "/organizations")
	}

	// Get permission
	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", permissionID, organizationId).First(&permission)
	if err != nil {
		return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
	}

	// Delete permission
	_, err = facades.Orm().Query().Delete(&permission)
	if err != nil {
		return ctx.Response().View().Make("permissions/index.tmpl", map[string]interface{}{
			"title":          "Permissions",
			"organizationId": organizationId,
			"error":          "Failed to delete permission",
			"permissions":    []models.Permission{},
		})
	}

	return ctx.Response().Redirect(302, "/permissions?organization_id="+organizationId)
}
