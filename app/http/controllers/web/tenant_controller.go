package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/models"
)

type TenantController struct{}

func NewTenantController() *TenantController {
	return &TenantController{}
}

// Index displays the tenants list page
func (c *TenantController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")

	// Build query
	query := facades.Orm().Query()

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ? OR domain LIKE ?", "%"+search+"%", "%"+search+"%")
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
		return ctx.Response().View().Make("tenants/index.tmpl", map[string]interface{}{
			"title":   "Tenants",
			"error":   "Invalid cursor format",
			"tenants": []models.Tenant{},
		})
	}

	var tenants []models.Tenant
	err = query.Find(&tenants)
	if err != nil {
		return ctx.Response().View().Make("tenants/index.tmpl", map[string]interface{}{
			"title":   "Tenants",
			"error":   "Failed to retrieve tenants",
			"tenants": []models.Tenant{},
		})
	}

	// Check if there are more results
	hasMore := len(tenants) > limit
	if hasMore {
		tenants = tenants[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(tenants, limit, cursor, hasMore)

	return ctx.Response().View().Make("tenants/index.tmpl", map[string]interface{}{
		"title":      "Tenants",
		"tenants":    tenants,
		"pagination": paginationInfo,
		"filters": map[string]interface{}{
			"search":    search,
			"is_active": isActive,
		},
	})
}

// Show displays a specific tenant
func (c *TenantController) Show(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	if tenantID == "" {
		return ctx.Response().Redirect(302, "/tenants")
	}

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/show.tmpl", map[string]interface{}{
			"title": "Tenant Not Found",
			"error": "Tenant not found",
		})
	}

	return ctx.Response().View().Make("tenants/show.tmpl", map[string]interface{}{
		"title":  "Tenant: " + tenant.Name,
		"tenant": tenant,
	})
}

// Create displays the tenant creation form
func (c *TenantController) Create(ctx http.Context) http.Response {
	return ctx.Response().View().Make("tenants/create.tmpl", map[string]interface{}{
		"title": "Create Tenant",
	})
}

// Store handles tenant creation
func (c *TenantController) Store(ctx http.Context) http.Response {
	// Get form data
	name := ctx.Request().Input("name", "")
	domain := ctx.Request().Input("domain", "")
	description := ctx.Request().Input("description", "")
	isActive := ctx.Request().Input("is_active", "true") == "true"

	// Validate required fields
	if name == "" {
		return ctx.Response().View().Make("tenants/create.tmpl", map[string]interface{}{
			"title":       "Create Tenant",
			"error":       "Name is required",
			"name":        name,
			"domain":      domain,
			"description": description,
		})
	}

	// Create tenant
	tenant := models.Tenant{
		Name:        name,
		Domain:      domain,
		Description: description,
		IsActive:    isActive,
	}

	err := facades.Orm().Query().Create(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/create.tmpl", map[string]interface{}{
			"title":       "Create Tenant",
			"error":       "Failed to create tenant",
			"name":        name,
			"domain":      domain,
			"description": description,
		})
	}

	return ctx.Response().Redirect(302, "/tenants/"+tenant.ID)
}

// Edit displays the tenant edit form
func (c *TenantController) Edit(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	if tenantID == "" {
		return ctx.Response().Redirect(302, "/tenants")
	}

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/edit.tmpl", map[string]interface{}{
			"title": "Tenant Not Found",
			"error": "Tenant not found",
		})
	}

	return ctx.Response().View().Make("tenants/edit.tmpl", map[string]interface{}{
		"title":  "Edit Tenant: " + tenant.Name,
		"tenant": tenant,
	})
}

// Update handles tenant updates
func (c *TenantController) Update(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	if tenantID == "" {
		return ctx.Response().Redirect(302, "/tenants")
	}

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/edit.tmpl", map[string]interface{}{
			"title": "Tenant Not Found",
			"error": "Tenant not found",
		})
	}

	// Get form data
	name := ctx.Request().Input("name", "")
	domain := ctx.Request().Input("domain", "")
	description := ctx.Request().Input("description", "")
	isActive := ctx.Request().Input("is_active", "true") == "true"

	// Validate required fields
	if name == "" {
		return ctx.Response().View().Make("tenants/edit.tmpl", map[string]interface{}{
			"title":  "Edit Tenant",
			"error":  "Name is required",
			"tenant": tenant,
		})
	}

	// Update tenant
	tenant.Name = name
	tenant.Domain = domain
	tenant.Description = description
	tenant.IsActive = isActive

	err = facades.Orm().Query().Save(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/edit.tmpl", map[string]interface{}{
			"title":  "Edit Tenant",
			"error":  "Failed to update tenant",
			"tenant": tenant,
		})
	}

	return ctx.Response().Redirect(302, "/tenants/"+tenant.ID)
}

// Delete handles tenant deletion
func (c *TenantController) Delete(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	if tenantID == "" {
		return ctx.Response().Redirect(302, "/tenants")
	}

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().Redirect(302, "/tenants")
	}

	// Delete tenant
	_, err = facades.Orm().Query().Delete(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/show.tmpl", map[string]interface{}{
			"title":  "Tenant: " + tenant.Name,
			"tenant": tenant,
			"error":  "Failed to delete tenant",
		})
	}

	return ctx.Response().Redirect(302, "/tenants")
}

// Users displays users for a specific tenant
func (c *TenantController) Users(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	if tenantID == "" {
		return ctx.Response().Redirect(302, "/tenants")
	}

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().View().Make("tenants/users.tmpl", map[string]interface{}{
			"title": "Tenant Not Found",
			"error": "Tenant not found",
		})
	}

	// Get users for this tenant
	var users []models.User
	err = facades.Orm().Query().
		Where("id IN (SELECT user_id FROM user_tenants WHERE tenant_id = ?)", tenantID).
		Find(&users)

	if err != nil {
		return ctx.Response().View().Make("tenants/users.tmpl", map[string]interface{}{
			"title":  "Users - " + tenant.Name,
			"tenant": tenant,
			"error":  "Failed to retrieve users",
			"users":  []models.User{},
		})
	}

	return ctx.Response().View().Make("tenants/users.tmpl", map[string]interface{}{
		"title":  "Users - " + tenant.Name,
		"tenant": tenant,
		"users":  users,
	})
}
