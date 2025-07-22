package v1

import (
	"strconv"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type TenantController struct{}

func NewTenantController() *TenantController {
	return &TenantController{}
}

// Index returns all tenants
// @Summary Get all tenants
// @Description Retrieve a list of all tenants with cursor-based pagination
// @Tags tenants
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or domain"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Tenant}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants [get]
func (tc *TenantController) Index(ctx http.Context) http.Response {
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
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var tenants []models.Tenant
	err = query.Find(&tenants)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tenants",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(tenants) > limit
	if hasMore {
		tenants = tenants[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(tenants, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   tenants,
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

// Show returns a specific tenant
// @Summary Get a specific tenant by ID
// @Description Retrieve a single tenant by its unique identifier
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Success 200 {object} http.Json{data=models.Tenant}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id} [get]
func (tc *TenantController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", id).First(&tenant)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Tenant not found",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": tenant,
	})
}

// Store creates a new tenant
// @Summary Create a new tenant
// @Description Create a new tenant with the provided data
// @Tags tenants
// @Accept json
// @Produce json
// @Param tenant body models.Tenant true "Tenant data"
// @Success 201 {object} http.Json{data=models.Tenant,message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants [post]
func (tc *TenantController) Store(ctx http.Context) http.Response {
	var tenant models.Tenant

	if err := ctx.Request().Bind(&tenant); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	// Set default values
	tenant.IsActive = true

	err := facades.Orm().Query().Create(&tenant)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to create tenant",
		})
	}

	return ctx.Response().Status(201).Json(http.Json{
		"data":    tenant,
		"message": "Tenant created successfully",
	})
}

// Update updates an existing tenant
// @Summary Update an existing tenant
// @Description Update an existing tenant by its unique identifier
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param tenant body models.Tenant true "Updated tenant data"
// @Success 200 {object} http.Json{data=models.Tenant,message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id} [put]
func (tc *TenantController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", id).First(&tenant)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Tenant not found",
		})
	}

	if err := ctx.Request().Bind(&tenant); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	err = facades.Orm().Query().Save(&tenant)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to update tenant",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data":    tenant,
		"message": "Tenant updated successfully",
	})
}

// Delete removes a tenant
// @Summary Delete a tenant
// @Description Delete a tenant by its unique identifier
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id} [delete]
func (tc *TenantController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", id).First(&tenant)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Tenant not found",
		})
	}

	_, err = facades.Orm().Query().Delete(&tenant)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to delete tenant",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "Tenant deleted successfully",
	})
}

// Users returns all users for a specific tenant
// @Summary Get all users for a specific tenant
// @Description Retrieve a list of all users associated with a tenant
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Success 200 {object} http.Json{data=[]models.User}
// @Failure 400 {object} http.Json{error=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id}/users [get]
func (tc *TenantController) Users(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid tenant ID",
		})
	}

	var users []models.User
	err = facades.Orm().Query().
		Where("id IN (SELECT user_id FROM user_tenants WHERE tenant_id = ? AND is_active = ?)", tenantID, true).
		Find(&users)

	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to retrieve tenant users",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": users,
	})
}

// AddUser adds a user to a tenant
// @Summary Add a user to a tenant
// @Description Add a user to a tenant by their unique identifier
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param user_id body string true "User ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id}/users [post]
func (tc *TenantController) AddUser(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	userID := ctx.Request().Input("user_id")

	if userID == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "User ID is required",
		})
	}

	// Check if tenant exists
	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ?", tenantID).First(&tenant)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Tenant not found",
		})
	}

	// Check if user exists
	var user models.User
	err = facades.Orm().Query().Where("id = ?", userID).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "User not found",
		})
	}

	// Create user-tenant relationship
	userTenant := models.UserTenant{
		UserID:   user.ID,
		TenantID: tenant.ID,
		IsActive: true,
	}

	err = facades.Orm().Query().Create(&userTenant)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to add user to tenant",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "User added to tenant successfully",
	})
}

// RemoveUser removes a user from a tenant
// @Summary Remove a user from a tenant
// @Description Remove a user from a tenant by their unique identifier
// @Tags tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param user_id path string true "User ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /tenants/{id}/users/{user_id} [delete]
func (tc *TenantController) RemoveUser(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	_, err := facades.Orm().Query().
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		Delete(&models.UserTenant{})

	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to remove user from tenant",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "User removed from tenant successfully",
	})
}
