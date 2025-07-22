package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type PermissionController struct{}

func NewPermissionController() *PermissionController {
	return &PermissionController{}
}

// Index returns all permissions for a tenant
// @Summary Get all permissions
// @Description Retrieve a list of all permissions with cursor-based pagination
// @Tags permissions
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name"
// @Param guard query string false "Filter by guard"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Permission}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions [get]
func (pc *PermissionController) Index(ctx http.Context) http.Response {
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
	guard := ctx.Request().Input("guard", "")

	// Build query
	query := facades.Orm().Query().Where("tenant_id = ?", tenantID)

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ?", "%"+search+"%")
	}

	// Apply guard filter
	if guard != "" {
		query = query.Where("guard = ?", guard)
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

	var permissions []models.Permission
	err = query.Find(&permissions)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve permissions",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(permissions) > limit
	if hasMore {
		permissions = permissions[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(permissions, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   permissions,
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

// Show returns a specific permission
// @Summary Get a specific permission
// @Description Retrieve a single permission by its ID
// @Tags permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Success 200 {object} http.Json{data=models.Permission}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions/{id} [get]
func (pc *PermissionController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&permission)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Permission not found",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data": permission,
	})
}

// Store creates a new permission
// @Summary Create a new permission
// @Description Create a new permission for a tenant
// @Tags permissions
// @Accept json
// @Produce json
// @Param permission body models.Permission true "Permission data"
// @Success 201 {object} http.Json{data=models.Permission,message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions [post]
func (pc *PermissionController) Store(ctx http.Context) http.Response {
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Tenant context required",
		})
	}

	var permission models.Permission
	if err := ctx.Request().Bind(&permission); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	// Set tenant ID
	permission.TenantID = &[]string{tenantID.(string)}[0]

	err := facades.Orm().Query().Create(&permission)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to create permission",
		})
	}

	return ctx.Response().Status(201).Json(http.Json{
		"data":    permission,
		"message": "Permission created successfully",
	})
}

// Update updates an existing permission
// @Summary Update an existing permission
// @Description Update a permission by its ID
// @Tags permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Param permission body models.Permission true "Permission data"
// @Success 200 {object} http.Json{data=models.Permission,message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions/{id} [put]
func (pc *PermissionController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&permission)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Permission not found",
		})
	}

	if err := ctx.Request().Bind(&permission); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	err = facades.Orm().Query().Save(&permission)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to update permission",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"data":    permission,
		"message": "Permission updated successfully",
	})
}

// Delete removes a permission
// @Summary Delete a permission
// @Description Delete a permission by its ID
// @Tags permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Success 200 {object} http.Json{message=string}
// @Failure 404 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions/{id} [delete]
func (pc *PermissionController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND tenant_id = ?", id, tenantID).First(&permission)
	if err != nil {
		return ctx.Response().Status(404).Json(http.Json{
			"error": "Permission not found",
		})
	}

	_, err = facades.Orm().Query().Delete(&permission)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error": "Failed to delete permission",
		})
	}

	return ctx.Response().Success().Json(http.Json{
		"message": "Permission deleted successfully",
	})
}
