package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type PermissionController struct{}

func NewPermissionController() *PermissionController {
	return &PermissionController{}
}

// Index returns all permissions for the current organization
// @Summary Get all permissions
// @Description Retrieve a list of all permissions for the current organization with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags permissions
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[guard] query string false "Filter by guard name"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): roles,users,organization"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.Permission}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions [get]
func (pc *PermissionController) Index(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization context required",
			Timestamp: time.Now(),
		})
	}

	var permissions []models.Permission

	// Create query builder with organization context and allowed filters, sorts, and includes
	qb := querybuilder.For(&models.Permission{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Exact("guard"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("name", "guard", "created_at", "updated_at").
		AllowedIncludes("roles", "users", "organization").
		DefaultSort("-created_at")

	// Apply organization constraint to the base query
	query := qb.Build().Where("organization_id = ?", organizationId)

	// Create a new query builder with the constrained query
	constrainedQB := querybuilder.For(query).WithRequest(ctx)

	// Use AutoPaginate for unified pagination support
	result, err := constrainedQB.AutoPaginate(&permissions)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve permissions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Permissions retrieved successfully", result)
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
	organizationId := ctx.Value("organization_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", id, organizationId).First(&permission)
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
// @Description Create a new permission for a organization
// @Tags permissions
// @Accept json
// @Produce json
// @Param permission body models.Permission true "Permission data"
// @Success 201 {object} http.Json{data=models.Permission,message=string}
// @Failure 400 {object} http.Json{error=string}
// @Failure 500 {object} responses.ErrorResponse
// @Router /permissions [post]
func (pc *PermissionController) Store(ctx http.Context) http.Response {
	organizationId := ctx.Value("organization_id")
	if organizationId == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Organization context required",
		})
	}

	var permission models.Permission
	if err := ctx.Request().Bind(&permission); err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Invalid input data",
		})
	}

	// Set organization ID
	permission.OrganizationID = &[]string{organizationId.(string)}[0]

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
	organizationId := ctx.Value("organization_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", id, organizationId).First(&permission)
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
	organizationId := ctx.Value("organization_id")

	var permission models.Permission
	err := facades.Orm().Query().Where("id = ? AND organization_id = ?", id, organizationId).First(&permission)
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
