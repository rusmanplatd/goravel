package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type UserController struct {
	// Dependent services
}

func NewUserController() *UserController {
	return &UserController{
		// Inject services
	}
}

// Index returns all users
// @Summary Get all users
// @Description Retrieve a list of all users with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags users
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[email] query string false "Filter by email (partial match)"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[tenant_id] query string false "Filter by tenant ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): roles,permissions,tenant"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.User}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users [get]
func (uc *UserController) Index(ctx http.Context) http.Response {
	var users []models.User

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.User{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("email"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("tenant_id"),
		).
		AllowedSorts("name", "email", "created_at", "updated_at").
		AllowedIncludes("roles", "permissions", "tenant").
		DefaultSort("-created_at")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&users)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve users: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Users retrieved successfully", result)
}

// Show returns a specific user
// @Summary Get user by ID
// @Description Retrieve a specific user by their ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} responses.APIResponse{data=models.User}
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/{id} [get]
func (uc *UserController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      user,
		Timestamp: time.Now(),
	})
}

// Store creates a new user
// @Summary Create a new user
// @Description Create a new user with the provided information
// @Tags users
// @Accept json
// @Produce json
// @Param user body requests.CreateUserRequest true "User information"
// @Success 201 {object} responses.APIResponse{data=models.User}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users [post]
func (uc *UserController) Store(ctx http.Context) http.Response {
	var request requests.CreateUserRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	user := models.User{
		Name:     request.Name,
		Email:    request.Email,
		Password: request.Password,
		IsActive: request.IsActive,
	}

	// Hash password before saving
	hashedPassword, err := facades.Hash().Make(user.Password)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to hash password",
			Timestamp: time.Now(),
		})
	}
	user.Password = hashedPassword

	// Set default values
	user.IsActive = true

	err = facades.Orm().Query().Create(&user)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create user",
			Timestamp: time.Now(),
		})
	}

	// Don't return password in response
	user.Password = ""

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      user,
		Message:   "User created successfully",
		Timestamp: time.Now(),
	})
}

// Update updates an existing user
// @Summary Update a user
// @Description Update an existing user's information
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body requests.UpdateUserRequest true "Updated user information"
// @Success 200 {object} responses.APIResponse{data=models.User}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/{id} [put]
func (uc *UserController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.UpdateUserRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		user.Name = request.Name
	}
	if request.Email != "" {
		user.Email = request.Email
	}
	if request.Password != "" {
		hashedPassword, err := facades.Hash().Make(request.Password)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to hash password",
				Timestamp: time.Now(),
			})
		}
		user.Password = hashedPassword
	}
	user.IsActive = request.IsActive

	err = facades.Orm().Query().Save(&user)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update user",
			Timestamp: time.Now(),
		})
	}

	// Don't return password in response
	user.Password = ""

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      user,
		Message:   "User updated successfully",
		Timestamp: time.Now(),
	})
}

// Delete removes a user
// @Summary Delete a user
// @Description Delete a user by their ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/{id} [delete]
func (uc *UserController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&user)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete user",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User deleted successfully",
		Timestamp: time.Now(),
	})
}

// Tenants returns all tenants for a user
// @Summary Get user's tenants
// @Description Retrieve all tenants associated with a user
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} responses.APIResponse{data=[]models.Tenant}
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/{id}/tenants [get]
func (uc *UserController) Tenants(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	var tenants []models.Tenant
	err = facades.Orm().Query().
		Where("id IN (SELECT tenant_id FROM user_tenants WHERE user_id = ? AND is_active = ?)", user.ID, true).
		Find(&tenants)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user tenants",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      tenants,
		Timestamp: time.Now(),
	})
}

// Roles returns all roles for a user
// @Summary Get user's roles
// @Description Retrieve all roles associated with a user in a specific tenant
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param tenant_id query string true "Tenant ID"
// @Success 200 {object} responses.APIResponse{data=[]models.Role}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/{id}/roles [get]
func (uc *UserController) Roles(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	tenantID := ctx.Request().Query("tenant_id", "")

	if tenantID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Tenant ID is required",
			Timestamp: time.Now(),
		})
	}

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	roles, err := user.GetRolesForTenant(tenantID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user roles",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      roles,
		Timestamp: time.Now(),
	})
}

// AssignRole assigns a role to a user
// @Summary Assign role to user
// @Description Assign a specific role to a user in a tenant
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body requests.AssignRoleRequest true "Role assignment information"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/{id}/roles [post]
func (uc *UserController) AssignRole(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.AssignRoleRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	err = user.AssignRole(request.RoleID, request.TenantID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to assign role to user",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Role assigned successfully",
		Timestamp: time.Now(),
	})
}

// RevokeRole removes a role from a user
// @Summary Revoke role from user
// @Description Remove a specific role from a user in a tenant
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param role_id path string true "Role ID"
// @Param tenant_id query string true "Tenant ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /users/{id}/roles/{role_id} [delete]
func (uc *UserController) RevokeRole(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	roleID := ctx.Request().Route("role_id")
	tenantID := ctx.Request().Query("tenant_id", "")

	if tenantID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Tenant ID is required",
			Timestamp: time.Now(),
		})
	}

	var user models.User
	err := facades.Orm().Query().Where("id = ?", id).First(&user)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	err = user.RemoveRole(roleID, tenantID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to revoke role from user",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Role revoked successfully",
		Timestamp: time.Now(),
	})
}
