package requests

// CreatePermissionRequest represents the request for creating a permission
// @Description Request model for creating a new permission
type CreatePermissionRequest struct {
	// Permission name
	// @example users.create
	Name string `json:"name" binding:"required" example:"users.create" validate:"required"`

	// Permission guard (authentication guard)
	// @example api
	Guard string `json:"guard" example:"api"`

	// Permission description
	// @example Create new users
	Description string `json:"description" example:"Create new users"`
}

// UpdatePermissionRequest represents the request for updating a permission
// @Description Request model for updating an existing permission
type UpdatePermissionRequest struct {
	// Permission name
	// @example users.create
	Name string `json:"name" example:"users.create"`

	// Permission guard (authentication guard)
	// @example api
	Guard string `json:"guard" example:"api"`

	// Permission description
	// @example Create new users
	Description string `json:"description" example:"Create new users"`
}
