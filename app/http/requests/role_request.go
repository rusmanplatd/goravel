package requests

// CreateRoleRequest represents the request for creating a role
// @Description Request model for creating a new role
type CreateRoleRequest struct {
	// Role name
	// @example admin
	Name string `json:"name" binding:"required" example:"admin" validate:"required"`

	// Role guard (authentication guard)
	// @example api
	Guard string `json:"guard" example:"api"`

	// Role description
	// @example Administrator role with full access
	Description string `json:"description" example:"Administrator role with full access"`
}

// UpdateRoleRequest represents the request for updating a role
// @Description Request model for updating an existing role
type UpdateRoleRequest struct {
	// Role name
	// @example admin
	Name string `json:"name" example:"admin"`

	// Role guard (authentication guard)
	// @example api
	Guard string `json:"guard" example:"api"`

	// Role description
	// @example Administrator role with full access
	Description string `json:"description" example:"Administrator role with full access"`
}

// AssignPermissionRequest represents the request for assigning permissions to a role
// @Description Request model for assigning permissions to a role
type AssignPermissionRequest struct {
	// Array of permission IDs to assign
	// @example ["01HXYZ123456789ABCDEFGHIJK", "01HXYZ123456789ABCDEFGHIJL"]
	PermissionIDs []string `json:"permission_ids" binding:"required" example:"[\"01HXYZ123456789ABCDEFGHIJK\", \"01HXYZ123456789ABCDEFGHIJL\"]" validate:"required"`
}
