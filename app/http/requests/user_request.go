package requests

// CreateUserRequest represents the request for creating a user
// @Description Request model for creating a new user
type CreateUserRequest struct {
	// User's full name
	// @example John Doe
	Name string `json:"name" binding:"required" example:"John Doe" validate:"required"`

	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"required,email" example:"john.doe@example.com" validate:"required,email"`

	// User's password
	// @example password123
	// @minLength 8
	Password string `json:"password" binding:"required,min=8" example:"password123" validate:"required,min=8"`

	// Whether the user is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`
}

// UpdateUserRequest represents the request for updating a user
// @Description Request model for updating an existing user
type UpdateUserRequest struct {
	// User's full name
	// @example John Doe
	Name string `json:"name" example:"John Doe"`

	// User's email address
	// @example john.doe@example.com
	Email string `json:"email" binding:"omitempty,email" example:"john.doe@example.com" validate:"omitempty,email"`

	// User's password (optional for updates)
	// @example newpassword123
	// @minLength 8
	Password string `json:"password" binding:"omitempty,min=8" example:"newpassword123" validate:"omitempty,min=8"`

	// Whether the user is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`
}

// AssignRoleRequest represents the request for assigning a role to a user
// @Description Request model for assigning a role to a user within a organization
type AssignRoleRequest struct {
	// Role ID to assign
	// @example 01HXYZ123456789ABCDEFGHIJK
	RoleID string `json:"role_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Organization ID for the role assignment
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}
