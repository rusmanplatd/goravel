package requests

import (
	"time"

	"github.com/goravel/framework/contracts/http"
)

// OrganizationRequest represents the request data for organization operations
type OrganizationRequest struct {
	// Organization name
	// @example Acme Corporation
	Name string `json:"name" validate:"required,min=2,max=255" example:"Acme Corporation"`

	// Organization slug for URL identification
	// @example acme-corp
	Slug string `json:"slug" validate:"omitempty,min=2,max=100,regexp=^[a-z0-9-]+$" example:"acme-corp"`

	// Organization domain
	// @example acme.com
	Domain string `json:"domain" validate:"omitempty,email" example:"acme.com"`

	// Organization description
	// @example Leading technology solutions provider
	Description string `json:"description" validate:"omitempty,max=1000" example:"Leading technology solutions provider"`

	// Organization type (company, nonprofit, government, educational)
	// @example company
	Type string `json:"type" validate:"omitempty,oneof=company nonprofit government educational" example:"company"`

	// Industry/sector
	// @example Technology
	Industry string `json:"industry" validate:"omitempty,max=100" example:"Technology"`

	// Organization size (startup, small, medium, large, enterprise)
	// @example medium
	Size string `json:"size" validate:"omitempty,oneof=startup small medium large enterprise" example:"medium"`

	// Founded date
	// @example 2020-01-15T00:00:00Z
	FoundedAt *time.Time `json:"founded_at" validate:"omitempty" example:"2020-01-15T00:00:00Z"`

	// Organization website
	// @example https://acme.com
	Website string `json:"website" validate:"omitempty,url" example:"https://acme.com"`

	// Organization logo URL
	// @example https://acme.com/logo.png
	Logo string `json:"logo" validate:"omitempty,url" example:"https://acme.com/logo.png"`

	// Organization banner URL
	// @example https://acme.com/banner.png
	Banner string `json:"banner" validate:"omitempty,url" example:"https://acme.com/banner.png"`

	// Primary contact email
	// @example contact@acme.com
	ContactEmail string `json:"contact_email" validate:"omitempty,email" example:"contact@acme.com"`

	// Primary contact phone
	// @example +1-555-123-4567
	ContactPhone string `json:"contact_phone" validate:"omitempty,max=20" example:"+1-555-123-4567"`

	// Organization address
	// @example 123 Main St, City, State 12345
	Address string `json:"address" validate:"omitempty,max=500" example:"123 Main St, City, State 12345"`

	// Country ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID *string `json:"country_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Province/State ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID *string `json:"province_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// City ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID *string `json:"city_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// District ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	DistrictID *string `json:"district_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Postal/ZIP code
	// @example 12345
	PostalCode string `json:"postal_code" validate:"omitempty,max=20" example:"12345"`

	// Tenant ID that this organization belongs to (one-to-one relationship)
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `json:"tenant_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent organization ID for hierarchical structure
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentOrganizationID *string `json:"parent_organization_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization settings as JSON
	// @example {"theme":"dark","timezone":"UTC","features":{"api_access":true,"analytics":true}}
	Settings string `json:"settings" validate:"omitempty,json" example:"{\"theme\":\"dark\",\"timezone\":\"UTC\",\"features\":{\"api_access\":true,\"analytics\":true}}"`
}

// OrganizationUserRequest represents the request data for adding a user to an organization
type OrganizationUserRequest struct {
	// User ID to add to organization
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in organization (owner, admin, member, guest)
	// @example member
	Role string `json:"role" validate:"omitempty,oneof=owner admin member guest" example:"member"`

	// User status in organization (active, inactive, suspended)
	// @example active
	Status string `json:"status" validate:"omitempty,oneof=active inactive suspended" example:"active"`

	// User's title/position in organization
	// @example Senior Software Engineer
	Title string `json:"title" validate:"omitempty,max=100" example:"Senior Software Engineer"`

	// User's employee ID
	// @example EMP001
	EmployeeID string `json:"employee_id" validate:"omitempty,max=50" example:"EMP001"`

	// User's department ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `json:"department_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's team ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID *string `json:"team_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ManagerID *string `json:"manager_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's hire date
	// @example 2024-01-15T00:00:00Z
	HireDate *time.Time `json:"hire_date" validate:"omitempty" example:"2024-01-15T00:00:00Z"`

	// When the user's membership expires
	// @example 2025-01-15T10:30:00Z
	ExpiresAt *time.Time `json:"expires_at" validate:"omitempty" example:"2025-01-15T10:30:00Z"`

	// User's permissions as JSON
	// @example ["read:projects","write:reports"]
	Permissions string `json:"permissions" validate:"omitempty,json" example:"[\"read:projects\",\"write:reports\"]"`
}

// DepartmentRequest represents the request data for department operations
type DepartmentRequest struct {
	// Department name
	// @example Engineering
	Name string `json:"name" validate:"required,min=2,max=255" example:"Engineering"`

	// Department code
	// @example ENG
	Code string `json:"code" validate:"omitempty,max=10" example:"ENG"`

	// Department description
	// @example Software engineering and development
	Description string `json:"description" validate:"omitempty,max=1000" example:"Software engineering and development"`

	// Department color for UI
	// @example #3B82F6
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#3B82F6"`

	// Department icon
	// @example engineering
	Icon string `json:"icon" validate:"omitempty,max=50" example:"engineering"`

	// Whether the department is active
	// @example true
	IsActive bool `json:"is_active" validate:"omitempty" example:"true"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent department ID for hierarchical structure
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentDepartmentID *string `json:"parent_department_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ManagerID *string `json:"manager_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// TeamRequest represents the request data for team operations
type TeamRequest struct {
	// Team name
	// @example Backend Development
	Name string `json:"name" validate:"required,min=2,max=255" example:"Backend Development"`

	// Team code
	// @example BE-DEV
	Code string `json:"code" validate:"omitempty,max=20" example:"BE-DEV"`

	// Team description
	// @example Backend development and API team
	Description string `json:"description" validate:"omitempty,max=1000" example:"Backend development and API team"`

	// Team type (functional, project, cross-functional)
	// @example functional
	Type string `json:"type" validate:"omitempty,oneof=functional project cross-functional" example:"functional"`

	// Team color for UI
	// @example #10B981
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#10B981"`

	// Team icon
	// @example backend
	Icon string `json:"icon" validate:"omitempty,max=50" example:"backend"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `json:"department_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team lead ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamLeadID *string `json:"team_lead_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Maximum team size
	// @example 10
	MaxSize int `json:"max_size" validate:"omitempty,min=1,max=100" example:"10"`
}

// ProjectRequest represents the request data for project operations
type ProjectRequest struct {
	// Project name
	// @example Customer Portal Redesign
	Name string `json:"name" validate:"required,min=2,max=255" example:"Customer Portal Redesign"`

	// Project code
	// @example CPR-2024
	Code string `json:"code" validate:"omitempty,max=20" example:"CPR-2024"`

	// Project description
	// @example Redesign and modernize the customer portal
	Description string `json:"description" validate:"omitempty,max=1000" example:"Redesign and modernize the customer portal"`

	// Project status (planning, active, on-hold, completed, cancelled)
	// @example active
	Status string `json:"status" validate:"omitempty,oneof=planning active on-hold completed cancelled" example:"active"`

	// Project priority (low, medium, high, critical)
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// Project color for UI
	// @example #F59E0B
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#F59E0B"`

	// Project icon
	// @example project
	Icon string `json:"icon" validate:"omitempty,max=50" example:"project"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectManagerID *string `json:"project_manager_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project start date
	// @example 2024-01-15T00:00:00Z
	StartDate *time.Time `json:"start_date" validate:"omitempty" example:"2024-01-15T00:00:00Z"`

	// Project end date
	// @example 2024-06-15T00:00:00Z
	EndDate *time.Time `json:"end_date" validate:"omitempty" example:"2024-06-15T00:00:00Z"`

	// Project budget
	// @example 50000.00
	Budget float64 `json:"budget" validate:"omitempty,min=0" example:"50000.00"`

	// Project settings as JSON
	// @example {"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"}}
	Settings string `json:"settings" validate:"omitempty,json" example:"{\"timezone\":\"UTC\",\"working_hours\":{\"start\":\"09:00\",\"end\":\"17:00\"}}"`
}

// DepartmentUserRequest represents the request data for adding a user to a department
type DepartmentUserRequest struct {
	// User ID to add to department
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in department (manager, member, lead)
	// @example member
	Role string `json:"role" validate:"omitempty,oneof=manager member lead" example:"member"`
}

// TeamUserRequest represents the request data for adding a user to a team
type TeamUserRequest struct {
	// User ID to add to team
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in team (lead, member, contributor)
	// @example member
	Role string `json:"role" validate:"omitempty,oneof=lead member contributor" example:"member"`

	// User's allocation percentage to this team
	// @example 100.0
	Allocation float64 `json:"allocation" validate:"omitempty,min=0,max=100" example:"100.0"`
}

// ProjectUserRequest represents the request data for adding a user to a project
type ProjectUserRequest struct {
	// User ID to add to project
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in project (manager, member, contributor, reviewer)
	// @example member
	Role string `json:"role" validate:"omitempty,oneof=manager member contributor reviewer" example:"member"`

	// User's allocation percentage to this project
	// @example 100.0
	Allocation float64 `json:"allocation" validate:"omitempty,min=0,max=100" example:"100.0"`
}

// TeamProjectRequest represents the request data for adding a team to a project
type TeamProjectRequest struct {
	// Team ID to add to project
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID string `json:"team_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team role in project (lead, contributor, reviewer)
	// @example contributor
	Role string `json:"role" validate:"omitempty,oneof=lead contributor reviewer" example:"contributor"`

	// Team's allocation percentage to this project
	// @example 100.0
	Allocation float64 `json:"allocation" validate:"omitempty,min=0,max=100" example:"100.0"`
}

// Validation methods for request types

// Authorize validates the OrganizationRequest
func (r *OrganizationRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the OrganizationUserRequest
func (r *OrganizationUserRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the DepartmentRequest
func (r *DepartmentRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TeamRequest
func (r *TeamRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the ProjectRequest
func (r *ProjectRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the DepartmentUserRequest
func (r *DepartmentUserRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TeamUserRequest
func (r *TeamUserRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the ProjectUserRequest
func (r *ProjectUserRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TeamProjectRequest
func (r *TeamProjectRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}
