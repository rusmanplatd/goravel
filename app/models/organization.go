package models

import (
	"time"
)

// Organization represents an organization in the system
// @Description Organization model with hierarchical structure and departments
type Organization struct {
	BaseModel

	// Organization name
	// @example Acme Corporation
	Name string `gorm:"not null" json:"name" example:"Acme Corporation"`

	// Organization slug for URL identification
	// @example acme-corp
	Slug string `gorm:"unique;not null" json:"slug" example:"acme-corp"`

	// Organization domain
	// @example acme.com
	Domain string `gorm:"unique" json:"domain" example:"acme.com"`

	// Organization description
	// @example Leading technology solutions provider
	Description string `json:"description" example:"Leading technology solutions provider"`

	// Organization type (company, nonprofit, government, educational)
	// @example company
	Type string `gorm:"default:'company'" json:"type" example:"company"`

	// Industry/sector
	// @example Technology
	Industry string `json:"industry" example:"Technology"`

	// Organization size (startup, small, medium, large, enterprise)
	// @example medium
	Size string `gorm:"default:'medium'" json:"size" example:"medium"`

	// Founded date
	// @example 2020-01-15T00:00:00Z
	FoundedAt *time.Time `json:"founded_at,omitempty" example:"2020-01-15T00:00:00Z"`

	// Organization website
	// @example https://acme.com
	Website string `json:"website" example:"https://acme.com"`

	// Organization logo URL
	// @example https://acme.com/logo.png
	Logo string `json:"logo" example:"https://acme.com/logo.png"`

	// Organization banner URL
	// @example https://acme.com/banner.png
	Banner string `json:"banner" example:"https://acme.com/banner.png"`

	// Primary contact email
	// @example contact@acme.com
	ContactEmail string `json:"contact_email" example:"contact@acme.com"`

	// Primary contact phone
	// @example +1-555-123-4567
	ContactPhone string `json:"contact_phone" example:"+1-555-123-4567"`

	// Organization address
	// @example 123 Main St, City, State 12345
	Address string `json:"address" example:"123 Main St, City, State 12345"`

	// Country ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID *string `gorm:"index;type:char(26)" json:"country_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Province/State ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID *string `gorm:"index;type:char(26)" json:"province_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// City ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID *string `gorm:"index;type:char(26)" json:"city_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// District ID for address
	// @example 01HXYZ123456789ABCDEFGHIJK
	DistrictID *string `gorm:"index;type:char(26)" json:"district_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Postal/ZIP code
	// @example 12345
	PostalCode string `json:"postal_code" example:"12345"`

	// Whether the organization is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether the organization is verified
	// @example false
	IsVerified bool `gorm:"default:false" json:"is_verified" example:"false"`

	// Verification date
	// @example 2024-01-15T10:30:00Z
	VerifiedAt *time.Time `json:"verified_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Organization settings as JSON
	// @example {"theme":"dark","timezone":"UTC","features":{"api_access":true,"analytics":true}}
	Settings string `gorm:"type:json" json:"settings" example:"{\"theme\":\"dark\",\"timezone\":\"UTC\",\"features\":{\"api_access\":true,\"analytics\":true}}"`

	// Tenant ID that this organization belongs to (one-to-one relationship)
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"unique;not null;index;type:char(26)" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent organization ID for hierarchical structure
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentOrganizationID *string `gorm:"index;type:char(26)" json:"parent_organization_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization level in hierarchy (0 = root, 1 = subsidiary, etc.)
	// @example 0
	Level int `gorm:"default:0" json:"level" example:"0"`

	// Organization path for hierarchical queries
	// @example /01HXYZ123456789ABCDEFGHIJK/01HXYZ123456789ABCDEFGHIJL
	Path string `gorm:"index" json:"path" example:"/01HXYZ123456789ABCDEFGHIJK/01HXYZ123456789ABCDEFGHIJL"`

	// Relationships
	// @Description Tenant that this organization belongs to
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Users associated with this organization
	Users []User `gorm:"many2many:user_organizations;" json:"users,omitempty"`

	// @Description Organization's country
	Country *Country `gorm:"foreignKey:CountryID" json:"country,omitempty"`

	// @Description Organization's province/state
	Province *Province `gorm:"foreignKey:ProvinceID" json:"province,omitempty"`

	// @Description Organization's city
	City *City `gorm:"foreignKey:CityID" json:"city,omitempty"`

	// @Description Organization's district
	District *District `gorm:"foreignKey:DistrictID" json:"district,omitempty"`

	// @Description Parent organization
	ParentOrganization *Organization `gorm:"foreignKey:ParentOrganizationID" json:"parent_organization,omitempty"`

	// @Description Subsidiary organizations
	Subsidiaries []Organization `gorm:"foreignKey:ParentOrganizationID" json:"subsidiaries,omitempty"`

	// @Description Organization's departments
	Departments []Department `gorm:"foreignKey:OrganizationID" json:"departments,omitempty"`

	// @Description Organization's teams
	Teams []Team `gorm:"foreignKey:OrganizationID" json:"teams,omitempty"`

	// @Description Organization's projects
	Projects []Project `gorm:"foreignKey:OrganizationID" json:"projects,omitempty"`
}

// Department represents a department within an organization
// @Description Department model for organizational structure
type Department struct {
	BaseModel

	// Department name
	// @example Engineering
	Name string `gorm:"not null" json:"name" example:"Engineering"`

	// Department code
	// @example ENG
	Code string `json:"code" example:"ENG"`

	// Department description
	// @example Software engineering and development
	Description string `json:"description" example:"Software engineering and development"`

	// Department color for UI
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Department icon
	// @example engineering
	Icon string `json:"icon" example:"engineering"`

	// Whether the department is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;index;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent department ID for hierarchical structure
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentDepartmentID *string `gorm:"index;type:char(26)" json:"parent_department_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department level in hierarchy
	// @example 0
	Level int `gorm:"default:0" json:"level" example:"0"`

	// Department path for hierarchical queries
	// @example /01HXYZ123456789ABCDEFGHIJK/01HXYZ123456789ABCDEFGHIJL
	Path string `gorm:"index" json:"path" example:"/01HXYZ123456789ABCDEFGHIJK/01HXYZ123456789ABCDEFGHIJL"`

	// Department manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ManagerID *string `gorm:"index;type:char(26)" json:"manager_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Organization this department belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Parent department
	ParentDepartment *Department `gorm:"foreignKey:ParentDepartmentID" json:"parent_department,omitempty"`

	// @Description Sub-departments
	SubDepartments []Department `gorm:"foreignKey:ParentDepartmentID" json:"sub_departments,omitempty"`

	// @Description Department manager
	Manager *User `gorm:"foreignKey:ManagerID" json:"manager,omitempty"`

	// @Description Users in this department
	Users []User `gorm:"many2many:user_departments;" json:"users,omitempty"`

	// @Description Teams in this department
	Teams []Team `gorm:"foreignKey:DepartmentID" json:"teams,omitempty"`
}

// Team represents a team within an organization
// @Description Team model for project and functional teams
type Team struct {
	BaseModel

	// Team name
	// @example Backend Development
	Name string `gorm:"not null" json:"name" example:"Backend Development"`

	// Team code
	// @example BE-DEV
	Code string `json:"code" example:"BE-DEV"`

	// Team description
	// @example Backend development and API team
	Description string `json:"description" example:"Backend development and API team"`

	// Team type (functional, project, cross-functional)
	// @example functional
	Type string `gorm:"default:'functional'" json:"type" example:"functional"`

	// Team color for UI
	// @example #10B981
	Color string `json:"color" example:"#10B981"`

	// Team icon
	// @example backend
	Icon string `json:"icon" example:"backend"`

	// Whether the team is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;index;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `gorm:"index;type:char(26)" json:"department_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team lead ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamLeadID *string `gorm:"index;type:char(26)" json:"team_lead_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Maximum team size
	// @example 10
	MaxSize int `json:"max_size" example:"10"`

	// Current team size
	// @example 8
	CurrentSize int `gorm:"default:0" json:"current_size" example:"8"`

	// Relationships
	// @Description Organization this team belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Department this team belongs to
	Department *Department `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`

	// @Description Team lead
	TeamLead *User `gorm:"foreignKey:TeamLeadID" json:"team_lead,omitempty"`

	// @Description Users in this team
	Users []User `gorm:"many2many:user_teams;" json:"users,omitempty"`

	// @Description Projects this team works on
	Projects []Project `gorm:"many2many:team_projects;" json:"projects,omitempty"`
}

// Project represents a project within an organization
// @Description Project model for project management
type Project struct {
	BaseModel

	// Project name
	// @example Customer Portal Redesign
	Name string `gorm:"not null" json:"name" example:"Customer Portal Redesign"`

	// Project code
	// @example CPR-2024
	Code string `json:"code" example:"CPR-2024"`

	// Project description
	// @example Redesign and modernize the customer portal
	Description string `json:"description" example:"Redesign and modernize the customer portal"`

	// Project status (planning, active, on-hold, completed, cancelled)
	// @example active
	Status string `gorm:"default:'planning'" json:"status" example:"active"`

	// Project priority (low, medium, high, critical)
	// @example high
	Priority string `gorm:"default:'medium'" json:"priority" example:"high"`

	// Project color for UI
	// @example #F59E0B
	Color string `json:"color" example:"#F59E0B"`

	// Project icon
	// @example project
	Icon string `json:"icon" example:"project"`

	// Whether the project is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"not null;index;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectManagerID *string `gorm:"index;type:char(26)" json:"project_manager_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project start date
	// @example 2024-01-15T00:00:00Z
	StartDate *time.Time `json:"start_date,omitempty" example:"2024-01-15T00:00:00Z"`

	// Project end date
	// @example 2024-06-15T00:00:00Z
	EndDate *time.Time `json:"end_date,omitempty" example:"2024-06-15T00:00:00Z"`

	// Project budget
	// @example 50000.00
	Budget float64 `json:"budget" example:"50000.00"`

	// Project progress percentage
	// @example 65.5
	Progress float64 `gorm:"default:0" json:"progress" example:"65.5"`

	// Project settings as JSON
	// @example {"timezone":"UTC","working_hours":{"start":"09:00","end":"17:00"}}
	Settings string `gorm:"type:json" json:"settings" example:"{\"timezone\":\"UTC\",\"working_hours\":{\"start\":\"09:00\",\"end\":\"17:00\"}}"`

	// Relationships
	// @Description Organization this project belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Project manager
	ProjectManager *User `gorm:"foreignKey:ProjectManagerID" json:"project_manager,omitempty"`

	// @Description Teams working on this project
	Teams []Team `gorm:"many2many:team_projects;" json:"teams,omitempty"`

	// @Description Users assigned to this project
	Users []User `gorm:"many2many:user_projects;" json:"users,omitempty"`

	// @Description Project tasks
	Tasks []Task `gorm:"foreignKey:ProjectID" json:"tasks,omitempty"`

	// @Description Project task boards
	TaskBoards []TaskBoard `gorm:"foreignKey:ProjectID" json:"task_boards,omitempty"`

	// @Description Project milestones
	Milestones []Milestone `gorm:"foreignKey:ProjectID" json:"milestones,omitempty"`

	// @Description Project task labels
	TaskLabels []TaskLabel `gorm:"foreignKey:ProjectID" json:"task_labels,omitempty"`

	// @Description Project views
	Views []ProjectView `gorm:"foreignKey:ProjectID" json:"views,omitempty"`

	// @Description Project custom fields
	CustomFields []ProjectCustomField `gorm:"foreignKey:ProjectID" json:"custom_fields,omitempty"`

	// @Description Project workflows
	Workflows []ProjectWorkflow `gorm:"foreignKey:ProjectID" json:"workflows,omitempty"`

	// @Description Project insights and analytics
	Insights []ProjectInsight `gorm:"foreignKey:ProjectID" json:"insights,omitempty"`
}

// ProjectView represents different views of a project (table, board, roadmap, timeline)
// @Description Project view model for different project perspectives
type ProjectView struct {
	BaseModel

	// View name
	// @example Sprint Board
	Name string `gorm:"not null" json:"name" example:"Sprint Board"`

	// View description
	// @example Current sprint tasks and progress
	Description string `json:"description" example:"Current sprint tasks and progress"`

	// View type (table, board, roadmap, timeline)
	// @example board
	Type string `gorm:"not null" json:"type" example:"board"`

	// View layout settings as JSON
	// @example {"columns":["todo","in_progress","done"],"groupBy":"status","sortBy":"priority"}
	Layout string `gorm:"type:json" json:"layout" example:"{\"columns\":[\"todo\",\"in_progress\",\"done\"],\"groupBy\":\"status\",\"sortBy\":\"priority\"}"`

	// View filters as JSON
	// @example {"assignee":["user1","user2"],"priority":["high","medium"]}
	Filters string `gorm:"type:json" json:"filters" example:"{\"assignee\":[\"user1\",\"user2\"],\"priority\":[\"high\",\"medium\"]}"`

	// View sorting configuration as JSON
	// @example {"field":"created_at","direction":"desc"}
	Sorting string `gorm:"type:json" json:"sorting" example:"{\"field\":\"created_at\",\"direction\":\"desc\"}"`

	// View grouping configuration as JSON
	// @example {"field":"status","showCount":true}
	Grouping string `gorm:"type:json" json:"grouping" example:"{\"field\":\"status\",\"showCount\":true}"`

	// Whether the view is default for the project
	// @example true
	IsDefault bool `gorm:"default:false" json:"is_default" example:"true"`

	// Whether the view is public
	// @example true
	IsPublic bool `gorm:"default:true" json:"is_public" example:"true"`

	// View position/order
	// @example 1
	Position int `gorm:"default:0" json:"position" example:"1"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Project this view belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`
}

// ProjectCustomField represents custom fields for projects
// @Description Project custom field model for flexible metadata
type ProjectCustomField struct {
	BaseModel

	// Field name
	// @example Priority
	Name string `gorm:"not null" json:"name" example:"Priority"`

	// Field description
	// @example Task priority level
	Description string `json:"description" example:"Task priority level"`

	// Field type (text, number, date, select, multi_select, checkbox, url, email)
	// @example select
	Type string `gorm:"not null" json:"type" example:"select"`

	// Field options as JSON (for select/multi_select fields)
	// @example {"options":["Low","Medium","High","Critical"],"colors":{"Low":"#10B981","Medium":"#F59E0B","High":"#EF4444","Critical":"#7C3AED"}}
	Options string `gorm:"type:json" json:"options" example:"{\"options\":[\"Low\",\"Medium\",\"High\",\"Critical\"],\"colors\":{\"Low\":\"#10B981\",\"Medium\":\"#F59E0B\",\"High\":\"#EF4444\",\"Critical\":\"#7C3AED\"}}"`

	// Whether the field is required
	// @example false
	IsRequired bool `gorm:"default:false" json:"is_required" example:"false"`

	// Field position/order
	// @example 1
	Position int `gorm:"default:0" json:"position" example:"1"`

	// Whether the field is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Project this field belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	// @Description Task field values
	TaskFieldValues []TaskFieldValue `gorm:"foreignKey:FieldID" json:"task_field_values,omitempty"`
}

// ProjectWorkflow represents automated workflows for projects
// @Description Project workflow model for automation
type ProjectWorkflow struct {
	BaseModel

	// Workflow name
	// @example Auto-assign to Sprint
	Name string `gorm:"not null" json:"name" example:"Auto-assign to Sprint"`

	// Workflow description
	// @example Automatically assign new tasks to current sprint
	Description string `json:"description" example:"Automatically assign new tasks to current sprint"`

	// Workflow trigger (item_added, item_updated, field_changed, status_changed)
	// @example item_added
	Trigger string `gorm:"not null" json:"trigger" example:"item_added"`

	// Workflow conditions as JSON
	// @example {"field":"type","operator":"equals","value":"task"}
	Conditions string `gorm:"type:json" json:"conditions" example:"{\"field\":\"type\",\"operator\":\"equals\",\"value\":\"task\"}"`

	// Workflow actions as JSON
	// @example {"action":"set_field","field":"status","value":"todo"}
	Actions string `gorm:"type:json" json:"actions" example:"{\"action\":\"set_field\",\"field\":\"status\",\"value\":\"todo\"}"`

	// Whether the workflow is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Workflow position/order
	// @example 1
	Position int `gorm:"default:0" json:"position" example:"1"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Project this workflow belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`
}

// ProjectTemplate represents reusable project templates
// @Description Project template model for quick project setup
type ProjectTemplate struct {
	BaseModel

	// Template name
	// @example Software Development Template
	Name string `gorm:"not null" json:"name" example:"Software Development Template"`

	// Template description
	// @example Template for software development projects with standard workflow
	Description string `json:"description" example:"Template for software development projects with standard workflow"`

	// Template category (development, marketing, design, general)
	// @example development
	Category string `gorm:"default:'general'" json:"category" example:"development"`

	// Template icon
	// @example code
	Icon string `json:"icon" example:"code"`

	// Template color
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Whether the template is public
	// @example true
	IsPublic bool `gorm:"default:false" json:"is_public" example:"true"`

	// Whether the template is featured
	// @example false
	IsFeatured bool `gorm:"default:false" json:"is_featured" example:"false"`

	// Template configuration as JSON
	// @example {"default_views":[{"name":"Board","type":"board"}],"custom_fields":[{"name":"Priority","type":"select"}]}
	Configuration string `gorm:"type:json" json:"configuration" example:"{\"default_views\":[{\"name\":\"Board\",\"type\":\"board\"}],\"custom_fields\":[{\"name\":\"Priority\",\"type\":\"select\"}]}"`

	// Organization ID (null for system templates)
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID *string `gorm:"index;type:char(26)" json:"organization_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Usage count
	// @example 42
	UsageCount int `gorm:"default:0" json:"usage_count" example:"42"`

	// Relationships
	// @Description Organization this template belongs to (null for system templates)
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}

// ProjectInsight represents project analytics and insights
// @Description Project insight model for analytics
type ProjectInsight struct {
	BaseModel

	// Insight type (velocity, burndown, completion_rate, task_distribution)
	// @example velocity
	Type string `gorm:"not null" json:"type" example:"velocity"`

	// Insight period (daily, weekly, monthly, quarterly)
	// @example weekly
	Period string `gorm:"not null" json:"period" example:"weekly"`

	// Insight date
	// @example 2024-01-15T00:00:00Z
	Date time.Time `gorm:"not null" json:"date" example:"2024-01-15T00:00:00Z"`

	// Insight data as JSON
	// @example {"completed_tasks":15,"total_tasks":20,"velocity":3.5}
	Data string `gorm:"type:json" json:"data" example:"{\"completed_tasks\":15,\"total_tasks\":20,\"velocity\":3.5}"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Project this insight belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`
}

// UserOrganization represents the pivot table for user-organization relationship
// @Description User-organization relationship with role and status
type UserOrganization struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `gorm:"primaryKey;type:char(26)" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in organization (owner, admin, member, guest)
	// @example member
	Role string `gorm:"default:'member'" json:"role" example:"member"`

	// User status in organization (active, inactive, suspended)
	// @example active
	Status string `gorm:"default:'active'" json:"status" example:"active"`

	// Whether the user is active in this organization
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the user joined this organization
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// When the user's membership expires
	// @example 2025-01-15T10:30:00Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2025-01-15T10:30:00Z"`

	// User's title/position in organization
	// @example Senior Software Engineer
	Title string `json:"title" example:"Senior Software Engineer"`

	// User's employee ID
	// @example EMP001
	EmployeeID string `json:"employee_id" example:"EMP001"`

	// User's department ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID *string `gorm:"index;type:char(26)" json:"department_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's team ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID *string `gorm:"index;type:char(26)" json:"team_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's manager ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ManagerID *string `gorm:"index;type:char(26)" json:"manager_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User's hire date
	// @example 2024-01-15T00:00:00Z
	HireDate *time.Time `json:"hire_date,omitempty" example:"2024-01-15T00:00:00Z"`

	// User's termination date
	// @example 2024-12-31T00:00:00Z
	TerminationDate *time.Time `json:"termination_date,omitempty" example:"2024-12-31T00:00:00Z"`

	// User's salary information (encrypted)
	// @example encrypted_salary_data
	Salary string `json:"salary" example:"encrypted_salary_data"`

	// User's permissions as JSON
	// @example ["read:projects","write:reports"]
	Permissions string `gorm:"type:json" json:"permissions" example:"[\"read:projects\",\"write:reports\"]"`

	// Relationships
	User         User         `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Organization Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
	Department   *Department  `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`
	Team         *Team        `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	Manager      *User        `gorm:"foreignKey:ManagerID" json:"manager,omitempty"`
}

// UserDepartment represents the pivot table for user-department relationship
// @Description User-department relationship
type UserDepartment struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Department ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	DepartmentID string `gorm:"primaryKey;type:char(26)" json:"department_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in department (manager, member, lead)
	// @example member
	Role string `gorm:"default:'member'" json:"role" example:"member"`

	// Whether the user is active in this department
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the user joined this department
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	User       User       `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Department Department `gorm:"foreignKey:DepartmentID" json:"department,omitempty"`
}

// UserTeam represents the pivot table for user-team relationship
// @Description User-team relationship
type UserTeam struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID string `gorm:"primaryKey;type:char(26)" json:"team_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in team (lead, member, contributor)
	// @example member
	Role string `gorm:"default:'member'" json:"role" example:"member"`

	// Whether the user is active in this team
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the user joined this team
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Team Team `gorm:"foreignKey:TeamID" json:"team,omitempty"`
}

// UserProject represents the pivot table for user-project relationship
// @Description User-project relationship
type UserProject struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"primaryKey;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User role in project (manager, member, contributor, reviewer)
	// @example member
	Role string `gorm:"default:'member'" json:"role" example:"member"`

	// Whether the user is active in this project
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the user joined this project
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// User's allocation percentage to this project
	// @example 100.0
	Allocation float64 `gorm:"default:100" json:"allocation" example:"100.0"`

	// Relationships
	User    User    `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Project Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`
}

// TeamProject represents the pivot table for team-project relationship
// @Description Team-project relationship
type TeamProject struct {
	// Team ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TeamID string `gorm:"primaryKey;type:char(26)" json:"team_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"primaryKey;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Team role in project (lead, contributor, reviewer)
	// @example contributor
	Role string `gorm:"default:'contributor'" json:"role" example:"contributor"`

	// Whether the team is active in this project
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the team joined this project
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// Team's allocation percentage to this project
	// @example 100.0
	Allocation float64 `gorm:"default:100" json:"allocation" example:"100.0"`

	// Relationships
	Team    Team    `gorm:"foreignKey:TeamID" json:"team,omitempty"`
	Project Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`
}
