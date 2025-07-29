package requests

import "time"

// ModernProjectRequest represents the request data for creating a project (GitHub Projects v2 style)
type ModernProjectRequest struct {
	// Project name
	// @example Customer Portal Redesign
	Name string `json:"name" validate:"required,min=2,max=255" example:"Customer Portal Redesign"`

	// Project description
	// @example Redesign and modernize the customer portal
	Description string `json:"description" validate:"omitempty,max=1000" example:"Redesign and modernize the customer portal"`

	// Project README content (markdown supported)
	// @example # Project Overview\n\nThis project aims to redesign the customer portal...
	Readme string `json:"readme" validate:"omitempty,max=10000" example:"# Project Overview\\n\\nThis project aims to redesign the customer portal..."`

	// Project status (planning, active, on-hold, completed, cancelled)
	// @example active
	Status string `json:"status" validate:"omitempty,oneof=planning active on-hold completed cancelled" example:"active"`

	// Project state (open, closed) - GitHub Projects style
	// @example open
	State string `json:"state" validate:"omitempty,oneof=open closed" example:"open"`

	// Project priority (low, medium, high, critical)
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// Project visibility (private, public)
	// @example private
	Visibility string `json:"visibility" validate:"omitempty,oneof=private public" example:"private"`

	// Project owner ID (GitHub Projects style)
	// @example 01HXYZ123456789ABCDEFGHIJK
	OwnerID *string `json:"owner_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project template ID (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	TemplateID *string `json:"template_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project color for UI
	// @example #F59E0B
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#F59E0B"`

	// Project icon
	// @example project
	Icon string `json:"icon" validate:"omitempty,max=50" example:"project"`
}

// ModernProjectUpdateRequest represents the request data for updating a project
type ModernProjectUpdateRequest struct {
	// Project name
	// @example Customer Portal Redesign v2
	Name string `json:"name" validate:"omitempty,min=2,max=255" example:"Customer Portal Redesign v2"`

	// Project description
	// @example Updated project description
	Description string `json:"description" validate:"omitempty,max=1000" example:"Updated project description"`

	// Project README content (markdown supported)
	// @example # Updated Project Overview\n\nThis is the updated project description...
	Readme string `json:"readme" validate:"omitempty,max=10000" example:"# Updated Project Overview\\n\\nThis is the updated project description..."`

	// Project status (planning, active, on-hold, completed, cancelled)
	// @example completed
	Status string `json:"status" validate:"omitempty,oneof=planning active on-hold completed cancelled" example:"completed"`

	// Project state (open, closed) - GitHub Projects style
	// @example closed
	State string `json:"state" validate:"omitempty,oneof=open closed" example:"closed"`

	// Project priority (low, medium, high, critical)
	// @example critical
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"critical"`

	// Project visibility (private, public)
	// @example public
	Visibility string `json:"visibility" validate:"omitempty,oneof=private public" example:"public"`

	// Project owner ID (GitHub Projects style)
	// @example 01HXYZ123456789ABCDEFGHIJK
	OwnerID *string `json:"owner_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Project color for UI
	// @example #3B82F6
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#3B82F6"`

	// Project icon
	// @example project
	Icon string `json:"icon" validate:"omitempty,max=50" example:"project"`
}

// ProjectItemRequest represents the request data for adding items to a project
type ProjectItemRequest struct {
	// Content type (issue, pull_request, draft_issue)
	// @example issue
	ContentType string `json:"content_type" validate:"required,oneof=issue pull_request draft_issue" example:"issue"`

	// Content ID (for existing issues/PRs)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ContentID *string `json:"content_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Title (for draft issues)
	// @example New feature request
	Title string `json:"title" validate:"omitempty,min=1,max=255" example:"New feature request"`

	// Body (for draft issues)
	// @example Detailed description of the feature
	Body string `json:"body" validate:"omitempty,max=5000" example:"Detailed description of the feature"`
}

// ProjectItemUpdateRequest represents the request data for updating project items
type ProjectItemUpdateRequest struct {
	// Item status
	// @example in_progress
	Status string `json:"status" validate:"omitempty" example:"in_progress"`

	// Item priority
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// Custom field values (JSON)
	// @example {"sprint":"Sprint 1","estimate":5}
	FieldValues map[string]interface{} `json:"field_values" validate:"omitempty" example:"{\"sprint\":\"Sprint 1\",\"estimate\":5}"`

	// Assignee IDs
	// @example ["01HXYZ123456789ABCDEFGHIJK"]
	AssigneeIDs []string `json:"assignee_ids" validate:"omitempty,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\"]"`
}

// ProjectFieldRequest represents the request data for creating custom fields
type ProjectFieldRequest struct {
	// Field name
	// @example Priority
	Name string `json:"name" validate:"required,min=1,max=100" example:"Priority"`

	// Field type (text, number, date, single_select, multi_select, checkbox, url, email)
	// @example single_select
	DataType string `json:"data_type" validate:"required,oneof=text number date single_select multi_select checkbox url email" example:"single_select"`

	// Field description
	// @example Task priority level
	Description string `json:"description" validate:"omitempty,max=500" example:"Task priority level"`

	// Field options (for select fields)
	// @example [{"name":"High","color":"red"},{"name":"Medium","color":"yellow"},{"name":"Low","color":"green"}]
	Options []ProjectFieldOption `json:"options" validate:"omitempty" example:"[{\"name\":\"High\",\"color\":\"red\"},{\"name\":\"Medium\",\"color\":\"yellow\"},{\"name\":\"Low\",\"color\":\"green\"}]"`
}

// ProjectFieldOption represents an option for select fields
type ProjectFieldOption struct {
	// Option name
	// @example High
	Name string `json:"name" validate:"required,min=1,max=100" example:"High"`

	// Option color
	// @example red
	Color string `json:"color" validate:"omitempty,hexcolor|oneof=red yellow green blue purple pink gray" example:"red"`

	// Option description
	// @example High priority tasks
	Description string `json:"description" validate:"omitempty,max=200" example:"High priority tasks"`
}

// ProjectViewRequest represents the request data for creating project views
type ProjectViewRequest struct {
	// View name
	// @example Sprint Board
	Name string `json:"name" validate:"required,min=1,max=100" example:"Sprint Board"`

	// View layout (table, board, roadmap, timeline)
	// @example board
	Layout string `json:"layout" validate:"required,oneof=table board roadmap timeline" example:"board"`

	// View description
	// @example Kanban board for current sprint
	Description string `json:"description" validate:"omitempty,max=500" example:"Kanban board for current sprint"`

	// View configuration (JSON)
	// @example {"group_by":"status","sort_by":"created_at","filters":{"status":["todo","in_progress"]}}
	Configuration map[string]interface{} `json:"configuration" validate:"omitempty" example:"{\"group_by\":\"status\",\"sort_by\":\"created_at\",\"filters\":{\"status\":[\"todo\",\"in_progress\"]}}"`

	// Whether this is the default view
	// @example false
	IsDefault bool `json:"is_default" validate:"omitempty" example:"false"`
}

// ProjectWorkflowRequest represents the request data for creating project workflows
type ProjectWorkflowRequest struct {
	// Workflow name
	// @example Auto-assign to backlog
	Name string `json:"name" validate:"required,min=1,max=100" example:"Auto-assign to backlog"`

	// Workflow description
	// @example Automatically assign new issues to backlog
	Description string `json:"description" validate:"omitempty,max=500" example:"Automatically assign new issues to backlog"`

	// Workflow trigger (item_added, item_updated, item_closed, item_reopened)
	// @example item_added
	Trigger string `json:"trigger" validate:"required,oneof=item_added item_updated item_closed item_reopened" example:"item_added"`

	// Workflow conditions (JSON)
	// @example {"content_type":"issue","labels":["bug"]}
	Conditions map[string]interface{} `json:"conditions" validate:"omitempty" example:"{\"content_type\":\"issue\",\"labels\":[\"bug\"]}"`

	// Workflow actions (JSON)
	// @example {"set_field":{"status":"todo"},"assign_to":"01HXYZ123456789ABCDEFGHIJK"}
	Actions map[string]interface{} `json:"actions" validate:"required" example:"{\"set_field\":{\"status\":\"todo\"},\"assign_to\":\"01HXYZ123456789ABCDEFGHIJK\"}"`

	// Whether the workflow is enabled
	// @example true
	IsEnabled bool `json:"is_enabled" validate:"omitempty" example:"true"`
}

// ProjectTemplateRequest represents the request data for creating project templates
type ProjectTemplateRequest struct {
	// Template name
	// @example Software Development Template
	Name string `json:"name" validate:"required,min=2,max=255" example:"Software Development Template"`

	// Template description
	// @example Template for software development projects with standard workflow
	Description string `json:"description" validate:"omitempty,max=1000" example:"Template for software development projects with standard workflow"`

	// Template category (development, marketing, design, general)
	// @example development
	Category string `json:"category" validate:"required,oneof=development marketing design general" example:"development"`

	// Template icon
	// @example code
	Icon string `json:"icon" validate:"omitempty,max=50" example:"code"`

	// Template color
	// @example #3B82F6
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#3B82F6"`

	// Whether the template is public
	// @example true
	IsPublic bool `json:"is_public" validate:"omitempty" example:"true"`

	// Template configuration as JSON
	// @example {"default_views":[{"name":"Board","type":"board"}],"custom_fields":[{"name":"Priority","type":"select"}]}
	Configuration map[string]interface{} `json:"configuration" validate:"omitempty" example:"{\"default_views\":[{\"name\":\"Board\",\"type\":\"board\"}],\"custom_fields\":[{\"name\":\"Priority\",\"type\":\"select\"}]}"`

	// Organization ID (null for system templates)
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID *string `json:"organization_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// UseTemplateRequest represents the request data for creating a project from a template
type UseTemplateRequest struct {
	// Project name
	// @example My New Project
	Name string `json:"name" validate:"required,min=2,max=255" example:"My New Project"`

	// Project description
	// @example Project created from template
	Description string `json:"description" validate:"omitempty,max=1000" example:"Project created from template"`

	// Organization ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID string `json:"organization_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// BulkUpdateItemsRequest represents the request data for bulk updating project items
type BulkUpdateItemsRequest struct {
	// Item IDs to update
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ987654321ZYXWVUTSRQP"]
	ItemIDs []string `json:"item_ids" validate:"required,min=1,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ987654321ZYXWVUTSRQP\"]"`

	// New status (optional)
	// @example in_progress
	Status string `json:"status" validate:"omitempty" example:"in_progress"`

	// New priority (optional)
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// New assignee ID (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	AssigneeID *string `json:"assignee_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// BulkItemsRequest represents the request data for bulk operations on project items
type BulkItemsRequest struct {
	// Item IDs to operate on
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ987654321ZYXWVUTSRQP"]
	ItemIDs []string `json:"item_ids" validate:"required,min=1,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ987654321ZYXWVUTSRQP\"]"`
}

// ProjectPermissionRequest represents the request data for project permissions
type ProjectPermissionRequest struct {
	// User ID to grant permission to
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `json:"user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission role (owner, admin, write, read)
	// @example write
	Role string `json:"role" validate:"required,oneof=owner admin write read" example:"write"`

	// Permission type (project, view, field, item)
	// @example project
	PermissionType string `json:"permission_type" validate:"omitempty,oneof=project view field item" example:"project"`

	// Can read project and items
	// @example true
	CanRead bool `json:"can_read" example:"true"`

	// Can write/edit project and items
	// @example true
	CanWrite bool `json:"can_write" example:"true"`

	// Can administer project settings
	// @example false
	CanAdmin bool `json:"can_admin" example:"false"`

	// Permission expiration date (optional)
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at" validate:"omitempty" example:"2024-12-31T23:59:59Z"`
}

// BulkPermissionRequest represents the request data for bulk permission operations
type BulkPermissionRequest struct {
	// User IDs to grant permissions to
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ987654321ZYXWVUTSRQP"]
	UserIDs []string `json:"user_ids" validate:"required,min=1,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ987654321ZYXWVUTSRQP\"]"`

	// Permission role (owner, admin, write, read)
	// @example read
	Role string `json:"role" validate:"required,oneof=owner admin write read" example:"read"`

	// Permission type (project, view, field, item)
	// @example project
	PermissionType string `json:"permission_type" validate:"omitempty,oneof=project view field item" example:"project"`

	// Can read project and items
	// @example true
	CanRead bool `json:"can_read" example:"true"`

	// Can write/edit project and items
	// @example false
	CanWrite bool `json:"can_write" example:"false"`

	// Can administer project settings
	// @example false
	CanAdmin bool `json:"can_admin" example:"false"`
}

// DraftIssueRequest represents the request data for creating draft issues
type DraftIssueRequest struct {
	// Draft issue title
	// @example Quick task idea
	Title string `json:"title" validate:"required,min=1,max=255" example:"Quick task idea"`

	// Draft issue description (optional)
	// @example This is a quick idea that needs more details later
	Description string `json:"description" validate:"omitempty,max=2000" example:"This is a quick idea that needs more details later"`

	// Draft priority (optional)
	// @example medium
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"medium"`

	// Assignee ID (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	AssigneeID *string `json:"assignee_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`
}

// ProjectActivityRequest represents the request data for creating project activities
type ProjectActivityRequest struct {
	// Activity action/log name
	// @example item_created
	Action string `json:"action" validate:"required,min=1,max=100" example:"item_created"`

	// Activity description
	// @example Created new task item
	Description string `json:"description" validate:"required,min=1,max=500" example:"Created new task item"`

	// Activity category
	// @example data_modify
	Category string `json:"category" validate:"omitempty,oneof=authentication authorization data_access data_modify security system user admin compliance performance" example:"data_modify"`

	// Activity severity
	// @example info
	Severity string `json:"severity" validate:"omitempty,oneof=info low medium high critical" example:"info"`

	// Additional metadata as JSON
	// @example {"item_id": "01HXYZ123456789ABCDEFGHIJK", "field": "title"}
	Metadata map[string]interface{} `json:"metadata" example:"{\"item_id\": \"01HXYZ123456789ABCDEFGHIJK\", \"field\": \"title\"}"`
}

// ProjectMentionRequest represents the request data for creating project mentions
type ProjectMentionRequest struct {
	// User ID being mentioned
	// @example 01HXYZ123456789ABCDEFGHIJK
	MentionedUserID string `json:"mentioned_user_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Context of the mention (task, comment, etc.)
	// @example task_comment
	Context string `json:"context" validate:"required,oneof=task_comment task_description project_comment view_comment" example:"task_comment"`

	// Item ID where the mention occurred (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ItemID *string `json:"item_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Comment or message containing the mention
	// @example Hey @username, can you review this task?
	Comment string `json:"comment" validate:"required,min=1,max=1000" example:"Hey @username, can you review this task?"`

	// Description for the activity log
	// @example User mentioned in task comment
	Description string `json:"description" validate:"required,min=1,max=500" example:"User mentioned in task comment"`
}

// ProjectLabelRequest represents the request data for project labels
type ProjectLabelRequest struct {
	// Label name
	// @example Bug
	Name string `json:"name" validate:"required,min=1,max=100" example:"Bug"`

	// Label color (hex code)
	// @example #ff0000
	Color string `json:"color" validate:"required,hexcolor" example:"#ff0000"`

	// Label description (optional)
	// @example Issues that need immediate attention
	Description string `json:"description" validate:"omitempty,max=500" example:"Issues that need immediate attention"`
}

// ProjectMilestoneRequest represents the request data for project milestones
type ProjectMilestoneRequest struct {
	// Milestone title
	// @example Version 1.0 Release
	Title string `json:"title" validate:"required,min=1,max=255" example:"Version 1.0 Release"`

	// Milestone description (optional)
	// @example Complete all features for the first major release
	Description string `json:"description" validate:"omitempty,max=1000" example:"Complete all features for the first major release"`

	// Due date (optional)
	// @example 2024-12-31T23:59:59Z
	DueDate *time.Time `json:"due_date" validate:"omitempty" example:"2024-12-31T23:59:59Z"`

	// Start date (optional)
	// @example 2024-01-01T00:00:00Z
	StartDate *time.Time `json:"start_date" validate:"omitempty" example:"2024-01-01T00:00:00Z"`
}

// ProjectDuplicateRequest represents the request data for duplicating a project
type ProjectDuplicateRequest struct {
	// New project name
	// @example Customer Portal Redesign - Copy
	Name string `json:"name" validate:"required,min=2,max=255" example:"Customer Portal Redesign - Copy"`

	// Include views in duplication
	// @example true
	IncludeViews bool `json:"include_views" example:"true"`

	// Include custom fields in duplication
	// @example true
	IncludeCustomFields bool `json:"include_custom_fields" example:"true"`

	// Include tasks in duplication
	// @example false
	IncludeTasks bool `json:"include_tasks" example:"false"`

	// Include draft issues in duplication
	// @example false
	IncludeDrafts bool `json:"include_drafts" example:"false"`
}

// ProjectDraftRequest represents the request data for creating a draft issue
type ProjectDraftRequest struct {
	// Draft issue title
	// @example Investigate performance issue
	Title string `json:"title" validate:"required,min=2,max=255" example:"Investigate performance issue"`

	// Draft issue description
	// @example Need to look into slow loading times on the dashboard
	Description string `json:"description,omitempty" validate:"omitempty,max=2000" example:"Need to look into slow loading times on the dashboard"`
}

// ProjectDraftUpdateRequest represents the request data for updating a draft issue
type ProjectDraftUpdateRequest struct {
	// Draft issue title
	// @example Investigate performance issue - Updated
	Title string `json:"title,omitempty" validate:"omitempty,min=2,max=255" example:"Investigate performance issue - Updated"`

	// Draft issue description
	// @example Need to look into slow loading times on the dashboard and user complaints
	Description string `json:"description,omitempty" validate:"omitempty,max=2000" example:"Need to look into slow loading times on the dashboard and user complaints"`
}

// ProjectBulkConvertDraftsRequest represents the request data for bulk converting drafts to issues
type ProjectBulkConvertDraftsRequest struct {
	// Array of draft IDs to convert
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ123456789ABCDEFGHI2"]
	DraftIDs []string `json:"draft_ids" validate:"required,min=1,dive,len=26" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ123456789ABCDEFGHI2\"]"`
}

// ProjectInviteRequest represents the request data for inviting a user to a project
type ProjectInviteRequest struct {
	// Email of the user to invite
	// @example john.doe@example.com
	Email string `json:"email" validate:"required,email" example:"john.doe@example.com"`

	// Role to assign to the invited user
	// @example write
	Role string `json:"role" validate:"required,oneof=admin write read member maintainer" example:"write"`

	// Optional invitation message
	// @example Please join our project to help with the customer portal redesign
	Message string `json:"message,omitempty" validate:"omitempty,max=500" example:"Please join our project to help with the customer portal redesign"`
}

// ProjectRoleUpdateRequest represents the request data for updating a member's role
type ProjectRoleUpdateRequest struct {
	// New role for the member
	// @example admin
	Role string `json:"role" validate:"required,oneof=admin write read member maintainer owner" example:"admin"`

	// Reason for the role change (optional)
	// @example Promoted to project lead
	Reason string `json:"reason,omitempty" validate:"omitempty,max=500" example:"Promoted to project lead"`
}

// ProjectWebhookRequest represents the request data for creating a project webhook
type ProjectWebhookRequest struct {
	// Webhook name
	// @example Slack Integration
	Name string `json:"name" validate:"required,min=2,max=255" example:"Slack Integration"`

	// Webhook URL
	// @example https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
	URL string `json:"url" validate:"required,url" example:"https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"`

	// Events that trigger this webhook
	// @example ["project.created","project.updated","item.created","item.updated","item.deleted"]
	Events []string `json:"events" validate:"required,min=1,dive,oneof=project.created project.updated project.deleted project.archived project.unarchived item.created item.updated item.deleted member.added member.removed member.role_updated draft.created draft.updated draft.deleted draft.converted activity.created" example:"[\"project.created\",\"project.updated\",\"item.created\",\"item.updated\",\"item.deleted\"]"`

	// Content type for webhook payload
	// @example application/json
	ContentType string `json:"content_type,omitempty" validate:"omitempty,oneof=application/json application/x-www-form-urlencoded" example:"application/json"`

	// Whether the webhook is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Webhook description
	// @example Sends project updates to Slack channel
	Description string `json:"description,omitempty" validate:"omitempty,max=500" example:"Sends project updates to Slack channel"`
}

// ProjectWebhookUpdateRequest represents the request data for updating a project webhook
type ProjectWebhookUpdateRequest struct {
	// Webhook name
	// @example Slack Integration - Updated
	Name string `json:"name,omitempty" validate:"omitempty,min=2,max=255" example:"Slack Integration - Updated"`

	// Webhook URL
	// @example https://hooks.slack.com/services/T00000000/B00000000/YYYYYYYYYYYYYYYYYYYYYYYY
	URL string `json:"url,omitempty" validate:"omitempty,url" example:"https://hooks.slack.com/services/T00000000/B00000000/YYYYYYYYYYYYYYYYYYYYYYYY"`

	// Events that trigger this webhook
	// @example ["project.created","project.updated","item.created","item.updated"]
	Events []string `json:"events,omitempty" validate:"omitempty,min=1,dive,oneof=project.created project.updated project.deleted project.archived project.unarchived item.created item.updated item.deleted member.added member.removed member.role_updated draft.created draft.updated draft.deleted draft.converted activity.created" example:"[\"project.created\",\"project.updated\",\"item.created\",\"item.updated\"]"`

	// Content type for webhook payload
	// @example application/json
	ContentType string `json:"content_type,omitempty" validate:"omitempty,oneof=application/json application/x-www-form-urlencoded" example:"application/json"`

	// Whether the webhook is active
	// @example false
	IsActive *bool `json:"is_active,omitempty" example:"false"`

	// Webhook description
	// @example Updated Slack integration for project updates
	Description *string `json:"description,omitempty" validate:"omitempty,max=500" example:"Updated Slack integration for project updates"`

	// Whether to regenerate the webhook secret
	// @example true
	RegenerateSecret bool `json:"regenerate_secret,omitempty" example:"true"`
}

// ProjectStatusRequest represents the request data for project statuses
type ProjectStatusRequest struct {
	// Status name
	// @example In Review
	Name string `json:"name" validate:"required,min=1,max=100" example:"In Review"`

	// Status description
	// @example Items currently under review
	Description string `json:"description" validate:"omitempty,max=500" example:"Items currently under review"`

	// Status color (hex code)
	// @example #F59E0B
	Color string `json:"color" validate:"required,hexcolor" example:"#F59E0B"`

	// Status icon
	// @example eye
	Icon string `json:"icon" validate:"omitempty,max=50" example:"eye"`

	// Status type (todo, in_progress, done, custom)
	// @example custom
	Type string `json:"type" validate:"required,oneof=todo in_progress done custom" example:"custom"`

	// Status position/order
	// @example 3
	Position int `json:"position" validate:"omitempty,min=0" example:"3"`

	// Whether this is a default status
	// @example false
	IsDefault bool `json:"is_default" validate:"omitempty" example:"false"`
}

// ProjectIterationRequest represents the request data for project iterations
type ProjectIterationRequest struct {
	// Iteration title
	// @example Sprint 1
	Title string `json:"title" validate:"required,min=1,max=200" example:"Sprint 1"`

	// Iteration description
	// @example First sprint of Q1 2024
	Description string `json:"description" validate:"omitempty,max=1000" example:"First sprint of Q1 2024"`

	// Iteration start date
	// @example 2024-01-15T00:00:00Z
	StartDate *time.Time `json:"start_date" validate:"omitempty" example:"2024-01-15T00:00:00Z"`

	// Iteration end date
	// @example 2024-01-29T00:00:00Z
	EndDate *time.Time `json:"end_date" validate:"omitempty" example:"2024-01-29T00:00:00Z"`

	// Iteration duration in days
	// @example 14
	Duration int `json:"duration" validate:"omitempty,min=1,max=365" example:"14"`

	// Whether the iteration is current
	// @example true
	IsCurrent bool `json:"is_current" validate:"omitempty" example:"true"`
}

// ProjectAutomationRequest represents the request data for project automations
type ProjectAutomationRequest struct {
	// Automation name
	// @example Auto-assign to current iteration
	Name string `json:"name" validate:"required,min=1,max=200" example:"Auto-assign to current iteration"`

	// Automation description
	// @example Automatically assign new issues to current iteration
	Description string `json:"description" validate:"omitempty,max=1000" example:"Automatically assign new issues to current iteration"`

	// Automation trigger event
	// @example item_added
	TriggerEvent string `json:"trigger_event" validate:"required,oneof=item_added item_updated item_closed item_reopened item_deleted" example:"item_added"`

	// Automation conditions
	// @example {"item_type":"issue","labels":["bug"]}
	Conditions map[string]interface{} `json:"conditions" validate:"omitempty" example:"{\"item_type\":\"issue\",\"labels\":[\"bug\"]}"`

	// Automation actions
	// @example {"set_iteration":"current","add_labels":["needs-triage"]}
	Actions map[string]interface{} `json:"actions" validate:"required" example:"{\"set_iteration\":\"current\",\"add_labels\":[\"needs-triage\"]}"`

	// Whether the automation is enabled
	// @example true
	IsEnabled bool `json:"is_enabled" validate:"omitempty" example:"true"`
}

// ProjectRoadmapItemRequest represents the request data for project roadmap items
type ProjectRoadmapItemRequest struct {
	// Roadmap item title
	// @example Q1 Feature Release
	Title string `json:"title" validate:"required,min=1,max=200" example:"Q1 Feature Release"`

	// Roadmap item description
	// @example Major feature release for Q1 2024
	Description string `json:"description" validate:"omitempty,max=1000" example:"Major feature release for Q1 2024"`

	// Item type (milestone, epic, feature, release)
	// @example milestone
	Type string `json:"type" validate:"required,oneof=milestone epic feature release" example:"milestone"`

	// Item status (planned, in_progress, completed, cancelled)
	// @example in_progress
	Status string `json:"status" validate:"omitempty,oneof=planned in_progress completed cancelled" example:"in_progress"`

	// Item start date
	// @example 2024-01-01T00:00:00Z
	StartDate *time.Time `json:"start_date" validate:"omitempty" example:"2024-01-01T00:00:00Z"`

	// Item target date
	// @example 2024-03-31T00:00:00Z
	TargetDate *time.Time `json:"target_date" validate:"omitempty" example:"2024-03-31T00:00:00Z"`

	// Item color for visualization
	// @example #10B981
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#10B981"`

	// Parent roadmap item ID (for hierarchical items)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentID *string `json:"parent_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Related task IDs
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ123456789ABCDEFGHIJK"]
	TaskIDs []string `json:"task_ids" validate:"omitempty,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ123456789ABCDEFGHIJK\"]"`
}
