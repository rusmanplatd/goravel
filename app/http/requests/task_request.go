package requests

import (
	"time"

	"github.com/goravel/framework/contracts/http"
)

// TaskRequest represents a request to create or update a task
// @Description Task request validation model
type TaskRequest struct {
	// Task title
	// @example Implement user authentication
	Title string `json:"title" validate:"required,min=2,max=255" example:"Implement user authentication"`

	// Task description
	// @example Add JWT-based authentication with refresh tokens
	Description string `json:"description" validate:"omitempty,max=5000" example:"Add JWT-based authentication with refresh tokens"`

	// Task status (todo, in_progress, done, cancelled)
	// @example in_progress
	Status string `json:"status" validate:"omitempty,oneof=todo in_progress done cancelled" example:"in_progress"`

	// Task priority (low, medium, high, critical)
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// Task type (task, bug, feature, story, epic)
	// @example feature
	Type string `json:"type" validate:"omitempty,oneof=task bug feature story epic" example:"feature"`

	// Task color for UI
	// @example #3B82F6
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#3B82F6"`

	// Task icon
	// @example feature
	Icon string `json:"icon" validate:"omitempty,max=50" example:"feature"`

	// Assignee user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AssigneeID *string `json:"assignee_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Reviewer user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ReviewerID *string `json:"reviewer_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Milestone ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MilestoneID *string `json:"milestone_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent task ID for subtasks
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentTaskID *string `json:"parent_task_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Task start date
	// @example 2024-01-15T00:00:00Z
	StartDate *time.Time `json:"start_date" validate:"omitempty" example:"2024-01-15T00:00:00Z"`

	// Task due date
	// @example 2024-01-31T00:00:00Z
	DueDate *time.Time `json:"due_date" validate:"omitempty" example:"2024-01-31T00:00:00Z"`

	// Task estimated hours
	// @example 8.0
	EstimatedHours float64 `json:"estimated_hours" validate:"omitempty,min=0" example:"8.0"`

	// Task progress percentage
	// @example 75.0
	Progress float64 `json:"progress" validate:"omitempty,min=0,max=100" example:"75.0"`

	// Task position in board view
	// @example 1
	Position int `json:"position" validate:"omitempty,min=0" example:"1"`

	// Task settings as JSON
	// @example {"auto_assign":true,"require_review":false}
	Settings string `json:"settings" validate:"omitempty,json" example:"{\"auto_assign\":true,\"require_review\":false}"`
}

// TaskLabelRequest represents a request to create or update a task label
// @Description Task label request validation model
type TaskLabelRequest struct {
	// Label name
	// @example Bug
	Name string `json:"name" validate:"required,min=1,max=100" example:"Bug"`

	// Label description
	// @example Issues that need to be fixed
	Description string `json:"description" validate:"omitempty,max=500" example:"Issues that need to be fixed"`

	// Label color
	// @example #EF4444
	Color string `json:"color" validate:"required,hexcolor" example:"#EF4444"`

	// Label icon
	// @example bug
	Icon string `json:"icon" validate:"omitempty,max=50" example:"bug"`
}

// MilestoneRequest represents a request to create or update a milestone
// @Description Milestone request validation model
type MilestoneRequest struct {
	// Milestone title
	// @example Version 2.0 Release
	Title string `json:"title" validate:"required,min=2,max=255" example:"Version 2.0 Release"`

	// Milestone description
	// @example Major feature release with new UI
	Description string `json:"description" validate:"omitempty,max=1000" example:"Major feature release with new UI"`

	// Milestone status (open, closed)
	// @example open
	Status string `json:"status" validate:"omitempty,oneof=open closed" example:"open"`

	// Milestone color
	// @example #10B981
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#10B981"`

	// Milestone icon
	// @example milestone
	Icon string `json:"icon" validate:"omitempty,max=50" example:"milestone"`

	// Milestone due date
	// @example 2024-03-31T00:00:00Z
	DueDate *time.Time `json:"due_date" validate:"omitempty" example:"2024-03-31T00:00:00Z"`

	// Milestone progress percentage
	// @example 75.0
	Progress float64 `json:"progress" validate:"omitempty,min=0,max=100" example:"75.0"`
}

// TaskBoardRequest represents a request to create or update a task board
// @Description Task board request validation model
type TaskBoardRequest struct {
	// Board name
	// @example Development Board
	Name string `json:"name" validate:"required,min=2,max=255" example:"Development Board"`

	// Board description
	// @example Main development workflow board
	Description string `json:"description" validate:"omitempty,max=1000" example:"Main development workflow board"`

	// Board type (kanban, table, list, timeline)
	// @example kanban
	Type string `json:"type" validate:"omitempty,oneof=kanban table list timeline" example:"kanban"`

	// Board color
	// @example #3B82F6
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#3B82F6"`

	// Board icon
	// @example board
	Icon string `json:"icon" validate:"omitempty,max=50" example:"board"`

	// Whether the board is default for the project
	// @example true
	IsDefault bool `json:"is_default" validate:"omitempty" example:"true"`

	// Board settings as JSON
	// @example {"columns":["todo","in_progress","done"],"filters":{"assignee":"all"}}
	Settings string `json:"settings" validate:"omitempty,json" example:"{\"columns\":[\"todo\",\"in_progress\",\"done\"],\"filters\":{\"assignee\":\"all\"}}"`
}

// TaskBoardColumnRequest represents a request to create or update a task board column
// @Description Task board column request validation model
type TaskBoardColumnRequest struct {
	// Column name
	// @example In Progress
	Name string `json:"name" validate:"required,min=1,max=100" example:"In Progress"`

	// Column description
	// @example Tasks currently being worked on
	Description string `json:"description" validate:"omitempty,max=500" example:"Tasks currently being worked on"`

	// Column color
	// @example #F59E0B
	Color string `json:"color" validate:"omitempty,hexcolor" example:"#F59E0B"`

	// Column position
	// @example 2
	Position int `json:"position" validate:"required,min=0" example:"2"`

	// Column status filter (if any)
	// @example in_progress
	StatusFilter string `json:"status_filter" validate:"omitempty,oneof=todo in_progress done cancelled" example:"in_progress"`

	// Column limit (max number of tasks)
	// @example 10
	TaskLimit int `json:"task_limit" validate:"omitempty,min=0" example:"10"`
}

// TaskCommentRequest represents a request to create a task comment
// @Description Task comment request validation model
type TaskCommentRequest struct {
	// Comment content
	// @example This looks good! Ready for review.
	Content string `json:"content" validate:"required,min=1,max=10000" example:"This looks good! Ready for review."`

	// Parent comment ID for replies
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentCommentID *string `json:"parent_comment_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether the comment is internal (not visible to external users)
	// @example false
	IsInternal bool `json:"is_internal" validate:"omitempty" example:"false"`

	// Comment type (comment, review, system)
	// @example comment
	Type string `json:"type" validate:"omitempty,oneof=comment review system" example:"comment"`
}

// TaskTimeEntryRequest represents a request to create a task time entry
// @Description Task time entry request validation model
type TaskTimeEntryRequest struct {
	// Time entry description
	// @example Implemented user authentication
	Description string `json:"description" validate:"required,min=1,max=500" example:"Implemented user authentication"`

	// Time entry start time
	// @example 2024-01-15T09:00:00Z
	StartTime time.Time `json:"start_time" validate:"required" example:"2024-01-15T09:00:00Z"`

	// Time entry end time
	// @example 2024-01-15T17:00:00Z
	EndTime *time.Time `json:"end_time" validate:"omitempty" example:"2024-01-15T17:00:00Z"`

	// Time entry duration in hours
	// @example 8.0
	Duration float64 `json:"duration" validate:"omitempty,min=0" example:"8.0"`

	// Whether the time entry is billable
	// @example true
	IsBillable bool `json:"is_billable" validate:"omitempty" example:"true"`

	// Time entry rate per hour
	// @example 50.00
	Rate float64 `json:"rate" validate:"omitempty,min=0" example:"50.00"`
}

// TaskDependencyRequest represents a request to create a task dependency
// @Description Task dependency request validation model
type TaskDependencyRequest struct {
	// Dependent task ID (the task that is depended upon)
	// @example 01HXYZ123456789ABCDEFGHIJK
	DependentTaskID string `json:"dependent_task_id" validate:"required,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Dependency type (blocks, requires, relates_to)
	// @example blocks
	Type string `json:"type" validate:"omitempty,oneof=blocks requires relates_to" example:"blocks"`
}

// TaskFilterRequest represents a request to filter tasks
// @Description Task filter request validation model
type TaskFilterRequest struct {
	// Search term for title and description
	// @example authentication
	Search string `json:"search" validate:"omitempty,max=255" example:"authentication"`

	// Task status filter
	// @example in_progress
	Status string `json:"status" validate:"omitempty,oneof=todo in_progress done cancelled" example:"in_progress"`

	// Task priority filter
	// @example high
	Priority string `json:"priority" validate:"omitempty,oneof=low medium high critical" example:"high"`

	// Task type filter
	// @example feature
	Type string `json:"type" validate:"omitempty,oneof=task bug feature story epic" example:"feature"`

	// Assignee user ID filter
	// @example 01HXYZ123456789ABCDEFGHIJK
	AssigneeID string `json:"assignee_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Milestone ID filter
	// @example 01HXYZ123456789ABCDEFGHIJK
	MilestoneID string `json:"milestone_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent task ID filter (null for root tasks)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentTaskID *string `json:"parent_task_id" validate:"omitempty,ulid" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether to include only active tasks
	// @example true
	IsActive *bool `json:"is_active" validate:"omitempty" example:"true"`

	// Whether to include only archived tasks
	// @example false
	IsArchived *bool `json:"is_archived" validate:"omitempty" example:"false"`

	// Due date range start
	// @example 2024-01-01T00:00:00Z
	DueDateFrom *time.Time `json:"due_date_from" validate:"omitempty" example:"2024-01-01T00:00:00Z"`

	// Due date range end
	// @example 2024-12-31T23:59:59Z
	DueDateTo *time.Time `json:"due_date_to" validate:"omitempty" example:"2024-12-31T23:59:59Z"`

	// Label IDs filter (array)
	// @example ["01HXYZ123456789ABCDEFGHIJK","01HXYZ123456789ABCDEFGHIJL"]
	LabelIDs []string `json:"label_ids" validate:"omitempty,dive,ulid" example:"[\"01HXYZ123456789ABCDEFGHIJK\",\"01HXYZ123456789ABCDEFGHIJL\"]"`

	// Sort field
	// @example created_at
	SortBy string `json:"sort_by" validate:"omitempty,oneof=created_at updated_at title number priority due_date" example:"created_at"`

	// Sort direction
	// @example desc
	SortDirection string `json:"sort_direction" validate:"omitempty,oneof=asc desc" example:"desc"`
}

// Validation methods for request types

// Authorize validates the TaskRequest
func (r *TaskRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskLabelRequest
func (r *TaskLabelRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the MilestoneRequest
func (r *MilestoneRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskBoardRequest
func (r *TaskBoardRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskBoardColumnRequest
func (r *TaskBoardColumnRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskCommentRequest
func (r *TaskCommentRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskTimeEntryRequest
func (r *TaskTimeEntryRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskDependencyRequest
func (r *TaskDependencyRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}

// Authorize validates the TaskFilterRequest
func (r *TaskFilterRequest) Authorize(ctx http.Context) error {
	// Add any custom validation logic here
	return nil
}
