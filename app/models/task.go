package models

import (
	"time"
)

// Task represents a task or issue within a project
// @Description Task model for project task management
type Task struct {
	BaseModel

	// Task title
	// @example Implement user authentication
	Title string `gorm:"not null" json:"title" example:"Implement user authentication"`

	// Task description
	// @example Add JWT-based authentication with refresh tokens
	Description string `json:"description" example:"Add JWT-based authentication with refresh tokens"`

	// Task number (auto-incremented per project)
	// @example 1
	Number int `gorm:"not null" json:"number" example:"1"`

	// Task status (todo, in_progress, done, cancelled)
	// @example in_progress
	Status string `gorm:"default:'todo'" json:"status" example:"in_progress"`

	// Task priority (low, medium, high, critical)
	// @example high
	Priority string `gorm:"default:'medium'" json:"priority" example:"high"`

	// Task type (task, bug, feature, story, epic)
	// @example feature
	Type string `gorm:"default:'task'" json:"type" example:"feature"`

	// Task color for UI
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Task icon
	// @example feature
	Icon string `json:"icon" example:"feature"`

	// Whether the task is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether the task is archived
	// @example false
	IsArchived bool `gorm:"default:false" json:"is_archived" example:"false"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Assignee user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AssigneeID *string `gorm:"index;type:char(26)" json:"assignee_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Reviewer user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ReviewerID *string `gorm:"index;type:char(26)" json:"reviewer_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Milestone ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MilestoneID *string `gorm:"index;type:char(26)" json:"milestone_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent task ID for subtasks
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentTaskID *string `gorm:"index;type:char(26)" json:"parent_task_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Task start date
	// @example 2024-01-15T00:00:00Z
	StartDate *time.Time `json:"start_date,omitempty" example:"2024-01-15T00:00:00Z"`

	// Task due date
	// @example 2024-01-31T00:00:00Z
	DueDate *time.Time `json:"due_date,omitempty" example:"2024-01-31T00:00:00Z"`

	// Task estimated hours
	// @example 8.0
	EstimatedHours float64 `json:"estimated_hours" example:"8.0"`

	// Task actual hours spent
	// @example 6.5
	ActualHours float64 `gorm:"default:0" json:"actual_hours" example:"6.5"`

	// Task progress percentage
	// @example 75.0
	Progress float64 `gorm:"default:0" json:"progress" example:"75.0"`

	// Task position in board view
	// @example 1
	Position int `gorm:"default:0" json:"position" example:"1"`

	// Task settings as JSON
	// @example {"auto_assign":true,"require_review":false}
	Settings string `gorm:"type:json" json:"settings" example:"{\"auto_assign\":true,\"require_review\":false}"`

	// Relationships
	// @Description Project this task belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	// @Description Task assignee
	Assignee *User `gorm:"foreignKey:AssigneeID" json:"assignee,omitempty"`

	// @Description Task reviewer
	Reviewer *User `gorm:"foreignKey:ReviewerID" json:"reviewer,omitempty"`

	// @Description Associated milestone
	Milestone *Milestone `gorm:"foreignKey:MilestoneID" json:"milestone,omitempty"`

	// @Description Parent task
	ParentTask *Task `gorm:"foreignKey:ParentTaskID" json:"parent_task,omitempty"`

	// @Description Subtasks
	Subtasks []Task `gorm:"foreignKey:ParentTaskID" json:"subtasks,omitempty"`

	// @Description Task labels
	Labels []TaskLabel `gorm:"many2many:task_label_pivot;" json:"labels,omitempty"`

	// @Description Task comments
	Comments []TaskComment `gorm:"foreignKey:TaskID" json:"comments,omitempty"`

	// @Description Task activities
	Activities []TaskActivity `gorm:"foreignKey:TaskID" json:"activities,omitempty"`

	// @Description Task dependencies (tasks that depend on this task)
	Dependencies []TaskDependency `gorm:"foreignKey:DependentTaskID" json:"dependencies,omitempty"`

	// @Description Tasks this task depends on
	Dependents []TaskDependency `gorm:"foreignKey:TaskID" json:"dependents,omitempty"`

	// @Description Task time entries
	TimeEntries []TaskTimeEntry `gorm:"foreignKey:TaskID" json:"time_entries,omitempty"`

	// @Description Task attachments
	Attachments []TaskAttachment `gorm:"foreignKey:TaskID" json:"attachments,omitempty"`

	// @Description Task custom field values
	CustomFieldValues []TaskFieldValue `gorm:"foreignKey:TaskID" json:"custom_field_values,omitempty"`
}

// TaskLabel represents a label for categorizing tasks
// @Description Task label model for task categorization
type TaskLabel struct {
	BaseModel

	// Label name
	// @example Bug
	Name string `gorm:"not null" json:"name" example:"Bug"`

	// Label description
	// @example Issues that need to be fixed
	Description string `json:"description" example:"Issues that need to be fixed"`

	// Label color
	// @example #EF4444
	Color string `gorm:"not null" json:"color" example:"#EF4444"`

	// Label icon
	// @example bug
	Icon string `json:"icon" example:"bug"`

	// Whether the label is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Project this label belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	// @Description Tasks with this label
	Tasks []Task `gorm:"many2many:task_label_pivot;" json:"tasks,omitempty"`
}

// TaskLabelPivot represents the pivot table for task-label relationship
// @Description Task-label relationship
type TaskLabelPivot struct {
	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"primaryKey;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Label ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	LabelID string `gorm:"primaryKey;type:char(26)" json:"label_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When the label was added to the task
	// @example 2024-01-15T10:30:00Z
	AddedAt time.Time `json:"added_at" example:"2024-01-15T10:30:00Z"`

	// User who added the label
	// @example 01HXYZ123456789ABCDEFGHIJK
	AddedBy string `gorm:"index;type:char(26)" json:"added_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	Task      Task      `gorm:"foreignKey:TaskID" json:"task,omitempty"`
	TaskLabel TaskLabel `gorm:"foreignKey:LabelID" json:"label,omitempty"`
	User      User      `gorm:"foreignKey:AddedBy" json:"user,omitempty"`
}

// Milestone represents a milestone for grouping tasks
// @Description Milestone model for task grouping
type Milestone struct {
	BaseModel

	// Milestone title
	// @example Version 2.0 Release
	Title string `gorm:"not null" json:"title" example:"Version 2.0 Release"`

	// Milestone description
	// @example Major feature release with new UI
	Description string `json:"description" example:"Major feature release with new UI"`

	// Milestone status (open, closed)
	// @example open
	Status string `gorm:"default:'open'" json:"status" example:"open"`

	// Milestone color
	// @example #10B981
	Color string `json:"color" example:"#10B981"`

	// Milestone icon
	// @example milestone
	Icon string `json:"icon" example:"milestone"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Milestone due date
	// @example 2024-03-31T00:00:00Z
	DueDate *time.Time `json:"due_date,omitempty" example:"2024-03-31T00:00:00Z"`

	// Milestone completion date
	// @example 2024-03-25T00:00:00Z
	CompletedAt *time.Time `json:"completed_at,omitempty" example:"2024-03-25T00:00:00Z"`

	// Milestone progress percentage
	// @example 75.0
	Progress float64 `gorm:"default:0" json:"progress" example:"75.0"`

	// Relationships
	// @Description Project this milestone belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	// @Description Tasks in this milestone
	Tasks []Task `gorm:"foreignKey:MilestoneID" json:"tasks,omitempty"`
}

// TaskComment represents a comment on a task
// @Description Task comment model for task discussions
type TaskComment struct {
	BaseModel

	// Comment content
	// @example This looks good! Ready for review.
	Content string `gorm:"not null" json:"content" example:"This looks good! Ready for review."`

	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Comment author ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AuthorID string `gorm:"not null;index;type:char(26)" json:"author_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Parent comment ID for replies
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentCommentID *string `gorm:"index;type:char(26)" json:"parent_comment_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether the comment is internal (not visible to external users)
	// @example false
	IsInternal bool `gorm:"default:false" json:"is_internal" example:"false"`

	// Comment type (comment, review, system)
	// @example comment
	Type string `gorm:"default:'comment'" json:"type" example:"comment"`

	// Relationships
	// @Description Task this comment belongs to
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description Comment author
	Author *User `gorm:"foreignKey:AuthorID" json:"author,omitempty"`

	// @Description Parent comment
	ParentComment *TaskComment `gorm:"foreignKey:ParentCommentID" json:"parent_comment,omitempty"`

	// @Description Reply comments
	Replies []TaskComment `gorm:"foreignKey:ParentCommentID" json:"replies,omitempty"`
}

// TaskFieldValue represents custom field values for tasks
// @Description Task field value model for custom metadata
type TaskFieldValue struct {
	BaseModel

	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Field ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	FieldID string `gorm:"not null;index;type:char(26)" json:"field_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Field value as string (all values stored as string and parsed based on field type)
	// @example High
	Value string `json:"value" example:"High"`

	// Field value as JSON for complex types
	// @example {"selected":["option1","option2"]}
	ValueJSON string `gorm:"type:json" json:"value_json,omitempty" example:"{\"selected\":[\"option1\",\"option2\"]}"`

	// Relationships
	// @Description Task this value belongs to
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description Custom field definition
	Field *ProjectCustomField `gorm:"foreignKey:FieldID" json:"field,omitempty"`
}

// TaskAttachment represents file attachments for tasks
// @Description Task attachment model for file uploads
type TaskAttachment struct {
	BaseModel

	// Attachment filename
	// @example screenshot.png
	Filename string `gorm:"not null" json:"filename" example:"screenshot.png"`

	// Original filename
	// @example My Screenshot.png
	OriginalFilename string `gorm:"not null" json:"original_filename" example:"My Screenshot.png"`

	// File path/URL
	// @example /uploads/tasks/01HXYZ123456789ABCDEFGHIJK/screenshot.png
	FilePath string `gorm:"not null" json:"file_path" example:"/uploads/tasks/01HXYZ123456789ABCDEFGHIJK/screenshot.png"`

	// File size in bytes
	// @example 1024768
	FileSize int64 `json:"file_size" example:"1024768"`

	// MIME type
	// @example image/png
	MimeType string `json:"mime_type" example:"image/png"`

	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Uploaded by user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UploadedBy string `gorm:"not null;index;type:char(26)" json:"uploaded_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Task this attachment belongs to
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description User who uploaded the attachment
	Uploader *User `gorm:"foreignKey:UploadedBy" json:"uploader,omitempty"`
}

// TaskActivity represents an activity log for a task
// @Description Task activity model for task history
type TaskActivity struct {
	BaseModel

	// Activity type (created, updated, assigned, commented, etc.)
	// @example assigned
	Type string `gorm:"not null" json:"type" example:"assigned"`

	// Activity description
	// @example Task assigned to John Doe
	Description string `gorm:"not null" json:"description" example:"Task assigned to John Doe"`

	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User who performed the activity
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null;index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Activity data as JSON
	// @example {"old_value":"todo","new_value":"in_progress"}
	Data string `gorm:"type:json" json:"data" example:"{\"old_value\":\"todo\",\"new_value\":\"in_progress\"}"`

	// Relationships
	// @Description Task this activity belongs to
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description User who performed the activity
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TaskDependency represents a dependency between tasks
// @Description Task dependency model for task relationships
type TaskDependency struct {
	BaseModel

	// Task ID (the task that depends on another)
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Dependent task ID (the task that is depended upon)
	// @example 01HXYZ123456789ABCDEFGHIJK
	DependentTaskID string `gorm:"not null;index;type:char(26)" json:"dependent_task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Dependency type (blocks, requires, relates_to)
	// @example blocks
	Type string `gorm:"default:'blocks'" json:"type" example:"blocks"`

	// Whether the dependency is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Relationships
	// @Description Task that depends on another
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description Task that is depended upon
	DependentTask *Task `gorm:"foreignKey:DependentTaskID" json:"dependent_task,omitempty"`
}

// TaskTimeEntry represents time tracking for a task
// @Description Task time entry model for time tracking
type TaskTimeEntry struct {
	BaseModel

	// Time entry description
	// @example Implemented user authentication
	Description string `gorm:"not null" json:"description" example:"Implemented user authentication"`

	// Task ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TaskID string `gorm:"not null;index;type:char(26)" json:"task_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who logged the time
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null;index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Time entry start time
	// @example 2024-01-15T09:00:00Z
	StartTime time.Time `gorm:"not null" json:"start_time" example:"2024-01-15T09:00:00Z"`

	// Time entry end time
	// @example 2024-01-15T17:00:00Z
	EndTime *time.Time `json:"end_time,omitempty" example:"2024-01-15T17:00:00Z"`

	// Time entry duration in hours
	// @example 8.0
	Duration float64 `gorm:"default:0" json:"duration" example:"8.0"`

	// Whether the time entry is billable
	// @example true
	IsBillable bool `gorm:"default:true" json:"is_billable" example:"true"`

	// Time entry rate per hour
	// @example 50.00
	Rate float64 `json:"rate" example:"50.00"`

	// Relationships
	// @Description Task this time entry belongs to
	Task *Task `gorm:"foreignKey:TaskID" json:"task,omitempty"`

	// @Description User who logged the time
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TaskBoard represents a board view for tasks
// @Description Task board model for different task views
type TaskBoard struct {
	BaseModel

	// Board name
	// @example Development Board
	Name string `gorm:"not null" json:"name" example:"Development Board"`

	// Board description
	// @example Main development workflow board
	Description string `json:"description" example:"Main development workflow board"`

	// Board type (kanban, table, list, timeline)
	// @example kanban
	Type string `gorm:"default:'kanban'" json:"type" example:"kanban"`

	// Board color
	// @example #3B82F6
	Color string `json:"color" example:"#3B82F6"`

	// Board icon
	// @example board
	Icon string `json:"icon" example:"board"`

	// Whether the board is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether the board is default for the project
	// @example true
	IsDefault bool `gorm:"default:false" json:"is_default" example:"true"`

	// Project ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProjectID string `gorm:"not null;index;type:char(26)" json:"project_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Board settings as JSON
	// @example {"columns":["todo","in_progress","done"],"filters":{"assignee":"all"}}
	Settings string `gorm:"type:json" json:"settings" example:"{\"columns\":[\"todo\",\"in_progress\",\"done\"],\"filters\":{\"assignee\":\"all\"}}"`

	// Relationships
	// @Description Project this board belongs to
	Project *Project `gorm:"foreignKey:ProjectID" json:"project,omitempty"`

	// @Description Board columns
	Columns []TaskBoardColumn `gorm:"foreignKey:BoardID" json:"columns,omitempty"`
}

// TaskBoardColumn represents a column in a task board
// @Description Task board column model for board organization
type TaskBoardColumn struct {
	BaseModel

	// Column name
	// @example In Progress
	Name string `gorm:"not null" json:"name" example:"In Progress"`

	// Column description
	// @example Tasks currently being worked on
	Description string `json:"description" example:"Tasks currently being worked on"`

	// Column color
	// @example #F59E0B
	Color string `json:"color" example:"#F59E0B"`

	// Column position
	// @example 2
	Position int `gorm:"not null" json:"position" example:"2"`

	// Column status filter (if any)
	// @example in_progress
	StatusFilter string `json:"status_filter" example:"in_progress"`

	// Column limit (max number of tasks)
	// @example 10
	TaskLimit int `json:"task_limit" example:"10"`

	// Whether the column is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Board ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	BoardID string `gorm:"not null;index;type:char(26)" json:"board_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Board this column belongs to
	Board *TaskBoard `gorm:"foreignKey:BoardID" json:"board,omitempty"`
}
