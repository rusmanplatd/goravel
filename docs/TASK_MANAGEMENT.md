# Task Management System

This document describes the comprehensive task management system implemented in Goravel, similar to GitHub Projects. The system provides full-featured project management capabilities including tasks, labels, milestones, boards, and more.

## Overview

The task management system is built around the concept of projects, where each project can contain:
- **Tasks**: Individual work items with various types, priorities, and statuses
- **Labels**: Categorization system for tasks
- **Milestones**: Grouping mechanism for related tasks
- **Boards**: Different views (Kanban, Table, List, Timeline) for organizing tasks
- **Comments**: Discussion and collaboration on tasks
- **Time Tracking**: Logging time spent on tasks
- **Dependencies**: Relationships between tasks

## Core Models

### Task
The central entity representing individual work items.

**Key Features:**
- Auto-incremented task numbers per project
- Multiple statuses: `todo`, `in_progress`, `done`, `cancelled`
- Priority levels: `low`, `medium`, `high`, `critical`
- Task types: `task`, `bug`, `feature`, `story`, `epic`
- Time tracking with estimated and actual hours
- Progress tracking (0-100%)
- Assignee and reviewer assignment
- Parent-child relationships for subtasks
- Due dates and start dates
- Position tracking for board views

**Example:**
```json
{
  "id": "01HXYZ123456789ABCDEFGHIJK",
  "title": "Implement user authentication",
  "description": "Add JWT-based authentication with refresh tokens",
  "number": 1,
  "status": "in_progress",
  "priority": "high",
  "type": "feature",
  "color": "#3B82F6",
  "icon": "feature",
  "is_active": true,
  "is_archived": false,
  "project_id": "01HXYZ123456789ABCDEFGHIJK",
  "created_by": "01HXYZ123456789ABCDEFGHIJK",
  "assignee_id": "01HXYZ123456789ABCDEFGHIJK",
  "reviewer_id": "01HXYZ123456789ABCDEFGHIJK",
  "milestone_id": "01HXYZ123456789ABCDEFGHIJK",
  "parent_task_id": null,
  "start_date": "2024-01-15T00:00:00Z",
  "due_date": "2024-01-31T00:00:00Z",
  "estimated_hours": 16.0,
  "actual_hours": 8.0,
  "progress": 50.0,
  "position": 1,
  "settings": "{\"auto_assign\":true,\"require_review\":true}"
}
```

### TaskLabel
Categorization system for tasks with color coding.

**Key Features:**
- Color-coded labels for visual organization
- Project-scoped labels
- Icon support for better visual identification

**Example:**
```json
{
  "id": "01HXYZ123456789ABCDEFGHIJK",
  "name": "Bug",
  "description": "Issues that need to be fixed",
  "color": "#EF4444",
  "icon": "bug",
  "is_active": true,
  "project_id": "01HXYZ123456789ABCDEFGHIJK",
  "created_by": "01HXYZ123456789ABCDEFGHIJK"
}
```

### Milestone
Grouping mechanism for related tasks with progress tracking.

**Key Features:**
- Progress tracking across all tasks in the milestone
- Due dates and completion dates
- Status tracking (open/closed)
- Color coding and icons

**Example:**
```json
{
  "id": "01HXYZ123456789ABCDEFGHIJK",
  "title": "Version 2.0 Release",
  "description": "Major feature release with new UI",
  "status": "open",
  "color": "#10B981",
  "icon": "milestone",
  "project_id": "01HXYZ123456789ABCDEFGHIJK",
  "created_by": "01HXYZ123456789ABCDEFGHIJK",
  "due_date": "2024-03-31T00:00:00Z",
  "completed_at": null,
  "progress": 75.0
}
```

### TaskBoard
Different view types for organizing and visualizing tasks.

**Board Types:**
- **Kanban**: Column-based workflow visualization
- **Table**: Spreadsheet-like view with sorting and filtering
- **List**: Simple list view
- **Timeline**: Time-based visualization

**Key Features:**
- Multiple board types per project
- Default board designation
- Customizable settings and filters
- Column-based organization (for Kanban)

**Example:**
```json
{
  "id": "01HXYZ123456789ABCDEFGHIJK",
  "name": "Development Board",
  "description": "Main development workflow board",
  "type": "kanban",
  "color": "#3B82F6",
  "icon": "board",
  "is_active": true,
  "is_default": true,
  "project_id": "01HXYZ123456789ABCDEFGHIJK",
  "created_by": "01HXYZ123456789ABCDEFGHIJK",
  "settings": "{\"columns\":[\"todo\",\"in_progress\",\"review\",\"done\"],\"filters\":{\"assignee\":\"all\"}}"
}
```

### TaskBoardColumn
Columns within Kanban boards for organizing tasks by status.

**Key Features:**
- Position-based ordering
- Status filtering
- Task limits per column
- Color coding

**Example:**
```json
{
  "id": "01HXYZ123456789ABCDEFGHIJK",
  "name": "In Progress",
  "description": "Tasks currently being worked on",
  "color": "#F59E0B",
  "position": 2,
  "status_filter": "in_progress",
  "task_limit": 10,
  "is_active": true,
  "board_id": "01HXYZ123456789ABCDEFGHIJK"
}
```

## Supporting Models

### TaskComment
Discussion and collaboration system for tasks.

**Features:**
- Threaded comments with replies
- Internal comments (not visible to external users)
- Different comment types (comment, review, system)
- Rich text support

### TaskActivity
Audit trail for all task-related activities.

**Features:**
- Activity logging for all task changes
- User tracking for all activities
- JSON data storage for detailed change information
- Activity types: created, updated, assigned, commented, etc.

### TaskDependency
Relationship management between tasks.

**Dependency Types:**
- **blocks**: Task A blocks Task B from starting
- **requires**: Task A requires Task B to be completed
- **relates_to**: General relationship between tasks

### TaskTimeEntry
Time tracking system for tasks.

**Features:**
- Start and end time tracking
- Duration calculation
- Billable/non-billable designation
- Rate tracking for billing
- Description for time entries

## API Endpoints

### Tasks
- `GET /api/v1/projects/{project_id}/tasks` - List tasks with filtering and pagination
- `POST /api/v1/projects/{project_id}/tasks` - Create a new task
- `GET /api/v1/projects/{project_id}/tasks/{id}` - Get a specific task
- `PUT /api/v1/projects/{project_id}/tasks/{id}` - Update a task
- `DELETE /api/v1/projects/{project_id}/tasks/{id}` - Delete a task

### Task Labels
- `GET /api/v1/projects/{project_id}/task-labels` - List task labels
- `POST /api/v1/projects/{project_id}/task-labels` - Create a new task label

### Milestones
- `GET /api/v1/projects/{project_id}/milestones` - List milestones
- `POST /api/v1/projects/{project_id}/milestones` - Create a new milestone

### Task Boards
- `GET /api/v1/projects/{project_id}/task-boards` - List task boards
- `POST /api/v1/projects/{project_id}/task-boards` - Create a new task board

## Usage Examples

### Creating a Task
```bash
curl -X POST /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Implement user authentication",
    "description": "Add JWT-based authentication with refresh tokens",
    "status": "todo",
    "priority": "high",
    "type": "feature",
    "color": "#3B82F6",
    "icon": "feature",
    "assignee_id": "01HXYZ123456789ABCDEFGHIJK",
    "milestone_id": "01HXYZ123456789ABCDEFGHIJK",
    "due_date": "2024-01-31T00:00:00Z",
    "estimated_hours": 16.0
  }'
```

### Creating a Task Label
```bash
curl -X POST /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/task-labels \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Bug",
    "description": "Issues that need to be fixed",
    "color": "#EF4444",
    "icon": "bug"
  }'
```

### Creating a Milestone
```bash
curl -X POST /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/milestones \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Version 2.0 Release",
    "description": "Major feature release with new UI",
    "status": "open",
    "color": "#10B981",
    "icon": "milestone",
    "due_date": "2024-03-31T00:00:00Z"
  }'
```

### Creating a Task Board
```bash
curl -X POST /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/task-boards \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Development Board",
    "description": "Main development workflow board",
    "type": "kanban",
    "color": "#3B82F6",
    "icon": "board",
    "is_default": true,
    "settings": "{\"columns\":[\"todo\",\"in_progress\",\"review\",\"done\"]}"
  }'
```

## Filtering and Search

The task listing endpoint supports comprehensive filtering:

### Query Parameters
- `search`: Search in title and description
- `status`: Filter by task status
- `priority`: Filter by priority level
- `type`: Filter by task type
- `assignee_id`: Filter by assignee
- `milestone_id`: Filter by milestone
- `is_active`: Filter by active status
- `is_archived`: Filter by archived status
- `cursor`: Pagination cursor
- `limit`: Number of items per page

### Example Filtering
```bash
# Get all high priority bugs assigned to a specific user
GET /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/tasks?priority=high&type=bug&assignee_id=01HXYZ123456789ABCDEFGHIJK

# Search for authentication-related tasks
GET /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/tasks?search=authentication

# Get only active tasks in progress
GET /api/v1/projects/01HXYZ123456789ABCDEFGHIJK/tasks?status=in_progress&is_active=true
```

## Database Schema

The task management system uses the following database tables:

1. `tasks` - Main task table
2. `task_labels` - Task labels
3. `task_label_pivot` - Many-to-many relationship between tasks and labels
4. `milestones` - Project milestones
5. `task_comments` - Task comments
6. `task_activities` - Activity log
7. `task_dependencies` - Task dependencies
8. `task_time_entries` - Time tracking
9. `task_boards` - Task boards
10. `task_board_columns` - Board columns

## Migration and Seeding

The system includes comprehensive migrations and seeders:

### Running Migrations
```bash
go run artisan migrate
```

### Running Seeders
```bash
go run artisan db:seed
```

The seeder creates sample data including:
- Task labels (Bug, Feature, Enhancement, Documentation, Testing)
- Milestones (Phase 1, Phase 2, Phase 3)
- Task boards (Development Board, Bug Tracker)
- Sample tasks with various statuses and priorities

## Testing

The system includes comprehensive tests covering:
- Task creation, updating, and deletion
- Label management
- Milestone operations
- Board creation and management
- Request validation
- Service layer functionality

Run tests with:
```bash
go test ./tests/feature/task_management_test.go
```

## Future Enhancements

Planned features for future releases:
- **Task Templates**: Predefined task templates for common workflows
- **Automated Workflows**: Trigger actions based on task state changes
- **Advanced Reporting**: Analytics and reporting on task metrics
- **Integration**: Webhook support for external integrations
- **Mobile Support**: Mobile-optimized views and interactions
- **Real-time Updates**: WebSocket support for live updates
- **File Attachments**: Support for file uploads to tasks
- **Advanced Permissions**: Granular permission system for task operations

## Conclusion

The task management system provides a comprehensive solution for project management within the Goravel framework. It offers all the essential features needed for modern software development teams while maintaining flexibility for customization and future enhancements.

The system is designed to be scalable, maintainable, and follows best practices for API design and database architecture. It integrates seamlessly with the existing authentication, authorization, and organization management systems. 