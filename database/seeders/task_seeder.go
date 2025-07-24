package seeders

import (
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskSeeder struct {
}

// Signature The unique signature for the seeder.
func (r *TaskSeeder) Signature() string {
	return "task_seeder"
}

// Run executes the seeder.
func (r *TaskSeeder) Run() error {
	// Get existing projects and users for seeding
	var projects []models.Project
	facades.Orm().Query().Find(&projects)
	if len(projects) == 0 {
		return nil // No projects to seed tasks for
	}

	var users []models.User
	facades.Orm().Query().Find(&users)
	if len(users) == 0 {
		return nil // No users to assign tasks to
	}

	// Create task labels for each project
	for _, project := range projects {
		userSeederULID := models.USER_SEEDER_ULID
		labels := []models.TaskLabel{
			{
				Name:        "Bug",
				Description: "Issues that need to be fixed",
				Color:       "#EF4444",
				Icon:        "bug",
				IsActive:    true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &userSeederULID,
					UpdatedBy: &userSeederULID,
				},
			},
			{
				Name:        "Feature",
				Description: "New features to be implemented",
				Color:       "#3B82F6",
				Icon:        "feature",
				IsActive:    true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
			},
			{
				Name:        "Enhancement",
				Description: "Improvements to existing features",
				Color:       "#10B981",
				Icon:        "enhancement",
				IsActive:    true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
			},
			{
				Name:        "Documentation",
				Description: "Documentation updates",
				Color:       "#F59E0B",
				Icon:        "documentation",
				IsActive:    true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
			},
			{
				Name:        "Testing",
				Description: "Testing and quality assurance",
				Color:       "#8B5CF6",
				Icon:        "testing",
				IsActive:    true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
			},
		}

		for _, label := range labels {
			facades.Orm().Query().Create(&label)
		}
	}

	// Create milestones for each project
	for _, project := range projects {
		dueDate := time.Now().AddDate(0, 3, 0) // 3 months from now
		milestones := []models.Milestone{
			{
				Title:       "Phase 1 - Foundation",
				Description: "Core infrastructure and basic features",
				Status:      "open",
				Color:       "#10B981",
				Icon:        "milestone",
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				DueDate:  &dueDate,
				Progress: 25.0,
			},
			{
				Title:       "Phase 2 - Features",
				Description: "Main feature development",
				Status:      "open",
				Color:       "#3B82F6",
				Icon:        "milestone",
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				DueDate:  &dueDate,
				Progress: 0.0,
			},
			{
				Title:       "Phase 3 - Polish",
				Description: "UI/UX improvements and bug fixes",
				Status:      "open",
				Color:       "#F59E0B",
				Icon:        "milestone",
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				DueDate:  &dueDate,
				Progress: 0.0,
			},
		}

		for _, milestone := range milestones {
			facades.Orm().Query().Create(&milestone)
		}
	}

	// Create task boards for each project
	for _, project := range projects {
		boards := []models.TaskBoard{
			{
				Name:        "Development Board",
				Description: "Main development workflow board",
				Type:        "kanban",
				Color:       "#3B82F6",
				Icon:        "board",
				IsActive:    true,
				IsDefault:   true,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				Settings: `{"columns":["todo","in_progress","review","done"],"filters":{"assignee":"all"}}`,
			},
			{
				Name:        "Bug Tracker",
				Description: "Bug tracking and resolution board",
				Type:        "table",
				Color:       "#EF4444",
				Icon:        "board",
				IsActive:    true,
				IsDefault:   false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				Settings: `{"columns":["new","investigating","fixing","testing","resolved"],"filters":{"type":"bug"}}`,
			},
		}

		for _, board := range boards {
			facades.Orm().Query().Create(&board)
		}
	}

	// Create sample tasks for each project
	for _, project := range projects {
		// Get project's labels, milestones, and boards
		var labels []models.TaskLabel
		facades.Orm().Query().Where("project_id = ?", project.ID).Find(&labels)

		var milestones []models.Milestone
		facades.Orm().Query().Where("project_id = ?", project.ID).Find(&milestones)

		var boards []models.TaskBoard
		facades.Orm().Query().Where("project_id = ?", project.ID).Find(&boards)

		if len(labels) == 0 || len(milestones) == 0 || len(boards) == 0 {
			continue
		}

		// Create sample tasks
		tasks := []models.Task{
			{
				Title:       "Implement user authentication",
				Description: "Add JWT-based authentication with refresh tokens and password reset functionality",
				Number:      1,
				Status:      "in_progress",
				Priority:    "high",
				Type:        "feature",
				Color:       "#3B82F6",
				Icon:        "feature",
				IsActive:    true,
				IsArchived:  false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				AssigneeID:     &users[0].ID,
				MilestoneID:    &milestones[0].ID,
				StartDate:      helpers.TimePtr(time.Now().AddDate(0, 0, -7)),
				DueDate:        helpers.TimePtr(time.Now().AddDate(0, 0, 14)),
				EstimatedHours: 16.0,
				ActualHours:    8.0,
				Progress:       50.0,
				Position:       1,
				Settings:       `{"auto_assign":true,"require_review":true}`,
			},
			{
				Title:       "Fix login page responsive design",
				Description: "The login page is not displaying correctly on mobile devices",
				Number:      2,
				Status:      "todo",
				Priority:    "medium",
				Type:        "bug",
				Color:       "#EF4444",
				Icon:        "bug",
				IsActive:    true,
				IsArchived:  false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				AssigneeID:     &users[0].ID,
				MilestoneID:    &milestones[0].ID,
				StartDate:      nil,
				DueDate:        helpers.TimePtr(time.Now().AddDate(0, 0, 7)),
				EstimatedHours: 4.0,
				ActualHours:    0.0,
				Progress:       0.0,
				Position:       2,
				Settings:       `{"auto_assign":false,"require_review":false}`,
			},
			{
				Title:       "Add user profile management",
				Description: "Allow users to update their profile information and avatar",
				Number:      3,
				Status:      "todo",
				Priority:    "medium",
				Type:        "feature",
				Color:       "#3B82F6",
				Icon:        "feature",
				IsActive:    true,
				IsArchived:  false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				AssigneeID:     nil,
				MilestoneID:    &milestones[1].ID,
				StartDate:      nil,
				DueDate:        helpers.TimePtr(time.Now().AddDate(0, 1, 0)),
				EstimatedHours: 12.0,
				ActualHours:    0.0,
				Progress:       0.0,
				Position:       3,
				Settings:       `{"auto_assign":true,"require_review":true}`,
			},
			{
				Title:       "Update API documentation",
				Description: "Update the API documentation with new endpoints and examples",
				Number:      4,
				Status:      "done",
				Priority:    "low",
				Type:        "documentation",
				Color:       "#F59E0B",
				Icon:        "documentation",
				IsActive:    true,
				IsArchived:  false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				AssigneeID:     &users[0].ID,
				MilestoneID:    &milestones[0].ID,
				StartDate:      helpers.TimePtr(time.Now().AddDate(0, 0, -14)),
				DueDate:        helpers.TimePtr(time.Now().AddDate(0, 0, -7)),
				EstimatedHours: 6.0,
				ActualHours:    5.5,
				Progress:       100.0,
				Position:       4,
				Settings:       `{"auto_assign":false,"require_review":false}`,
			},
			{
				Title:       "Write unit tests for auth service",
				Description: "Add comprehensive unit tests for the authentication service",
				Number:      5,
				Status:      "in_progress",
				Priority:    "high",
				Type:        "testing",
				Color:       "#8B5CF6",
				Icon:        "testing",
				IsActive:    true,
				IsArchived:  false,
				ProjectID:   project.ID,
				BaseModel: models.BaseModel{
					CreatedBy: &users[0].ID,
				},
				AssigneeID:     &users[0].ID,
				MilestoneID:    &milestones[0].ID,
				StartDate:      helpers.TimePtr(time.Now().AddDate(0, 0, -3)),
				DueDate:        helpers.TimePtr(time.Now().AddDate(0, 0, 4)),
				EstimatedHours: 8.0,
				ActualHours:    3.0,
				Progress:       37.5,
				Position:       5,
				Settings:       `{"auto_assign":true,"require_review":true}`,
			},
		}

		for _, task := range tasks {
			facades.Orm().Query().Create(&task)
		}

		// Add labels to tasks
		var createdTasks []models.Task
		facades.Orm().Query().Where("project_id = ?", project.ID).Find(&createdTasks)

		if len(createdTasks) > 0 && len(labels) > 0 {
			// Add feature label to feature tasks
			for _, task := range createdTasks {
				if task.Type == "feature" {
					labelPivot := models.TaskLabelPivot{
						TaskID:  task.ID,
						LabelID: labels[1].ID, // Feature label
						AddedAt: time.Now(),
						AddedBy: users[0].ID,
					}
					facades.Orm().Query().Create(&labelPivot)
				} else if task.Type == "bug" {
					labelPivot := models.TaskLabelPivot{
						TaskID:  task.ID,
						LabelID: labels[0].ID, // Bug label
						AddedAt: time.Now(),
						AddedBy: users[0].ID,
					}
					facades.Orm().Query().Create(&labelPivot)
				} else if task.Type == "documentation" {
					labelPivot := models.TaskLabelPivot{
						TaskID:  task.ID,
						LabelID: labels[3].ID, // Documentation label
						AddedAt: time.Now(),
						AddedBy: users[0].ID,
					}
					facades.Orm().Query().Create(&labelPivot)
				} else if task.Type == "testing" {
					labelPivot := models.TaskLabelPivot{
						TaskID:  task.ID,
						LabelID: labels[4].ID, // Testing label
						AddedAt: time.Now(),
						AddedBy: users[0].ID,
					}
					facades.Orm().Query().Create(&labelPivot)
				}
			}
		}
	}

	return nil
}
