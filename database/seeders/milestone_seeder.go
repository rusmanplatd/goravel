package seeders

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type MilestoneSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *MilestoneSeeder) Signature() string {
	return "MilestoneSeeder"
}

// Run executes the seeder logic.
func (s *MilestoneSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get projects to associate milestones with
	var projects []models.Project
	err := facades.Orm().Query().Find(&projects)
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		facades.Log().Warning("No projects found, skipping milestone seeding")
		return nil
	}

	// Create sample milestones for each project
	for _, project := range projects {
		// Create different milestones based on project status
		var milestones []map[string]interface{}

		switch project.Status {
		case "planning":
			milestones = []map[string]interface{}{
				{
					"name":        "Project Planning",
					"description": "Complete project planning and requirements gathering",
					"due_date":    time.Now().AddDate(0, 1, 0), // 1 month from now
					"status":      "pending",
					"color":       "#F59E0B",
					"icon":        "planning",
				},
				{
					"name":        "Team Setup",
					"description": "Assemble project team and assign roles",
					"due_date":    time.Now().AddDate(0, 1, 15), // 1.5 months from now
					"status":      "pending",
					"color":       "#3B82F6",
					"icon":        "team",
				},
			}
		case "active":
			milestones = []map[string]interface{}{
				{
					"name":        "Phase 1 Complete",
					"description": "Complete initial development phase",
					"due_date":    time.Now().AddDate(0, 0, 15), // 2 weeks from now
					"status":      "in_progress",
					"color":       "#10B981",
					"icon":        "check",
				},
				{
					"name":        "Beta Release",
					"description": "Release beta version for testing",
					"due_date":    time.Now().AddDate(0, 1, 0), // 1 month from now
					"status":      "pending",
					"color":       "#8B5CF6",
					"icon":        "beta",
				},
				{
					"name":        "Production Ready",
					"description": "Complete all features and prepare for production",
					"due_date":    time.Now().AddDate(0, 2, 0), // 2 months from now
					"status":      "pending",
					"color":       "#EF4444",
					"icon":        "production",
				},
			}
		case "completed":
			milestones = []map[string]interface{}{
				{
					"name":        "Project Launch",
					"description": "Successfully launch the project",
					"due_date":    time.Now().AddDate(0, -1, 0), // 1 month ago
					"status":      "completed",
					"color":       "#10B981",
					"icon":        "launch",
				},
				{
					"name":        "Post-Launch Review",
					"description": "Conduct post-launch review and gather feedback",
					"due_date":    time.Now().AddDate(0, -1, 15), // 1.5 months ago
					"status":      "completed",
					"color":       "#6B7280",
					"icon":        "review",
				},
			}
		case "on-hold":
			milestones = []map[string]interface{}{
				{
					"name":        "Project Pause",
					"description": "Project temporarily paused",
					"due_date":    time.Now().AddDate(0, 0, 30), // 1 month from now
					"status":      "on_hold",
					"color":       "#F59E0B",
					"icon":        "pause",
				},
			}
		default:
			milestones = []map[string]interface{}{
				{
					"name":        "Project Kickoff",
					"description": "Project kickoff and initial setup",
					"due_date":    time.Now().AddDate(0, 0, 7), // 1 week from now
					"status":      "pending",
					"color":       "#3B82F6",
					"icon":        "kickoff",
				},
			}
		}

		for _, milestoneData := range milestones {
			// Check if milestone already exists for this project
			var existingMilestone models.Milestone
			err := facades.Orm().Query().Where("name = ? AND project_id = ?", milestoneData["name"], project.ID).First(&existingMilestone)
			if err == nil {
				continue // Milestone already exists
			}

			// Get a user ID for CreatedBy (use first user if available)
			var createdBy string
			if project.ProjectManagerID != nil {
				createdBy = *project.ProjectManagerID
			} else {
				// Get first user as fallback
				var user models.User
				if err := facades.Orm().Query().First(&user); err == nil {
					createdBy = user.ID
				}
			}

			milestone := models.Milestone{
				Title:       milestoneData["name"].(string),
				Description: milestoneData["description"].(string),
				Status:      milestoneData["status"].(string),
				Color:       milestoneData["color"].(string),
				Icon:        milestoneData["icon"].(string),
				ProjectID:   project.ID,
				DueDate:     milestoneData["due_date"].(*time.Time),
				BaseModel: models.BaseModel{
					CreatedBy: &createdBy,
				},
			}

			err = facades.Orm().Query().Create(&milestone)
			if err != nil {
				facades.Log().Error("Failed to create milestone: " + err.Error())
				return err
			}

			facades.Log().Info("Created milestone: " + milestone.Title + " for project: " + project.Name)
		}
	}

	return nil
}
